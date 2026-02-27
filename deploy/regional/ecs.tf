# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "${var.project}-${var.stage}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  configuration {
    execute_command_configuration {
      kms_key_id = aws_kms_key.exec_session.arn
      logging    = "OVERRIDE"

      log_configuration {
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.ssm_sessions.name
        cloud_watch_encryption_enabled = false
      }
    }
  }

  tags = local.common_tags
}

# CloudWatch log group for container logs
resource "aws_cloudwatch_log_group" "rosa_boundary" {
  name              = "/ecs/${var.project}-${var.stage}"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

# CloudWatch log group for SSM session logs (separate from container logs)
resource "aws_cloudwatch_log_group" "ssm_sessions" {
  name              = "/ecs/${var.project}-${var.stage}/ssm-sessions"
  retention_in_days = var.retention_days

  tags = local.common_tags
}

# Security group for Fargate tasks
resource "aws_security_group" "fargate" {
  name        = "${var.project}-${var.stage}-fargate-sg"
  description = "Security group for ROSA Boundary Fargate tasks"
  vpc_id      = var.vpc_id

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-fargate-sg"
  })
}

# ECS Task Definition
resource "aws_ecs_task_definition" "rosa_boundary" {
  family                   = "${var.project}-${var.stage}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.container_cpu
  memory                   = var.container_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  # EFS volume for /home/sre
  volume {
    name = "sre-home"

    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.sre_home.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.sre.id
        iam             = "ENABLED"
      }
    }
  }

  # Ephemeral bind mount for kube-proxy working directory (no EFS config)
  volume {
    name = "proxy-tmp"
  }

  container_definitions = jsonencode([
    {
      name        = "rosa-boundary"
      image       = var.container_image
      essential   = true
      stopTimeout = 120

      dependsOn = [
        {
          containerName = "kube-proxy"
          condition     = "HEALTHY"
        }
      ]

      environment = [
        {
          name  = "CLAUDE_CODE_USE_BEDROCK"
          value = "1"
        },
        {
          name  = "TASK_TIMEOUT"
          value = tostring(var.task_timeout_default)
        },
        {
          name  = "KUBE_PROXY_PORT"
          value = tostring(var.kube_proxy_port)
        }
      ]

      mountPoints = [{
        sourceVolume  = "sre-home"
        containerPath = "/home/sre"
        readOnly      = false
      }]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.rosa_boundary.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "rosa-boundary"
        }
      }

      linuxParameters = {
        initProcessEnabled = true
      }
    },
    {
      name      = "kube-proxy"
      image     = var.container_image
      essential = true

      command = [
        "sh", "-c",
        "printf '%s' \"$KUBECONFIG_DATA\" > /tmp/kubeconfig && exec oc proxy --address=127.0.0.1 --port=${var.kube_proxy_port} --kubeconfig=/tmp/kubeconfig"
      ]

      environment = [
        {
          name  = "HOME"
          value = "/tmp"
        }
      ]

      healthCheck = {
        command     = ["CMD-SHELL", "curl -sf http://127.0.0.1:${var.kube_proxy_port}/version || exit 1"]
        interval    = 10
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }

      mountPoints = [
        {
          sourceVolume  = "proxy-tmp"
          containerPath = "/tmp"
          readOnly      = false
        }
      ]

      readonlyRootFilesystem = true

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.rosa_boundary.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "kube-proxy"
        }
      }

      linuxParameters = {
        initProcessEnabled = true
      }
    }
  ])

  tags = local.common_tags
}

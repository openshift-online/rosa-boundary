resource "aws_ecs_cluster" "main" {
  name = var.app_name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = { Environment = var.environment }
}

locals {
  # app_config (see variables.tf) is the complete config file uploaded to S3.
  #
  # Compatibility window: the deployed container image may predate the
  # config-file keys for backplane/ocm/workers/allowlists — it reads those
  # from environment variables only. The compat_env entries below are
  # therefore derived from the config file (deprecated variable wins when
  # set), so an old image receives the same values the file carries. For a
  # new image the env value equals the file value, which makes the loader's
  # env-over-file precedence harmless. Remove compat_env with the deprecated
  # variables in the next change.
  container_environment = concat([
    { name = "ROSA_TA_LISTEN_ADDR", value = ":8080" },
    { name = "ROSA_TA_LOG_JSON", value = "true" },
    { name = "ROSA_TA_LOG_LEVEL", value = "info" },
    { name = "ROSA_TA_ENABLE_AUTH", value = "true" },
    { name = "ROSA_TA_S3_BUCKET", value = aws_s3_bucket.app.bucket },
    { name = "ROSA_TA_S3_KEY_PREFIX", value = "trusted-actions" },
    { name = "ROSA_TA_JWK_CERT_URL", value = var.jwk_cert_url },
    { name = "ROSA_TA_ALLOWED_ACCOUNTS", value = var.allowed_accounts },
    { name = "AWS_REGION", value = var.aws_region },
    # IAM database-authentication contract (ticket 01): connection
    # coordinates only — no password anywhere. The runtime mints a fresh IAM
    # token per connection; TLS verifies the Aurora certificate against the
    # RDS CA bundle baked into the image.
    { name = "ROSA_TA_DB_HOST", value = aws_rds_cluster.main.endpoint },
    { name = "ROSA_TA_DB_PORT", value = tostring(aws_rds_cluster.main.port) },
    { name = "ROSA_TA_DB_NAME", value = var.db_name },
    { name = "ROSA_TA_DB_USER", value = local.db_app_username },
    { name = "ROSA_TA_DB_SSLMODE", value = "verify-full" },
    { name = "ROSA_TA_DB_SSLROOTCERT", value = "/etc/ssl/rds/global-bundle.pem" },
    { name = "ROSA_TA_CONFIG_HASH", value = sha256(local.app_config_effective) },
    ],
    [for name, value in local.compat_env : { name = name, value = value } if value != ""],
  )

  # roles has no env var — the loader reads it from the file only. The shim
  # merges a deprecated var.roles into the config file when app_config does
  # not define a roles block itself: an absent key counts as "not defined"
  # (try yields null, which is not a list), while an explicit roles: [] in
  # the file IS a definition and wins — the file said "no roles" on purpose.
  app_config_effective = var.roles != null && !can(yamldecode(var.app_config).roles) ? yamlencode(merge(
    yamldecode(var.app_config),
    { roles = [for r in var.roles : { id = r.id, amsResource = r.ams_resource }] },
  )) : var.app_config

  config_decoded = yamldecode(local.app_config_effective)

  # Env values for the compatibility window: the deprecated per-setting
  # variable when set, otherwise the value from the config file. A missing
  # key yields "" and the env entry is then omitted.
  compat_env = {
    ROSA_TA_WORKER_CONCURRENCY       = var.worker_concurrency != null ? tostring(var.worker_concurrency) : tostring(try(local.config_decoded.workers.concurrency, ""))
    ROSA_TA_WORKER_POLL_INTERVAL     = var.worker_poll_interval != null ? var.worker_poll_interval : try(local.config_decoded.workers.poll_interval, "")
    ROSA_TA_WORKER_EXECUTION_TIMEOUT = var.worker_execution_timeout != null ? var.worker_execution_timeout : try(local.config_decoded.workers.execution_timeout, "")
    ROSA_TA_ALLOWED_NAMESPACES       = var.allowed_namespaces != null ? var.allowed_namespaces : try(join(",", local.config_decoded.actions.allowed_namespaces), "")
    ROSA_TA_ALLOWED_SECRETS          = var.allowed_secrets != null ? var.allowed_secrets : try(join(",", local.config_decoded.actions.allowed_secrets), "")
    ROSA_TA_OCM_BASE_URL             = var.ocm_base_url != null ? var.ocm_base_url : try(local.config_decoded.ocm.base_url, "")
    ROSA_TA_BACKPLANE_URL            = var.backplane_url != null ? var.backplane_url : try(local.config_decoded.backplane.base_url, "")
    ROSA_TA_BACKPLANE_CLIENT_ID      = var.backplane_client_id != null ? var.backplane_client_id : try(local.config_decoded.backplane.client_id, "")
  }

  container_secrets = [
    { name = "ROSA_TA_OCM_CLIENT_SECRET", valueFrom = "${local.global.secretsmanager_secret_arn}:ocm_client_secret::" },
    { name = "ROSA_TA_OCM_TOKEN", valueFrom = "${local.global.secretsmanager_secret_arn}:ocm_token::" },
    { name = "ROSA_TA_BACKPLANE_CLIENT_SECRET", valueFrom = "${local.global.secretsmanager_secret_arn}:backplane_client_secret::" },
  ]
}

resource "aws_s3_object" "config" {
  bucket       = aws_s3_bucket.app.bucket
  key          = "config/${var.aws_region}/config.yaml"
  content      = local.app_config_effective
  content_type = "application/yaml"

  tags = { Environment = var.environment }
}

resource "aws_ecs_task_definition" "app" {
  family                   = var.app_name
  task_role_arn            = aws_iam_role.task.arn
  execution_role_arn       = local.global.iam_role_task_execution_arn
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory

  volume {
    name = "config-data"
  }

  container_definitions = jsonencode([
    {
      name      = "config-init"
      image     = "public.ecr.aws/aws-cli/aws-cli:latest"
      essential = false

      command = ["s3", "cp", "s3://${aws_s3_bucket.app.bucket}/${aws_s3_object.config.key}", "/config/config.yaml", "--region", var.aws_region]

      mountPoints = [{ sourceVolume = "config-data", containerPath = "/config", readOnly = false }]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs-config-init"
        }
      }

      cpu    = 256
      memory = 256
    },
    {
      name      = var.app_name
      image     = var.container_image
      essential = true
      command   = ["--config-file", "/config/config.yaml"]

      dependsOn = [{ containerName = "config-init", condition = "SUCCESS" }]

      portMappings = [{ containerPort = 8080, hostPort = 8080, protocol = "tcp" }]

      mountPoints = [
        { sourceVolume = "config-data", containerPath = "/config", readOnly = true },
      ]

      environment = local.container_environment
      secrets     = local.container_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }

      cpu    = 512
      memory = 512
    }
  ])
  depends_on = [
    aws_s3_object.config,
  ]
}

resource "aws_ecs_service" "app" {
  name                 = var.app_name
  cluster              = aws_ecs_cluster.main.id
  task_definition      = aws_ecs_task_definition.app.arn
  desired_count        = 2
  launch_type          = "FARGATE"
  force_new_deployment = true

  network_configuration {
    subnets          = [local.private_subnet_a, local.private_subnet_b]
    security_groups  = [aws_security_group.ecs_task.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = var.app_name
    container_port   = 8080
  }

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 60 # the task runs migrations before serving /health
  enable_execute_command             = true

  depends_on = [
    aws_lb_listener.http,
  ]
}

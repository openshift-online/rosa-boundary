# Lambda function for periodic garbage collection of stale investigations

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "reap_investigations_lambda" {
  name              = "/aws/lambda/${var.project}-${var.stage}-reap-investigations"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

# IAM role for Lambda execution
resource "aws_iam_role" "reap_investigations_lambda" {
  name = "${var.project}-${var.stage}-reap-investigations-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

# Lambda basic execution permissions (CloudWatch Logs)
resource "aws_iam_role_policy_attachment" "reap_investigations_lambda_basic" {
  role       = aws_iam_role.reap_investigations_lambda.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda VPC execution permissions (required for VPC-attached Lambda)
resource "aws_iam_role_policy_attachment" "reap_investigations_lambda_vpc" {
  role       = aws_iam_role.reap_investigations_lambda.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Lambda permissions for ECS operations
resource "aws_iam_role_policy" "reap_investigations_lambda_ecs" {
  name = "ecs-investigation-reaping"
  role = aws_iam_role.reap_investigations_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecs:ListTasks",
          "ecs:DescribeTasks"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ecs:cluster" = aws_ecs_cluster.main.arn
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = "ecs:ListTaskDefinitions"
        Resource = "*"  # ListTaskDefinitions requires wildcard resource
      },
      {
        Effect   = "Allow"
        Action   = "ecs:DeregisterTaskDefinition"
        Resource = "*"  # DeregisterTaskDefinition does not support resource-level permissions
      }
    ]
  })
}

# Lambda permissions for EFS operations
resource "aws_iam_role_policy" "reap_investigations_lambda_efs" {
  name = "efs-investigation-cleanup"
  role = aws_iam_role.reap_investigations_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action   = "elasticfilesystem:DescribeAccessPoints"
        Resource = aws_efs_file_system.sre_home.arn
      },
      {
        Effect   = "Allow"
        Action   = "elasticfilesystem:DeleteAccessPoint"
        Resource = "arn:${data.aws_partition.current.partition}:elasticfilesystem:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:access-point/*"
        Condition = {
          StringEquals = {
            # Investigation access points created by the OIDC Lambda carry this tag.
            # It prevents the reaper role from deleting unrelated access points.
            "aws:ResourceTag/ManagedBy" = "rosa-boundary-lambda"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticfilesystem:ClientMount",
          "elasticfilesystem:ClientWrite",
          "elasticfilesystem:ClientRootAccess"
        ]
        Resource = aws_efs_file_system.sre_home.arn
        Condition = {
          StringEquals = {
            "elasticfilesystem:AccessPointArn" = aws_efs_access_point.reaper.arn
          }
        }
      }
    ]
  })
}

# Lambda permissions for S3 audit backup
resource "aws_iam_role_policy" "reap_investigations_lambda_s3" {
  name = "s3-audit-backup"
  role = aws_iam_role.reap_investigations_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "s3:ListBucket"
        Resource = aws_s3_bucket.audit.arn
        Condition = {
          StringLike = {
            "s3:prefix" = "*/*/reaper-final-backup/*"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        # Reaper writes to a deterministic path: s3://bucket/{cluster}/{investigation}/reaper-final-backup/*
        Resource = "${aws_s3_bucket.audit.arn}/*/*/reaper-final-backup/*"
      }
    ]
  })
}

# Dedicated EFS access point for reaper Lambda (root access to entire filesystem)
resource "aws_efs_access_point" "reaper" {
  file_system_id = aws_efs_file_system.sre_home.id

  posix_user {
    uid = 0  # root user
    gid = 0  # root group
  }

  root_directory {
    path = "/"  # Root of filesystem for full access

    creation_info {
      owner_uid   = 0
      owner_gid   = 0
      permissions = "0755"
    }
  }

  tags = merge(local.common_tags, {
    Name    = "${var.project}-${var.stage}-reaper-access-point"
    Purpose = "Lambda reaper root access for investigation cleanup"
  })
}

# Security group for reaper Lambda
resource "aws_security_group" "reaper_lambda" {
  name        = "${var.project}-${var.stage}-reaper-lambda-sg"
  description = "Security group for investigation reaper Lambda"
  vpc_id      = var.vpc_id

  # Lambda needs no ingress (initiated by EventBridge)

  egress {
    description = "Allow all outbound traffic (for AWS API calls)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-reaper-lambda-sg"
  })
}

# Update EFS security group to allow NFS from reaper Lambda
resource "aws_security_group_rule" "efs_from_reaper_lambda" {
  type                     = "ingress"
  description              = "NFS from reaper Lambda"
  from_port                = 2049
  to_port                  = 2049
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.reaper_lambda.id
  security_group_id        = aws_security_group.efs.id
}

# Archive the Lambda function code (single file, no dependencies)
data "archive_file" "reap_investigations_lambda" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/reap-investigations/handler.py"
  output_path = "${path.module}/.terraform/lambda/reap-investigations.zip"
}

# Lambda function
resource "aws_lambda_function" "reap_investigations" {
  filename         = data.archive_file.reap_investigations_lambda.output_path
  function_name    = "${var.project}-${var.stage}-reap-investigations"
  role             = aws_iam_role.reap_investigations_lambda.arn
  handler          = "handler.lambda_handler"
  source_code_hash = data.archive_file.reap_investigations_lambda.output_base64sha256
  runtime          = "python3.11"
  timeout          = 300 # 5 minutes (enough to process many investigations)
  memory_size      = 256 # Need more memory than task reaper for directory operations

  environment {
    variables = {
      ECS_CLUSTER             = aws_ecs_cluster.main.name
      EFS_FILESYSTEM_ID       = aws_efs_file_system.sre_home.id
      GRACE_PERIOD_HOURS      = var.investigation_grace_period_hours
      S3_AUDIT_BUCKET         = aws_s3_bucket.audit.id
      TASK_DEFINITION_FAMILY  = aws_ecs_task_definition.rosa_boundary.family
    }
  }

  # VPC configuration for EFS access
  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.reaper_lambda.id]
  }

  # EFS mount configuration
  file_system_config {
    arn              = aws_efs_access_point.reaper.arn
    local_mount_path = "/mnt/efs"
  }

  depends_on = [
    aws_cloudwatch_log_group.reap_investigations_lambda,
    aws_iam_role_policy_attachment.reap_investigations_lambda_basic,
    aws_iam_role_policy_attachment.reap_investigations_lambda_vpc,
    aws_efs_mount_target.sre_home # Ensure mount targets exist before Lambda tries to mount
  ]

  tags = local.common_tags
}

# EventBridge Rule for periodic invocation
resource "aws_cloudwatch_event_rule" "reap_investigations_schedule" {
  name                = "${var.project}-${var.stage}-reap-investigations"
  description         = "Trigger investigation reaper Lambda every ${var.investigation_reaper_schedule_hours} hours"
  schedule_expression = "rate(${var.investigation_reaper_schedule_hours} hours)"

  tags = local.common_tags
}

# EventBridge Target
resource "aws_cloudwatch_event_target" "reap_investigations_lambda" {
  rule      = aws_cloudwatch_event_rule.reap_investigations_schedule.name
  target_id = "ReapInvestigationsLambda"
  arn       = aws_lambda_function.reap_investigations.arn
}

# Lambda permission for EventBridge invocation
resource "aws_lambda_permission" "reap_investigations_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.reap_investigations.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.reap_investigations_schedule.arn
}

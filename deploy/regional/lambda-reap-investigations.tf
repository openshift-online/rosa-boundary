# Lambda function for periodic garbage collection of stale investigations

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "reap_investigations_lambda" {
  name              = "/aws/lambda/${var.project}-${var.stage}-reap-investigations"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

# Lambda permissions for ECS operations
resource "aws_iam_role_policy" "reap_investigations_lambda_ecs" {
  name = "ecs-investigation-reaping${local.regional_policy_suffix}"
  role = data.aws_iam_role.reap_investigations_lambda.id

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
        Action   = ["ecs:ListTaskDefinitions", "ecs:DescribeTaskDefinition"]
        Resource = "*" # List and describe do not support resource-level permissions
      },
      {
        Effect   = "Allow"
        Action   = "ecs:DeregisterTaskDefinition"
        Resource = "*" # DeregisterTaskDefinition does not support resource-level permissions
      }
    ]
  })
}

# Lambda permissions for EFS operations
resource "aws_iam_role_policy" "reap_investigations_lambda_efs" {
  name = "efs-investigation-cleanup${local.regional_policy_suffix}"
  role = data.aws_iam_role.reap_investigations_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "elasticfilesystem:DescribeAccessPoints"
        Resource = aws_efs_file_system.sre_home.arn
      },
      {
        Sid      = "DeleteUnsealedInvestigationAccessPoint"
        Effect   = "Allow"
        Action   = "elasticfilesystem:DeleteAccessPoint"
        Resource = "arn:${data.aws_partition.current.partition}:elasticfilesystem:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:access-point/*"
        Condition = {
          StringEquals = {
            # Investigation access points created by the OIDC Lambda carry this tag.
            # It prevents the reaper role from deleting unrelated access points.
            "aws:ResourceTag/ManagedBy" = "rosa-boundary-lambda"
          }
          Null = { "aws:ResourceTag/AuditCloseSeal" = "true" }
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
      },
      {
        # A seal this reaper applied may be finished by this reaper. A seal
        # without the managed marker is a manual or legacy hold and stays
        # protected by IAM, not only by handler logic.
        Sid      = "DeleteOwnManagedSealedAccessPoint"
        Effect   = "Allow"
        Action   = "elasticfilesystem:DeleteAccessPoint"
        Resource = "arn:${data.aws_partition.current.partition}:elasticfilesystem:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:access-point/*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/ManagedBy"           = "rosa-boundary-lambda"
            "aws:ResourceTag/AuditCloseManagedBy" = "rosa-boundary-reaper"
          }
        }
      },
      {
        # Apply the managed close marker. The Null condition means IAM itself
        # refuses to overwrite an existing seal of any kind.
        Sid      = "SealUnsealedInvestigationAccessPoint"
        Effect   = "Allow"
        Action   = "elasticfilesystem:TagResource"
        Resource = "arn:${data.aws_partition.current.partition}:elasticfilesystem:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:access-point/*"
        Condition = {
          StringEquals = { "aws:ResourceTag/ManagedBy" = "rosa-boundary-lambda" }
          Null         = { "aws:ResourceTag/AuditCloseSeal" = "true" }
        }
      }
    ]
  })
}

# Lambda permissions for close requests, attempt evidence and receipts.
#
# Everything the finalizer reads or writes lives under the service-only
# _boundary-close/ prefix, which the investigation task role is explicitly
# denied (see the task_s3 policy). The historical reaper-final-backup/ prefix
# is no longer written: a shared prefix cannot show which attempt produced it,
# so each close copies into its own attempt prefix instead.
resource "aws_iam_role_policy" "reap_investigations_lambda_s3" {
  name = "s3-audit-backup${local.regional_policy_suffix}"
  role = data.aws_iam_role.reap_investigations_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.audit.arn
        Condition = {
          StringLike = {
            "s3:prefix" = "_boundary-close/*"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.audit.arn}/_boundary-close/*"
      },
      {
        Effect   = "Allow"
        Action   = "s3:AbortMultipartUpload"
        Resource = "${aws_s3_bucket.audit.arn}/_boundary-close/evidence/fsap-*/attempts/*/workspace/*"
      }
    ]
  })
}

# Finalization needs to observe sessions and stop consented tasks.
resource "aws_iam_role_policy" "reap_investigations_lambda_sessions" {
  name = "close-session-observation${local.regional_policy_suffix}"
  role = data.aws_iam_role.reap_investigations_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "ecs:StopTask"
        Resource  = "arn:${data.aws_partition.current.partition}:ecs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.main.name}/*"
        Condition = { StringEquals = { "ecs:cluster" = aws_ecs_cluster.main.arn } }
      },
      {
        # DescribeSessions cannot be scoped to an SSM resource ARN. A RUNNING
        # task is not proof of an attached session, so the finalizer has to ask.
        Effect   = "Allow"
        Action   = "ssm:DescribeSessions"
        Resource = "*"
      }
    ]
  })
}

# Dedicated EFS access point for reaper Lambda (root access to entire filesystem)
resource "aws_efs_access_point" "reaper" {
  file_system_id = aws_efs_file_system.sre_home.id

  posix_user {
    uid = 0 # root user
    gid = 0 # root group
  }

  root_directory {
    path = "/" # Root of filesystem for full access

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

# Archive the Lambda function code. The reaper is several standard-library
# modules now (the finalization pipeline, the record contract, the ownership
# observation and the shared workspace comparator), so the whole directory is
# packaged with its tests excluded.
data "archive_file" "reap_investigations_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../lambda/reap-investigations"
  output_path = "${path.module}/.terraform/lambda/reap-investigations.zip"

  excludes = [
    "test_handler.py",
    "test_close_finalization.py",
    "__pycache__",
    ".pytest_cache",
  ]
}

# Lambda function
resource "aws_lambda_function" "reap_investigations" {
  filename         = data.archive_file.reap_investigations_lambda.output_path
  function_name    = "${var.project}-${var.stage}-reap-investigations"
  description      = "Drain sessions and finalize investigation closure after independent workspace backup verification."
  role             = data.aws_iam_role.reap_investigations_lambda.arn
  handler          = "handler.lambda_handler"
  source_code_hash = data.archive_file.reap_investigations_lambda.output_base64sha256
  runtime          = "python3.11"
  timeout          = 300 # 5 minutes (enough to process many investigations)
  memory_size      = 256 # Need more memory than task reaper for directory operations

  # Finalization is serialized to one invocation per deployment. This is an
  # operational constraint on finalizers so two of them cannot interleave
  # sealing, copying and cleanup for the same workspace. It is not a lock
  # against session creation or against any other EFS client, and nothing in
  # the handler treats it as one.
  reserved_concurrent_executions = 1

  environment {
    variables = {
      ECS_CLUSTER                = aws_ecs_cluster.main.name
      EFS_FILESYSTEM_ID          = aws_efs_file_system.sre_home.id
      INVESTIGATION_EXPIRY_HOURS = var.investigation_grace_period_hours
      S3_AUDIT_BUCKET            = aws_s3_bucket.audit.id
      AWS_ACCOUNT_ID             = data.aws_caller_identity.current.account_id
      TASK_DEFINITION_FAMILY     = aws_ecs_task_definition.rosa_boundary.family
      CLOSE_QUIET_SECONDS        = tostring(var.investigation_close_quiet_seconds)
      CLOSE_REQUESTS_PER_RUN     = tostring(var.investigation_close_requests_per_run)
      CLOSE_STALE_RECLAIM        = tostring(var.investigation_stale_reclaim_directories)
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
    aws_iam_role_policy.reap_investigations_lambda_efs,
    aws_efs_file_system_policy.sre_home,
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

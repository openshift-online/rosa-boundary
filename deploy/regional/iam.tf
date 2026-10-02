# IAM role for S3 cross-account audit log replication
resource "aws_iam_role" "s3_replication" {
  count = var.audit_replication_bucket_arn != "" ? 1 : 0
  name  = "${var.project}-${var.stage}-s3-replication-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "s3.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "s3_replication" {
  count = var.audit_replication_bucket_arn != "" ? 1 : 0
  name  = "s3-replication-policy"
  role  = aws_iam_role.s3_replication[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.audit.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging",
          "s3:GetObjectRetention",
          "s3:GetObjectLegalHold"
        ]
        Resource = "${aws_s3_bucket.audit.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags",
          "s3:ObjectOwnerOverrideToBucketOwner"
        ]
        Resource = "${var.audit_replication_bucket_arn}/*"
      }
    ]
  })
}

# ECS Task Execution Role
# Used by ECS to pull images, write logs, and access Secrets Manager
resource "aws_iam_role" "execution" {
  name = "${var.project}-${var.stage}-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

# Attach AWS managed policy for ECS task execution
resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Additional execution permissions for Secrets Manager
resource "aws_iam_role_policy" "execution_secrets" {
  name = "secrets-manager-access"
  role = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ]
      Resource = "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:secret:${var.project}/*"
    }]
  })
}

# ECS Task Role
# Used by the container at runtime for AWS API calls
resource "aws_iam_role" "task" {
  name = "${var.project}-${var.stage}-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

# S3 write access to audit bucket
resource "aws_iam_role_policy" "task_s3" {
  name = "s3-audit-access"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.audit.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.audit.arn
      }
    ]
  })
}

# Deny all unapproved resources even if someone adds another role policy.
# Keep this inline policy small: IAM limits aggregate inline policy size on a
# role, and five cross-Region model grants exceed that budget by themselves.
resource "aws_iam_role_policy" "task_bedrock" {
  name = "bedrock-access"
  role = aws_iam_role.task.id

  # When onboarding a model, attach its scoped grant before replacing the
  # former broad inline policy to minimize interruption for existing tasks.
  depends_on = [aws_iam_role_policy_attachment.task_bedrock_model]

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.bedrock_invoke_denies
  })
}

# Each approved model gets an independent managed policy, avoiding both the
# role's aggregate inline policy limit and the managed policy document limit.
resource "aws_iam_policy" "task_bedrock_model" {
  for_each = var.bedrock_allowed_models

  name = "${var.project}-${var.stage}-bedrock-${replace(each.key, ":", "-")}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(local.bedrock_model_statements[each.key], [
      {
        # A direct foundation-model call or another profile must never reuse
        # this grant, including if another Allow is later added to the role.
        Effect   = "Deny"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = local.bedrock_allowed_foundation_models[each.key]
        Condition = {
          StringNotEqualsIfExists = { "bedrock:InferenceProfileArn" = local.bedrock_allowed_profiles[each.key] }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["bedrock:GetInferenceProfile"]
        Resource = [local.bedrock_allowed_profiles[each.key]]
      }
    ])
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "task_bedrock_model" {
  for_each = aws_iam_policy.task_bedrock_model

  role       = aws_iam_role.task.name
  policy_arn = each.value.arn
}

# ECS Exec access via SSM
resource "aws_iam_role_policy" "task_ecs_exec" {
  name = "ecs-exec-access"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ]
      Resource = "*"
    }]
  })
}

# SSM session logging to CloudWatch Logs
resource "aws_iam_role_policy" "task_ssm_logging" {
  name = "ssm-session-logging"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # logs:DescribeLogGroups does not support resource-level
        # authorization, so it must be granted against all resources.
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          aws_cloudwatch_log_group.ssm_sessions.arn,
          "${aws_cloudwatch_log_group.ssm_sessions.arn}:*"
        ]
      }
    ]
  })
}

# KMS permissions for ECS Exec session encryption
resource "aws_iam_role_policy" "task_kms" {
  name = "kms-exec-session"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ]
      Resource = aws_kms_key.exec_session.arn
    }]
  })
}

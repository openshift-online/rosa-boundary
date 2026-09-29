# Bedrock invocation logging is account/Region-wide, not limited to Boundary
# tasks. Keep payloads separate from ECS Exec and container logs with a longer
# audit retention period and a log-group-scoped encryption key.
resource "aws_kms_key" "bedrock_invocations" {
  description             = "Encrypt Bedrock model invocation logs for ${var.project}-${var.stage}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableAccountIAMPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogsForBedrockInvocations"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.${data.aws_partition.current.dns_suffix}" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/bedrock/${var.project}-${var.stage}/model-invocations"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "bedrock_invocations" {
  name          = "alias/${var.project}-${var.stage}-bedrock-invocations"
  target_key_id = aws_kms_key.bedrock_invocations.key_id
}

resource "aws_cloudwatch_log_group" "bedrock_invocations" {
  name              = "/aws/bedrock/${var.project}-${var.stage}/model-invocations"
  retention_in_days = var.retention_days
  kms_key_id        = aws_kms_key.bedrock_invocations.arn

  tags = local.common_tags
}

resource "aws_iam_role" "bedrock_invocation_logging" {
  name = "${var.project}-${var.stage}-bedrock-invocation-logging"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:bedrock:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*" }
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "bedrock_invocation_logging" {
  name = "write-model-invocations"
  role = aws_iam_role.bedrock_invocation_logging.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.bedrock_invocations.arn}:log-stream:aws/bedrock/modelinvocations"
    }]
  })
}

# Only text delivery is enabled for the current Claude Code path. This setting
# affects every Bedrock Runtime caller in the account/Region; CloudWatch can
# contain prompt/response bodies up to 100 KB; larger text bodies go to the
# dedicated S3 bucket. Both destinations require restricted read access.
resource "aws_bedrock_model_invocation_logging_configuration" "boundary" {
  logging_config {
    text_data_delivery_enabled      = true
    image_data_delivery_enabled     = false
    embedding_data_delivery_enabled = false
    video_data_delivery_enabled     = false

    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.bedrock_invocations.name
      role_arn       = aws_iam_role.bedrock_invocation_logging.arn

      large_data_delivery_s3_config {
        bucket_name = aws_s3_bucket.bedrock_large_payloads.id
        key_prefix  = "large-data"
      }
    }
  }

  depends_on = [
    aws_iam_role_policy.bedrock_invocation_logging,
    aws_s3_bucket_policy.bedrock_large_payloads,
    aws_s3_bucket_server_side_encryption_configuration.bedrock_large_payloads,
    aws_s3_bucket_ownership_controls.bedrock_large_payloads,
    aws_s3_bucket_lifecycle_configuration.bedrock_large_payloads
  ]
}

# The regional S3 Files service role is distinct from the shared task role and
# publisher identities. Only AWS may assume it; users receive no credentials.
resource "aws_iam_role" "content_files" {
  name = "${var.project}-${var.stage}-content-files-${data.aws_region.current.region}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "elasticfilesystem.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike = {
          "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:s3files:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:file-system/*"
        }
      }
    }]
  })
  tags = local.common_tags
}

# AWS's synchronization service requires bucket/version operations and managed
# EventBridge rules. Scope object and KMS permissions to the published prefixes.
# These service-side permissions are NOT granted to investigation tasks. All
# file-system clients are denied writes by the file-system resource policies.
resource "aws_iam_role_policy" "content_files" {
  role = aws_iam_role.content_files.id
  name = "content-files-service"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Follow the service prerequisite contract: bucket-scoped listing may
        # be used during initialization. Object reads/writes remain prefix-scoped;
        # this service-only grant does not widen the task's listing permissions.
        Sid      = "ListPublishedVersions"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:ListBucketVersions"]
        Resource = aws_s3_bucket.content.arn
      },
      {
        Sid      = "SynchronizePublishedContent"
        Effect   = "Allow"
        Action   = ["s3:GetObject*", "s3:PutObject*", "s3:DeleteObject*", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
        Resource = local.content_object_arns
      },
      {
        Sid      = "UseContentKeyThroughS3"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Encrypt", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo"]
        Resource = local.content_kms_key_arn
        Condition = {
          StringLike = {
            "kms:ViaService"                   = local.content_kms_via_service
            "kms:EncryptionContext:aws:s3:arn" = local.content_object_arns
          }
        }
      },
      {
        Sid       = "ManageServiceOwnedSynchronizationRules"
        Effect    = "Allow"
        Action    = ["events:DeleteRule", "events:DisableRule", "events:EnableRule", "events:PutRule", "events:PutTargets", "events:RemoveTargets"]
        Resource  = "arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:rule/DO-NOT-DELETE-S3-Files*"
        Condition = { StringEquals = { "events:ManagedBy" = "elasticfilesystem.amazonaws.com" } }
      },
      {
        Sid      = "InspectSynchronizationRules"
        Effect   = "Allow"
        Action   = ["events:DescribeRule", "events:ListRuleNamesByTarget", "events:ListRules", "events:ListTargetsByRule"]
        Resource = "arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:rule/*"
      },
    ]
  })
}

# Explicit denials prevent broader grants on the shared task role from turning
# the mounted content into a write path, including bypass via the S3 API.
resource "aws_iam_role_policy" "task_content_files" {
  role = data.aws_iam_role.task.id
  name = "s3-content-files-read${local.regional_policy_suffix}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "MountPublishedContent"
        Effect   = "Allow"
        Action   = ["s3files:ClientMount"]
        Resource = [for fs in aws_s3files_file_system.content : fs.arn]
      },
      {
        Sid      = "DenyFileSystemWrites"
        Effect   = "Deny"
        Action   = ["s3files:ClientWrite", "s3files:ClientRootAccess"]
        Resource = [for fs in aws_s3files_file_system.content : fs.arn]
      },
      {
        Sid      = "DenyDirectContentMutation"
        Effect   = "Deny"
        Action   = ["s3:Put*", "s3:Delete*", "s3:AbortMultipartUpload", "s3:RestoreObject", "s3:Replicate*"]
        Resource = [aws_s3_bucket.content.arn, "${aws_s3_bucket.content.arn}/*"]
      },
    ]
  })
}

# S3 Files consumes object-change events through service-managed EventBridge
# rules. This is the sole owner of the content bucket notification configuration.
resource "aws_s3_bucket_notification" "content" {
  bucket      = aws_s3_bucket.content.id
  eventbridge = true
}

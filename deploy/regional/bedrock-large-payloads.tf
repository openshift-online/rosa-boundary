# CloudWatch includes model invocation bodies only up to 100 KB. Keep larger
# text payloads in a separate bucket, never in the investigation audit escrow.
resource "aws_s3_bucket" "bedrock_large_payloads" {
  bucket = "${local.bucket_name}-bedrock-invocations"
  tags   = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "bedrock_large_payloads" {
  bucket = aws_s3_bucket.bedrock_large_payloads.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "bedrock_large_payloads" {
  bucket = aws_s3_bucket.bedrock_large_payloads.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bedrock_large_payloads" {
  bucket = aws_s3_bucket.bedrock_large_payloads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "bedrock_large_payloads" {
  bucket = aws_s3_bucket.bedrock_large_payloads.id

  rule {
    id     = "expire-model-invocation-payloads"
    status = "Enabled"
    filter {}

    expiration {
      days = var.retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "bedrock_large_payloads" {
  bucket = aws_s3_bucket.bedrock_large_payloads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.bedrock_large_payloads.arn,
          "${aws_s3_bucket.bedrock_large_payloads.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "AllowBedrockLargePayloadDelivery"
        Effect    = "Allow"
        Principal = { Service = "bedrock.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.bedrock_large_payloads.arn}/large-data/AWSLogs/${data.aws_caller_identity.current.account_id}/BedrockModelInvocationLogs/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
          ArnLike      = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:bedrock:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.bedrock_large_payloads]
}

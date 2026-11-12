# regional content storage for published SRE content.
#
# This bucket is deliberately separate from the audit bucket in s3.tf. Audit
# data is write-once evidence under Object Lock; published content is mutable,
# replaceable and read by every investigation task, so the two have opposite
# retention and access requirements and must never share a bucket.
#
# Encryption is SSE-KMS with the Region's AWS-managed alias/aws/s3 key. That key
# may already exist in this account and Region or may not: AWS creates it on
# first use. Either way its ARN is an account- and Region-specific value that
# cannot be checked in. aws_s3_object.key_bootstrap below makes an SSE-KMS
# request so the key is guaranteed to be available, and
# data.aws_kms_alias.content_s3 then reads whatever ARN is actually in place.
# The bootstrap establishes availability; it is not evidence that the key was
# absent beforehand. No customer-managed key is created and no AWS-managed key
# policy is edited.

locals {
  content_bucket_name = "${local.bucket_name}-content"

  # Reserved, never published and never replicated. Writing it is what
  # materialises the Region's AWS-managed aws/s3 key; nothing reads it.
  content_bootstrap_key = "_bootstrap/key-init"

  # Sorted so a rule's generated priority depends only on the prefix set, not
  # on map iteration order.
  content_prefix_keys = sort(keys(var.content_prefixes))

  # A shared topology must never give replica states source-owned grants.
  content_replication_destinations = var.replication == null ? [] : [
    for region, destination in var.replication.destinations :
    merge(destination.content, { region = region })
    if destination.content != null && var.aws_region == var.replication.primary_region
  ]

  content_replication_enabled = length(local.content_replication_destinations) > 0

  # One rule per (destination, prefix). The stride is the prefix count rather
  # than a fixed number, so priorities stay unique for any number of prefixes.
  content_replication_rules = merge([
    for destination_index, destination in local.content_replication_destinations : {
      for prefix_index, prefix_key in local.content_prefix_keys :
      "${destination.region}:${prefix_key}" => {
        id          = "replicate-${prefix_key}-to-${destination.region}"
        prefix      = var.content_prefixes[prefix_key]
        priority    = destination_index * length(local.content_prefix_keys) + prefix_index + 1
        bucket_arn  = destination.bucket_arn
        kms_key_arn = destination.kms_key_arn
        region      = destination.region
      }
    }
  ]...)

  # Expected destination bucket names under the shared convention. A supplied
  # ARN that disagrees is rejected rather than silently replicated into.
  content_expected_destination_bucket_arns = {
    for destination in local.content_replication_destinations :
    destination.region => "arn:${data.aws_partition.current.partition}:s3:::${data.aws_caller_identity.current.account_id}-${var.project}-${var.stage}-${destination.region}-content"
  }
}

resource "aws_s3_bucket" "content" {
  bucket        = local.content_bucket_name
  force_destroy = var.content_bucket_force_destroy

  tags = merge(local.common_tags, {
    Name = local.content_bucket_name
  })
}

# Required by replication, and it keeps a bad publish recoverable.
resource "aws_s3_bucket_versioning" "content" {
  bucket = aws_s3_bucket.content.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "content" {
  bucket = aws_s3_bucket.content.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SSE-KMS with the AWS-managed aws/s3 key: sse_algorithm is "aws:kms" and
# kms_master_key_id is deliberately omitted, which is how S3 selects aws/s3.
# bucket_key_enabled is deliberately NOT set: omitting it is the agreed minimal
# initial implementation, not a claim that Bucket Keys can never work here.
# Enabling one would move the KMS encryption context from the object ARN to the
# bucket ARN and, per the S3 replication guidance, requires kms:Decrypt for the
# calling principal on the replica key. Since an AWS-managed key's policy is not
# ours to edit, that path would need its effective permissions demonstrated
# against a real account before it could be adopted.
resource "aws_s3_bucket_server_side_encryption_configuration" "content" {
  bucket = aws_s3_bucket.content.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_policy" "content" {
  bucket = aws_s3_bucket.content.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.content.arn,
          "${aws_s3_bucket.content.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        # "No object here is unencrypted or SSE-S3 encrypted" is the invariant
        # that lets the replication role omit kms:GenerateDataKey. Two
        # mechanisms hold it together: this statement denies any upload that
        # asks for an algorithm other than aws:kms, and bucket default
        # encryption (aws:kms, above) encrypts any upload that asks for
        # nothing.
        #
        # The Null guard is required for correctness, not leniency. AWS accepts
        # the x-amz-server-side-encryption request header only on PutObject,
        # CopyObject, POST Object and CreateMultipartUpload; UploadPart does
        # not carry it. A negated condition operator is true when its key is
        # absent, so a bare StringNotEquals would deny every UploadPart - and
        # UploadPart is authorised as s3:PutObject - breaking the multipart
        # path the publisher grant explicitly supports. Null = "false" limits
        # the check to requests that actually supplied the header, so it still
        # applies to every request that can carry one.
        #
        # Publishing jobs should still pass --sse aws:kms: it is the explicit,
        # auditable form and CreateMultipartUpload does carry it.
        Sid       = "DenyUploadsWithAnotherEncryptionAlgorithm"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.content.arn}/*"
        Condition = {
          StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" }
          Null            = { "s3:x-amz-server-side-encryption" = "false" }
        }
      },
      {
        # Absent headers use the bucket default and permit UploadPart. An
        # explicit key must be the resolved regional aws/s3 key ARN.
        Sid       = "DenyUploadsWithAnotherKMSKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.content.arn}/*"
        Condition = {
          StringNotEquals = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = local.content_kms_key_arn }
          Null            = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = "false" }
        }
      },
      {
        # SSE-C uses its own header, so it would slip past the statement above
        # whose Null guard only inspects x-amz-server-side-encryption, and S3
        # honours an explicit SSE-C request over the bucket default. A
        # customer-key-encrypted object cannot be read by the task role or
        # re-encrypted by the replication role, so it is refused outright.
        # Null = "false" here means "deny when the SSE-C header is present".
        Sid       = "DenyCustomerProvidedKeyUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.content.arn}/*"
        Condition = {
          Null = { "s3:x-amz-server-side-encryption-customer-algorithm" = "false" }
        }
      },
    ]
  })
}

# Noncurrent versions and abandoned multipart uploads only. There is
# deliberately no expiration rule for current objects: published content has no
# expiry and must never be removed by a lifecycle rule.
resource "aws_s3_bucket_lifecycle_configuration" "content" {
  bucket = aws_s3_bucket.content.id

  rule {
    id     = "expire-noncurrent-content-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = var.content_noncurrent_version_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.content]
}

# An SSE-KMS write that guarantees the AWS-managed aws/s3 key exists and is
# usable in this Region before anything depends on it. A single empty object under the reserved
# _bootstrap/ prefix: outside every published and replicated prefix, so no
# publisher's `aws s3 sync --delete` can remove it and it cannot collide with
# real content. It is key initialisation only — not a manifest, marker, catalog
# or fallback, and nothing reads it. server_side_encryption is explicit so the
# bootstrap requests SSE-KMS directly; omitted headers are also allowed and use
# the bucket's SSE-KMS default.
resource "aws_s3_object" "key_bootstrap" {
  bucket                 = aws_s3_bucket.content.id
  key                    = local.content_bootstrap_key
  content                = ""
  content_type           = "text/plain"
  server_side_encryption = "aws:kms"

  tags = local.common_tags

  depends_on = [
    aws_s3_bucket_server_side_encryption_configuration.content,
    # The bucket policy needs the resolved key ARN, so it must follow this
    # bootstrap rather than create a dependency cycle. This reserved object
    # explicitly requests aws:kms without a key ID and cannot use another key.
  ]
}

# Read after the bootstrap write, so the alias exists by the time it is read and
# the grants below receive the Region's real key ARN instead of a guess.
data "aws_kms_alias" "content_s3" {
  name = "alias/aws/s3"

  depends_on = [aws_s3_object.key_bootstrap]
}

# Exactly one replication configuration, owned by the source Region's state.
# It is created last: S3 accepts a replication configuration without validating
# the replica key, so replication would start and fail silently if the grants
# were not already in place.
resource "aws_s3_bucket_replication_configuration" "content" {
  count  = local.content_replication_enabled ? 1 : 0
  bucket = aws_s3_bucket.content.id
  role   = var.content_replication_role_arn

  lifecycle {
    precondition {
      condition     = var.content_replication_role_arn != ""
      error_message = "content_replication_role_arn is required when replication has active content destinations: S3 replication needs the account-owned content replication identity."
    }

    precondition {
      condition     = alltrue([for destination in local.content_replication_destinations : destination.content_prefixes == var.content_prefixes])
      error_message = "Destination content_prefixes must match the source map exactly; copy each destination's exported map with its bucket and key outputs before enabling replication."
    }

    precondition {
      condition = alltrue([
        for destination in local.content_replication_destinations :
        destination.region != var.aws_region
      ])
      error_message = "A content replication destination may not be this workspace's own aws_region; a bucket cannot replicate to itself."
    }

    precondition {
      condition = alltrue([
        for destination in local.content_replication_destinations :
        destination.bucket_arn == local.content_expected_destination_bucket_arns[destination.region]
      ])
      error_message = "Each content replication destination bucket_arn must match the shared convention <account>-<project>-<stage>-<region>-content in this account and partition. A mismatch means the ARN belongs to another account, stage or naming scheme."
    }

    precondition {
      condition = alltrue([
        for destination in local.content_replication_destinations :
        can(regex("^arn:${data.aws_partition.current.partition}:kms:${destination.region}:${data.aws_caller_identity.current.account_id}:key/", destination.kms_key_arn))
      ])
      error_message = "Each content replication destination kms_key_arn must be in this account and partition and in that destination's own Region. Cross-account replication would require a customer-managed key, which this design does not use."
    }
  }

  dynamic "rule" {
    for_each = local.content_replication_rules

    content {
      id       = rule.value.id
      status   = "Enabled"
      priority = rule.value.priority

      # Prefix-only filter, no tag predicate: that is what keeps delete-marker
      # replication valid for this rule.
      filter {
        prefix = rule.value.prefix
      }

      delete_marker_replication {
        status = "Enabled"
      }

      # S3 does not replicate SSE-KMS objects unless this opt-in is present.
      source_selection_criteria {
        sse_kms_encrypted_objects {
          status = "Enabled"
        }
      }

      destination {
        bucket        = rule.value.bucket_arn
        storage_class = "STANDARD"

        encryption_configuration {
          replica_kms_key_id = rule.value.kms_key_arn
        }
      }
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.content,
    aws_s3_bucket_policy.content,
    aws_iam_role_policy.content_replication,
    aws_iam_role_policy.content_publisher,
    aws_iam_role_policy.task_content,
  ]
}

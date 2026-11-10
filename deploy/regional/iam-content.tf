# regional grants for published content.
#
# Account state owns every identity referenced here (deploy/account);
# this state owns only the regional permissions attached to them, exactly as
# account-iam.tf and iam.tf already do for the shared roles. Each policy name
# carries local.regional_policy_suffix so a second Region attaches its own
# policy instead of overwriting this one.
#
# Every action below is justified by an actual call path. Deliberately absent:
#   s3:GetObject on the publisher grant   - `aws s3 sync` decides what to upload
#                                           from the listing's size and
#                                           last-modified time; it never reads
#                                           the destination object.
#   s3:PutObjectTagging                   - the CLI sets no tags.
#   kms:Encrypt on the publisher grant    - PutObject and CreateMultipartUpload
#                                           use GenerateDataKey, not Encrypt.
#   kms:DescribeKey                       - never called on these paths, and a
#                                           direct DescribeKey would be denied
#                                           by the kms:ViaService condition
#                                           anyway, since it does not arrive
#                                           through S3.
#   kms:GenerateDataKey on replication    - needed only to replicate plaintext
#                                           objects. Bucket default SSE-KMS,
#                                           DenyUploadsWithAnotherEncryptionAlgorithm
#                                           and DenyCustomerProvidedKeyUploads
#                                           together exclude those objects.

locals {
  # The account root publishes role ARNs; aws_iam_role_policy (PutRolePolicy)
  # takes a role NAME, which carries no path. The input validation restricts
  # these to path-less ARNs - the only shape deploy/account emits, since it
  # creates every role without a path - so this split yields the one
  # unambiguous name. A path-qualified ARN is rejected rather than accepted and
  # silently normalised: role names are unique per account, so a wrong path
  # with a real basename would otherwise attach the policy to a live role whose
  # ARN is not the one supplied. The preconditions below additionally reject an
  # ARN outside this account and partition.
  content_publisher_role_names = {
    for key, arn in var.content_publisher_role_arns :
    key => element(split("/", arn), length(split("/", arn)) - 1)
  }

  content_replication_role_name = var.content_replication_role_arn != "" ? element(
    split("/", var.content_replication_role_arn),
    length(split("/", var.content_replication_role_arn)) - 1
  ) : ""

  content_role_arn_prefix = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/"

  content_kms_key_arn = data.aws_kms_alias.content_s3.target_key_arn

  content_kms_via_service = "s3.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"

  # Object-ARN encryption contexts are correct precisely because S3 Bucket Keys
  # are not enabled; a Bucket Key would make the context the bucket ARN.
  content_object_arns = [
    for prefix in values(var.content_prefixes) : "${aws_s3_bucket.content.arn}/${prefix}*"
  ]

  # Both the bare prefix and its wildcard, so ListBucket works for the prefix
  # itself and everything beneath it.
  content_list_prefixes = flatten([
    for prefix in values(var.content_prefixes) : [prefix, "${prefix}*"]
  ])
}

# Publisher grants: upload into exactly one prefix, nothing else. Rendered only
# where publisher ARNs are supplied, which is the publishing source Region.
resource "aws_iam_role_policy" "content_publisher" {
  for_each = var.content_publisher_role_arns

  name = "content-publish-${each.key}${local.regional_policy_suffix}"
  role = local.content_publisher_role_names[each.key]

  lifecycle {
    precondition {
      condition     = contains(keys(var.content_prefixes), each.key)
      error_message = "Every content_publisher_role_arns key must name a prefix in content_prefixes. An unrecognised key is rejected rather than silently granted nothing."
    }

    precondition {
      condition     = startswith(var.content_publisher_role_arns[each.key], local.content_role_arn_prefix)
      error_message = "Each content_publisher_role_arns value must be a role in this workspace's own account and partition; these grants never cross an account boundary."
    }
  }

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListOwnPrefix"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.content.arn
        Condition = {
          StringLike = {
            "s3:prefix" = [
              var.content_prefixes[each.key],
              "${var.content_prefixes[each.key]}*",
            ]
          }
        }
      },
      {
        # s3:PutObject covers PutObject, CreateMultipartUpload, UploadPart and
        # CompleteMultipartUpload. AbortMultipartUpload is separate and is what
        # the CLI calls when an upload fails part way through.
        Sid    = "PublishOwnPrefix"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:AbortMultipartUpload",
        ]
        Resource = "${aws_s3_bucket.content.arn}/${var.content_prefixes[each.key]}*"
      },
      {
        # GenerateDataKey is required by PutObject and CreateMultipartUpload
        # under SSE-KMS; Decrypt is required by UploadPart and
        # CompleteMultipartUpload, which must read back the encrypted parts.
        Sid    = "UseRegionalS3ManagedKey"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
        ]
        Resource = local.content_kms_key_arn
        Condition = {
          StringLike = {
            "kms:ViaService"                   = local.content_kms_via_service
            "kms:EncryptionContext:aws:s3:arn" = "${aws_s3_bucket.content.arn}/${var.content_prefixes[each.key]}*"
          }
        }
      },
    ]
  })
}

# Runtime grant on the shared task role: read the local Region's content and
# decrypt it. No write action, and no ARN outside this Region's own bucket.
resource "aws_iam_role_policy" "task_content" {
  name = "s3-content-read${local.regional_policy_suffix}"
  role = data.aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListPublishedPrefixes"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.content.arn
        Condition = {
          StringLike = {
            "s3:prefix" = local.content_list_prefixes
          }
        }
      },
      {
        # This direction genuinely downloads, so GetObject and Decrypt are
        # required here even though the publisher grant does not need them.
        Sid      = "ReadPublishedContent"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = local.content_object_arns
      },
      {
        Sid      = "DecryptPublishedContent"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = local.content_kms_key_arn
        Condition = {
          StringLike = {
            "kms:ViaService"                   = local.content_kms_via_service
            "kms:EncryptionContext:aws:s3:arn" = local.content_object_arns
          }
        }
      },
    ]
  })
}

# Content replication identity, owned by the source Region's state so exactly
# one Region manages this role's regional policy. Separate from the audit
# replication role in iam.tf, which must never carry content permissions.
resource "aws_iam_role_policy" "content_replication" {
  count = local.content_replication_enabled ? 1 : 0

  name = "content-replication${local.regional_policy_suffix}"
  role = local.content_replication_role_name

  lifecycle {
    precondition {
      condition     = startswith(var.content_replication_role_arn, local.content_role_arn_prefix)
      error_message = "content_replication_role_arn must be a role in this workspace's own account and partition."
    }
  }

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "ReadSourceReplicationState"
          Effect = "Allow"
          Action = [
            "s3:GetReplicationConfiguration",
            "s3:ListBucket",
          ]
          Resource = aws_s3_bucket.content.arn
        },
        {
          Sid    = "ReadSourceObjectVersions"
          Effect = "Allow"
          Action = [
            "s3:GetObjectVersionForReplication",
            "s3:GetObjectVersionAcl",
          ]
          Resource = local.content_object_arns
        },
        {
          Sid      = "DecryptSourceObjects"
          Effect   = "Allow"
          Action   = ["kms:Decrypt"]
          Resource = local.content_kms_key_arn
          Condition = {
            StringLike = {
              "kms:ViaService"                   = local.content_kms_via_service
              "kms:EncryptionContext:aws:s3:arn" = local.content_object_arns
            }
          }
        },
      ],
      [
        for destination in var.content_replication_destinations : {
          Sid      = "ReplicateInto${replace(title(replace(destination.region, "-", " ")), " ", "")}"
          Effect   = "Allow"
          Action   = ["s3:ReplicateObject", "s3:ReplicateDelete"]
          Resource = [for prefix in values(var.content_prefixes) : "${destination.bucket_arn}/${prefix}*"]
        }
      ],
      [
        # The replica key lives in the destination Region, so its ViaService
        # condition names that Region's S3 endpoint, not this one's.
        for destination in var.content_replication_destinations : {
          Sid      = "EncryptReplicasIn${replace(title(replace(destination.region, "-", " ")), " ", "")}"
          Effect   = "Allow"
          Action   = ["kms:Encrypt"]
          Resource = destination.kms_key_arn
          Condition = {
            StringLike = {
              "kms:ViaService"                   = "s3.${destination.region}.${data.aws_partition.current.dns_suffix}"
              "kms:EncryptionContext:aws:s3:arn" = [for prefix in values(var.content_prefixes) : "${destination.bucket_arn}/${prefix}*"]
            }
          }
        }
      ],
    )
  })
}

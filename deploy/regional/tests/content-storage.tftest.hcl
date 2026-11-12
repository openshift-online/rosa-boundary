# published-content storage, grants and replication.
#
# Mocked applies render configuration without touching AWS or live state. These
# assertions prove what Terraform renders; they prove nothing about AWS
# enforcement, real alias/aws/s3 key ARNs or actual replication behaviour, all
# of which stay deferred until an authorised environment exists.
mock_provider "aws" {
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:us-east-1:123456789012:function:boundary-test" }
  }
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = { arn = "arn:aws:events:us-east-1:123456789012:rule/boundary-test" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::boundary-test-audit" }
  }
  mock_resource "aws_ecs_cluster" {
    defaults = { arn = "arn:aws:ecs:us-east-1:123456789012:cluster/rosa-boundary-dev" }
  }
  mock_resource "aws_efs_file_system" {
    defaults = { arn = "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0123456789abcdef0" }
  }
  mock_resource "aws_efs_access_point" {
    defaults = { arn = "arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/fsap-0123456789abcdef0" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:boundary-test" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws", dns_suffix = "amazonaws.com" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1", name = "us-east-1" }
  }
  mock_data "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/boundary-shared", id = "boundary-shared" }
  }
  mock_data "aws_iam_openid_connect_provider" {
    defaults = { arn = "arn:aws:iam::123456789012:oidc-provider/auth.example.com/realms/sre" }
  }
  mock_data "aws_kms_alias" {
    defaults = { target_key_arn = "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222" }
  }
}
mock_provider "archive" {}

variables {
  aws_account_id               = "123456789012"
  aws_region                   = "us-east-1"
  legacy_policy_region         = "us-east-1"
  container_image              = "example.com/rosa-boundary:test"
  vpc_id                       = "vpc-00000000000000000"
  subnet_ids                   = ["subnet-00000000000000000", "subnet-11111111111111111"]
  keycloak_issuer_url          = "https://auth.example.com/realms/sre"
  keycloak_thumbprint          = "0000000000000000000000000000000000000000"
  required_groups              = ["ai-sd-sre"]
  abac_tag_key                 = "uuid"
  enable_kube_proxy            = false
  audit_replication_bucket_arn = "arn:aws:s3:::destination-audit"
  audit_replication_account_id = "210987654321"
  bedrock_model_agreements     = { "anthropic.claude-sonnet-5" = "offer-test" }
  claude_default_model         = "us.anthropic.claude-sonnet-5"
}

override_data {
  target = data.aws_subnet.bedrock_runtime["subnet-00000000000000000"]
  values = { vpc_id = "vpc-00000000000000000", availability_zone_id = "use1-az1" }
}
override_data {
  target = data.aws_subnet.bedrock_runtime["subnet-11111111111111111"]
  values = { vpc_id = "vpc-00000000000000000", availability_zone_id = "use1-az2" }
}
override_data {
  target = data.aws_route_table.subnet[0]
  values = { routes = [{ cidr_block = "0.0.0.0/0", gateway_id = "igw-0", nat_gateway_id = "" }] }
}
override_data {
  target = data.aws_route_table.subnet[1]
  values = { routes = [{ cidr_block = "0.0.0.0/0", gateway_id = "igw-0", nat_gateway_id = "" }] }
}

# A distinct ARN for the content bucket; the shared aws_s3_bucket mock would
# otherwise give it the audit bucket's ARN and hide scoping mistakes.
override_resource {
  target = aws_s3_bucket.content
  values = {
    arn = "arn:aws:s3:::123456789012-rosa-boundary-dev-us-east-1-content"
    id  = "123456789012-rosa-boundary-dev-us-east-1-content"
  }
}

run "content_bucket_and_read_grant_exist_by_default" {
  command = apply

  assert {
    condition = (
      output.content_bucket_name == aws_s3_bucket.content.id &&
      output.content_bucket_arn == aws_s3_bucket.content.arn &&
      output.content_bucket_kms_key_arn == data.aws_kms_alias.content_s3.target_key_arn &&
      aws_iam_role_policy.task_content.role == data.aws_iam_role.task.id &&
      aws_iam_role_policy.task_content.name == "s3-content-read"
    )
    error_message = "Every Region must create its content bucket and task read grant without opting in."
  }

  assert {
    condition = (
      length(aws_iam_role_policy.content_publisher) == 0 &&
      length(aws_iam_role_policy.content_replication) == 0 &&
      length(aws_s3_bucket_replication_configuration.content) == 0 &&
      length(output.content_replication_rule_ids) == 0
    )
    error_message = "Publisher grants require role ARNs; replication requires destinations."
  }

  assert {
    condition     = output.content_bucket_region == "us-east-1" && length(output.content_prefixes) == 3
    error_message = "The default regional bucket exports its Region and all published prefixes."
  }
}

run "replication_role_alone_does_not_enable_replication" {
  command = apply

  variables {
    content_replication_role_arn = "arn:aws:iam::123456789012:role/rosa-boundary-dev-content-replication-role"
  }

  assert {
    condition = (
      length(aws_s3_bucket_replication_configuration.content) == 0 &&
      length(aws_iam_role_policy.content_replication) == 0 &&
      length(aws_iam_role_policy.content_publisher) == 0 &&
      length(output.content_replication_rule_ids) == 0 &&
      aws_iam_role_policy.task_content.role == data.aws_iam_role.task.id
    )
    error_message = "Replica Regions keep their read grant but must not own source grants or replication merely because an account role exists."
  }
}

run "content_bucket_protections" {
  command = apply

  assert {
    condition = length([
      for statement in jsondecode(aws_s3_bucket_policy.content.policy).Statement :
      statement if statement.Sid == "DenyUploadsWithAnotherKMSKey" &&
      statement.Effect == "Deny" &&
      statement.Action == "s3:PutObject" &&
      statement.Condition.StringNotEquals["s3:x-amz-server-side-encryption-aws-kms-key-id"] == data.aws_kms_alias.content_s3.target_key_arn &&
      statement.Condition.Null["s3:x-amz-server-side-encryption-aws-kms-key-id"] == "false"
    ]) == 1
    error_message = "Explicit foreign KMS keys must be denied without blocking absent headers or multipart parts."
  }

  assert {
    condition     = aws_s3_bucket.content.bucket == "123456789012-rosa-boundary-dev-us-east-1-content"
    error_message = "The content bucket must follow the <account>-<project>-<stage>-<region>-content convention derived from the audit bucket's local."
  }

  assert {
    condition     = aws_s3_bucket.content.bucket != aws_s3_bucket.audit.bucket
    error_message = "Content must never share the audit bucket: they have opposite retention and access requirements."
  }

  assert {
    condition     = aws_s3_bucket.content.force_destroy == false
    error_message = "force_destroy must default to false so destroying populated content fails loudly."
  }

  assert {
    condition     = one(aws_s3_bucket_versioning.content.versioning_configuration).status == "Enabled"
    error_message = "Versioning must be enabled: replication requires it."
  }

  assert {
    condition = (
      aws_s3_bucket_public_access_block.content.block_public_acls &&
      aws_s3_bucket_public_access_block.content.block_public_policy &&
      aws_s3_bucket_public_access_block.content.ignore_public_acls &&
      aws_s3_bucket_public_access_block.content.restrict_public_buckets
    )
    error_message = "All four public access block flags must be set on the content bucket."
  }

  assert {
    condition = one([
      for rule in aws_s3_bucket_server_side_encryption_configuration.content.rule :
      one(rule.apply_server_side_encryption_by_default).sse_algorithm
    ]) == "aws:kms"
    error_message = "Default encryption must be SSE-KMS."
  }

  assert {
    condition     = length(regexall("kms_master_key_id\\s*=", file("${path.module}/s3-content.tf"))) == 0
    error_message = "kms_master_key_id must never be set: omitting it is how S3 selects the AWS-managed alias/aws/s3 key, and setting one would introduce a customer-managed key."
  }

  assert {
    condition     = length(regexall("bucket_key_enabled\\s*=", file("${path.module}/s3-content.tf"))) == 0
    error_message = "S3 Bucket Keys must not be enabled: they move the KMS encryption context to the bucket ARN and require kms:Decrypt in the replica key's key policy, which cannot be authored for an AWS-managed key."
  }

  assert {
    condition = (
      length(regexall("aws_kms_key", file("${path.module}/s3-content.tf"))) == 0 &&
      length(regexall("aws_kms_key", file("${path.module}/iam-content.tf"))) == 0
    )
    error_message = "This feature must create no customer-managed key and must not edit any key policy."
  }

  assert {
    condition = length([
      for statement in jsondecode(aws_s3_bucket_policy.content.policy).Statement :
      statement if statement.Sid == "DenyNonTLS" && statement.Effect == "Deny"
    ]) == 1
    error_message = "The content bucket policy must deny non-TLS access, matching the audit bucket."
  }

  assert {
    condition = length([
      for statement in jsondecode(aws_s3_bucket_policy.content.policy).Statement :
      statement if statement.Sid == "DenyUploadsWithAnotherEncryptionAlgorithm" &&
      statement.Effect == "Deny" &&
      statement.Action == "s3:PutObject" &&
      statement.Condition.StringNotEquals["s3:x-amz-server-side-encryption"] == "aws:kms"
    ]) == 1
    error_message = "An upload that asks for any algorithm other than aws:kms must be denied."
  }

  assert {
    condition = length([
      for statement in jsondecode(aws_s3_bucket_policy.content.policy).Statement :
      statement if statement.Sid == "DenyUploadsWithAnotherEncryptionAlgorithm" &&
      statement.Condition.Null["s3:x-amz-server-side-encryption"] == "false"
    ]) == 1
    error_message = "The encryption deny must carry Null = false so it applies only to requests that supplied the header. AWS accepts that header on PutObject, CopyObject, POST Object and CreateMultipartUpload but not on UploadPart, and a negated condition operator is true when its key is absent, so without this guard every UploadPart - authorised as s3:PutObject - would be denied and multipart publishing would break."
  }

  assert {
    condition = length([
      for statement in jsondecode(aws_s3_bucket_policy.content.policy).Statement :
      statement if statement.Sid == "DenyCustomerProvidedKeyUploads" &&
      statement.Effect == "Deny" &&
      statement.Condition.Null["s3:x-amz-server-side-encryption-customer-algorithm"] == "false"
    ]) == 1
    error_message = "SSE-C uploads must be denied outright. They carry a different header, so the Null guard on x-amz-server-side-encryption does not cover them, and a customer-key-encrypted object could be read by neither the task role nor the replication role."
  }

  assert {
    condition = (
      aws_s3_object.key_bootstrap.key == "_bootstrap/key-init" &&
      aws_s3_object.key_bootstrap.server_side_encryption == "aws:kms"
    )
    error_message = "The bootstrap object must live under the reserved _bootstrap/ prefix and explicitly request SSE-KMS to initialise aws/s3."
  }

  assert {
    condition = alltrue([
      for prefix in values(var.content_prefixes) :
      !startswith(aws_s3_object.key_bootstrap.key, prefix)
    ])
    error_message = "The bootstrap object must sit outside every published prefix so a publisher's `aws s3 sync --delete` can never remove it."
  }

  assert {
    condition = alltrue([
      for rule in aws_s3_bucket_lifecycle_configuration.content.rule :
      length(rule.expiration) == 0
    ])
    error_message = "No lifecycle rule may expire current objects: published content has no expiry."
  }

  assert {
    condition = alltrue([
      for rule in aws_s3_bucket_lifecycle_configuration.content.rule :
      length(rule.noncurrent_version_expiration) == 1 && length(rule.abort_incomplete_multipart_upload) == 1
    ])
    error_message = "Lifecycle cleanup must be limited to noncurrent versions and abandoned multipart uploads."
  }

  assert {
    condition = one([
      for rule in aws_s3_bucket_lifecycle_configuration.content.rule :
      one(rule.noncurrent_version_expiration).noncurrent_days
    ]) == var.content_noncurrent_version_days
    error_message = "Content version retention must come from content_noncurrent_version_days, not from retention_days, which governs audit Object Lock and CloudWatch Logs."
  }

  assert {
    condition     = length(regexall("noncurrent_days\\s*=\\s*var\\.retention_days", file("${path.module}/s3-content.tf"))) == 0
    error_message = "Content retention must not be coupled to the audit retention variable."
  }

  assert {
    condition = (
      output.content_bucket_arn == "arn:aws:s3:::123456789012-rosa-boundary-dev-us-east-1-content" &&
      output.content_bucket_region == "us-east-1" &&
      output.content_bucket_kms_key_arn == "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222"
    )
    error_message = "The content outputs must publish the bucket ARN, Region and the resolved AWS-managed key ARN a replica Region's operator needs."
  }

  assert {
    condition = (
      output.content_prefixes["ops-sop"] == "ops-sop/" &&
      output.content_prefixes["rosa-claude-plugins"] == "rosa-claude-plugins/" &&
      output.content_prefixes["managed-notifications"] == "managed-notifications/" &&
      length(output.content_prefixes) == 3
    )
    error_message = "Exactly the three agreed published prefixes must be exported."
  }
}

run "publisher_and_runtime_grants_are_minimal" {
  command = apply

  variables {
    content_publisher_role_arns = {
      ops-sop               = "arn:aws:iam::123456789012:role/rosa-boundary-dev-publisher-ops-sop"
      managed-notifications = "arn:aws:iam::123456789012:role/rosa-boundary-dev-publisher-managed-notifications"
      rosa-claude-plugins   = "arn:aws:iam::123456789012:role/rosa-boundary-dev-publisher-rosa-claude-plugins"
    }
  }

  assert {
    condition = toset([for policy in values(aws_iam_role_policy.content_publisher) : policy.role]) == toset([
      "rosa-boundary-dev-publisher-ops-sop",
      "rosa-boundary-dev-publisher-managed-notifications",
      "rosa-boundary-dev-publisher-rosa-claude-plugins",
    ])
    error_message = "Each publisher grant must attach to the role named by its supplied ARN; identities stay owned by the account state."
  }

  assert {
    condition = alltrue([
      for key, policy in aws_iam_role_policy.content_publisher : alltrue([
        for statement in jsondecode(policy.policy).Statement :
        statement.Sid != "ListOwnPrefix" || (
          statement.Effect == "Allow" &&
          toset(statement.Action) == toset(["s3:ListBucket"]) &&
          statement.Resource == aws_s3_bucket.content.arn &&
          toset(statement.Condition.StringLike["s3:prefix"]) == toset([
            var.content_prefixes[key], "${var.content_prefixes[key]}*",
          ])
        )
        ]) && length([
        for statement in jsondecode(policy.policy).Statement : statement
        if statement.Sid == "ListOwnPrefix"
      ]) == 1
    ])
    error_message = "Every publisher needs ListObjectsV2 permission on the bucket, restricted to its own sync destination prefix."
  }

  assert {
    condition     = length(aws_s3_bucket_replication_configuration.content) == 0 && length(aws_iam_role_policy.content_replication) == 0
    error_message = "Publisher role ARNs alone must not enable replication."
  }

  assert {
    condition = toset(flatten([
      for statement in jsondecode(aws_iam_role_policy.content_publisher["ops-sop"].policy).Statement :
      flatten([statement.Action]) if statement.Sid == "PublishOwnPrefix"
    ])) == toset(["s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"])
    error_message = "The publisher object grant must be exactly PutObject, DeleteObject and AbortMultipartUpload."
  }

  assert {
    condition = length(setintersection(
      toset(flatten([
        for policy in values(aws_iam_role_policy.content_publisher) : [
          for statement in jsondecode(policy.policy).Statement : flatten([statement.Action])
        ]
      ])),
      toset([
        "s3:GetObject", "s3:PutObjectTagging", "kms:Encrypt", "kms:DescribeKey",
        "s3:ListBucketMultipartUploads", "s3:ListMultipartUploadParts", "s3:*", "kms:*",
      ])
    )) == 0
    error_message = "The publisher grant must not contain an action that no actual upload call path needs, and must contain no wildcard action."
  }

  assert {
    condition = toset(flatten([
      for statement in jsondecode(aws_iam_role_policy.content_publisher["rosa-claude-plugins"].policy).Statement :
      flatten([statement.Action]) if statement.Sid == "UseRegionalS3ManagedKey"
    ])) == toset(["kms:GenerateDataKey", "kms:Decrypt"])
    error_message = "Publisher KMS actions must be exactly GenerateDataKey (PutObject, CreateMultipartUpload) and Decrypt (UploadPart, CompleteMultipartUpload)."
  }

  assert {
    condition = alltrue([
      for key, policy in aws_iam_role_policy.content_publisher : alltrue([
        for statement in jsondecode(policy.policy).Statement :
        statement.Sid != "PublishOwnPrefix" ||
        statement.Resource == "arn:aws:s3:::123456789012-rosa-boundary-dev-us-east-1-content/${var.content_prefixes[key]}*"
      ])
    ])
    error_message = "Each publisher must be scoped to its own prefix only; one publisher must never be able to write another's content."
  }

  assert {
    condition = alltrue([
      for key, policy in aws_iam_role_policy.content_publisher : alltrue([
        for statement in jsondecode(policy.policy).Statement :
        statement.Sid != "UseRegionalS3ManagedKey" || (
          statement.Effect == "Allow" &&
          toset(statement.Action) == toset(["kms:GenerateDataKey", "kms:Decrypt"]) &&
          statement.Resource == "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222" &&
          statement.Condition.StringLike["kms:ViaService"] == "s3.us-east-1.amazonaws.com" &&
          statement.Condition.StringLike["kms:EncryptionContext:aws:s3:arn"] == "${aws_s3_bucket.content.arn}/${var.content_prefixes[key]}*"
        )
      ])
    ])
    error_message = "Publisher KMS statements must target the resolved regional AWS-managed key and be usable only through S3."
  }

  assert {
    condition = toset(flatten([
      for statement in jsondecode(aws_iam_role_policy.task_content.policy).Statement :
      flatten([statement.Action])
    ])) == toset(["s3:ListBucket", "s3:GetObject", "kms:Decrypt"])
    error_message = "The runtime task grant must be read and decrypt only: it downloads content and must never write it."
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.task_content.policy).Statement :
      alltrue([
        for resource in flatten([statement.Resource]) :
        startswith(resource, "arn:aws:s3:::123456789012-rosa-boundary-dev-us-east-1-content") ||
        startswith(resource, "arn:aws:kms:us-east-1:")
      ])
    ])
    error_message = "The runtime grant must reference only this Region's own content bucket and key; it must never reach another Region's replica."
  }

  assert {
    condition     = aws_iam_role_policy.task_content.role == data.aws_iam_role.task.id
    error_message = "The runtime grant must attach to the existing shared task role rather than introducing a sidecar-specific identity."
  }

  assert {
    condition = alltrue([
      for key in keys(var.content_prefixes) :
      !strcontains(jsonencode(aws_iam_role_policy.task_content.policy), "_bootstrap")
    ])
    error_message = "The reserved _bootstrap/ prefix must stay inaccessible to the runtime role."
  }

  assert {
    condition     = !strcontains(jsonencode([for policy in values(aws_iam_role_policy.content_publisher) : policy.policy]), "_bootstrap")
    error_message = "The reserved _bootstrap/ prefix must stay inaccessible to publishers."
  }

  assert {
    condition = toset([for policy in values(aws_iam_role_policy.content_publisher) : policy.name]) == toset([
      "content-publish-ops-sop", "content-publish-managed-notifications", "content-publish-rosa-claude-plugins",
    ]) && aws_iam_role_policy.task_content.name == "s3-content-read"
    error_message = "In the legacy policy Region the inline policy names carry no suffix."
  }
}

run "non_legacy_region_policy_names_carry_the_regional_suffix" {
  command   = apply
  state_key = "west-region"

  variables {
    aws_region           = "us-west-2"
    legacy_policy_region = "us-east-1"
    content_publisher_role_arns = {
      ops-sop = "arn:aws:iam::123456789012:role/rosa-boundary-dev-publisher-ops-sop"
    }
  }

  override_data {
    target = data.aws_region.current
    values = { region = "us-west-2", name = "us-west-2" }
  }
  override_data {
    target = data.aws_kms_alias.content_s3
    values = { target_key_arn = "arn:aws:kms:us-west-2:123456789012:key/33333333-3333-3333-3333-333333333333" }
  }
  override_resource {
    target = aws_s3_bucket.content
    values = {
      arn = "arn:aws:s3:::123456789012-rosa-boundary-dev-us-west-2-content"
      id  = "123456789012-rosa-boundary-dev-us-west-2-content"
    }
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.task_content.policy).Statement :
      statement.Sid != "ReadPublishedContent" || toset(statement.Resource) == toset([
        for prefix in values(var.content_prefixes) : "arn:aws:s3:::123456789012-rosa-boundary-dev-us-west-2-content/${prefix}*"
      ])
      ]) && one([
      for statement in jsondecode(aws_iam_role_policy.task_content.policy).Statement :
      statement.Resource == "arn:aws:kms:us-west-2:123456789012:key/33333333-3333-3333-3333-333333333333" &&
      statement.Condition.StringLike["kms:ViaService"] == "s3.us-west-2.amazonaws.com"
      if statement.Sid == "DecryptPublishedContent"
    ])
    error_message = "The west Region task grant must scope S3 and KMS to west Region resources."
  }

  assert {
    condition = (
      aws_iam_role_policy.content_publisher["ops-sop"].name == "content-publish-ops-sop-us-west-2" &&
      aws_iam_role_policy.task_content.name == "s3-content-read-us-west-2"
    )
    error_message = "Outside the legacy policy Region every inline policy on a shared account-owned role must carry the -<region> suffix, or one Region would overwrite another's policy."
  }
}

run "replication_rules_and_grant" {
  command = apply

  variables {
    content_replication_role_arn = "arn:aws:iam::123456789012:role/rosa-boundary-dev-content-replication-role"
    replication = {
      primary_region = "us-east-1"
      destinations = {
        "us-west-2" = {
          content = {
            bucket_arn       = "arn:aws:s3:::123456789012-rosa-boundary-dev-us-west-2-content"
            kms_key_arn      = "arn:aws:kms:us-west-2:123456789012:key/33333333-3333-3333-3333-333333333333"
            content_prefixes = { ops-sop = "ops-sop/", managed-notifications = "managed-notifications/", rosa-claude-plugins = "rosa-claude-plugins/" }
          }
        }
      }
    }
  }

  assert {
    condition     = length(aws_s3_bucket_replication_configuration.content) == 1
    error_message = "The source Region must own exactly one replication configuration for the content bucket."
  }

  assert {
    condition     = length(aws_s3_bucket_replication_configuration.content[0].rule) == length(var.content_prefixes)
    error_message = "There must be exactly one replication rule per destination and published prefix."
  }

  assert {
    condition = length(distinct([
      for rule in aws_s3_bucket_replication_configuration.content[0].rule : rule.priority
    ])) == length(aws_s3_bucket_replication_configuration.content[0].rule)
    error_message = "Replication rule priorities must be unique; the stride is the prefix count so uniqueness does not depend on the number of prefixes."
  }

  assert {
    condition = toset([
      for rule in aws_s3_bucket_replication_configuration.content[0].rule : rule.priority
    ]) == toset([1, 2, 3])
    error_message = "With one destination and three prefixes the generated priorities must be 1, 2 and 3."
  }

  assert {
    condition = alltrue([
      for rule in aws_s3_bucket_replication_configuration.content[0].rule :
      rule.status == "Enabled" &&
      one(rule.delete_marker_replication).status == "Enabled" &&
      one(one(rule.source_selection_criteria).sse_kms_encrypted_objects).status == "Enabled"
    ])
    error_message = "Every rule must be enabled, replicate delete markers, and opt in to SSE-KMS replication, which S3 requires before it will replicate encrypted objects at all."
  }

  assert {
    condition = alltrue([
      for rule in aws_s3_bucket_replication_configuration.content[0].rule :
      one(rule.filter).prefix != "" && length(one(rule.filter).tag) == 0
    ])
    error_message = "Rule filters must be prefix-only; a tag predicate would make delete-marker replication invalid."
  }

  assert {
    condition = toset([
      for rule in aws_s3_bucket_replication_configuration.content[0].rule : one(rule.filter).prefix
    ]) == toset(values(var.content_prefixes))
    error_message = "The replication rules must cover exactly the published prefixes, and therefore never the reserved _bootstrap/ prefix."
  }

  assert {
    condition = alltrue([
      for rule in aws_s3_bucket_replication_configuration.content[0].rule :
      one(rule.destination).bucket == "arn:aws:s3:::123456789012-rosa-boundary-dev-us-west-2-content" &&
      one(one(rule.destination).encryption_configuration).replica_kms_key_id == "arn:aws:kms:us-west-2:123456789012:key/33333333-3333-3333-3333-333333333333"
    ])
    error_message = "Each rule must target the supplied destination bucket and that Region's own replica key."
  }

  assert {
    condition     = aws_s3_bucket_replication_configuration.content[0].role == var.content_replication_role_arn
    error_message = "Replication must use the dedicated content replication identity, never the audit replication role."
  }

  assert {
    condition = (
      aws_iam_role_policy.content_replication[0].role == "rosa-boundary-dev-content-replication-role" &&
      aws_iam_role_policy.content_replication[0].name == "content-replication"
    )
    error_message = "The replication grant must attach to the account-owned content replication role with the regionally scoped policy name."
  }

  assert {
    condition = toset(flatten([
      for statement in jsondecode(aws_iam_role_policy.content_replication[0].policy).Statement :
      flatten([statement.Action])
      ])) == toset([
      "s3:GetReplicationConfiguration", "s3:ListBucket",
      "s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl",
      "s3:ReplicateObject", "s3:ReplicateDelete",
      "kms:Decrypt", "kms:Encrypt",
    ])
    error_message = "The replication grant must be exactly the minimal AWS-documented SSE-KMS replication set, with no kms:GenerateDataKey: the bucket policy makes plaintext objects impossible."
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.content_replication[0].policy).Statement :
      !startswith(statement.Sid, "EncryptReplicasIn") || (
        statement.Resource == "arn:aws:kms:us-west-2:123456789012:key/33333333-3333-3333-3333-333333333333" &&
        statement.Condition.StringLike["kms:ViaService"] == "s3.us-west-2.amazonaws.com"
      )
    ])
    error_message = "The replica key statement must name the destination Region's key and that Region's own S3 service endpoint."
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.content_replication[0].policy).Statement :
      statement.Sid != "DecryptSourceObjects" ||
      statement.Condition.StringLike["kms:ViaService"] == "s3.us-east-1.amazonaws.com"
    ])
    error_message = "The source key statement must name the source Region's S3 service endpoint."
  }

  assert {
    condition     = output.content_replication_rule_ids == tolist(["replicate-managed-notifications-to-us-west-2", "replicate-ops-sop-to-us-west-2", "replicate-rosa-claude-plugins-to-us-west-2"])
    error_message = "The exported rule IDs must name every rule this source Region owns."
  }

  assert {
    condition     = length(regexall("terraform_remote_state", file("${path.module}/s3-content.tf"))) == 0 && length(regexall("terraform_remote_state", file("${path.module}/iam-content.tf"))) == 0
    error_message = "Destination identifiers must arrive as plain inputs; reading another Region's state would create a cross-state cycle."
  }
}

run "two_destinations_keep_priorities_unique_across_regions" {
  command = apply

  variables {
    content_replication_role_arn = "arn:aws:iam::123456789012:role/rosa-boundary-dev-content-replication-role"
    replication = {
      primary_region = "us-east-1"
      destinations = {
        "us-west-2" = {
          content = {
            bucket_arn       = "arn:aws:s3:::123456789012-rosa-boundary-dev-us-west-2-content"
            kms_key_arn      = "arn:aws:kms:us-west-2:123456789012:key/33333333-3333-3333-3333-333333333333"
            content_prefixes = { ops-sop = "ops-sop/", managed-notifications = "managed-notifications/", rosa-claude-plugins = "rosa-claude-plugins/" }
          }
        }
        "eu-west-1" = {
          content = {
            bucket_arn       = "arn:aws:s3:::123456789012-rosa-boundary-dev-eu-west-1-content"
            kms_key_arn      = "arn:aws:kms:eu-west-1:123456789012:key/44444444-4444-4444-4444-444444444444"
            content_prefixes = { ops-sop = "ops-sop/", managed-notifications = "managed-notifications/", rosa-claude-plugins = "rosa-claude-plugins/" }
          }
        }
      }
    }
  }

  assert {
    condition = toset([
      for rule in aws_s3_bucket_replication_configuration.content[0].rule : rule.priority
    ]) == toset([1, 2, 3, 4, 5, 6])
    error_message = "A second destination must continue the priority sequence using the prefix-count stride rather than colliding with the first."
  }
}

run "rejects_empty_content_prefixes" {
  command = plan

  variables {
    content_prefixes = {}
  }

  expect_failures = [var.content_prefixes]
}

run "rejects_a_prefix_that_is_not_a_directory_prefix" {
  command = plan

  variables {
    content_prefixes = { ops-sop = "ops-sop" }
  }

  expect_failures = [var.content_prefixes]
}

run "rejects_overlapping_prefixes" {
  command = plan

  variables {
    content_prefixes = { ops-sop = "ops-sop/", nested = "ops-sop/nested/" }
  }

  expect_failures = [var.content_prefixes]
}

run "rejects_a_duplicate_prefix" {
  command = plan

  variables {
    content_prefixes = { ops-sop = "shared/", rosa-claude-plugins = "shared/" }
  }

  expect_failures = [var.content_prefixes]
}

run "rejects_publishing_into_the_reserved_bootstrap_prefix" {
  command = plan

  variables {
    content_prefixes = { ops-sop = "_bootstrap/content/" }
  }

  expect_failures = [var.content_prefixes]
}

run "rejects_a_replica_key_outside_its_destination_region" {
  command = plan

  variables {
    replication = {
      primary_region = "us-east-1"
      destinations = {
        "us-west-2" = {
          content = {
            bucket_arn       = "arn:aws:s3:::123456789012-rosa-boundary-dev-us-west-2-content"
            kms_key_arn      = "arn:aws:kms:us-east-1:123456789012:key/33333333-3333-3333-3333-333333333333"
            content_prefixes = { ops-sop = "ops-sop/", managed-notifications = "managed-notifications/", rosa-claude-plugins = "rosa-claude-plugins/" }
          }
        }
      }
    }
  }

  expect_failures = [var.replication]
}

run "rejects_replicating_to_the_source_region_itself" {
  command = plan

  variables {
    content_replication_role_arn = "arn:aws:iam::123456789012:role/rosa-boundary-dev-content-replication-role"
    replication = {
      primary_region = "us-east-1"
      destinations = {
        "us-east-1" = {
          content = {
            bucket_arn       = "arn:aws:s3:::123456789012-rosa-boundary-dev-us-east-1-content"
            kms_key_arn      = "arn:aws:kms:us-east-1:123456789012:key/33333333-3333-3333-3333-333333333333"
            content_prefixes = { ops-sop = "ops-sop/", managed-notifications = "managed-notifications/", rosa-claude-plugins = "rosa-claude-plugins/" }
          }
        }
      }
    }
  }

  expect_failures = [var.replication]
}

run "rejects_a_destination_bucket_outside_the_naming_convention" {
  command = plan

  variables {
    content_replication_role_arn = "arn:aws:iam::123456789012:role/rosa-boundary-dev-content-replication-role"
    replication = {
      primary_region = "us-east-1"
      destinations = {
        "us-west-2" = {
          content = {
            bucket_arn       = "arn:aws:s3:::someone-elses-bucket"
            kms_key_arn      = "arn:aws:kms:us-west-2:123456789012:key/33333333-3333-3333-3333-333333333333"
            content_prefixes = { ops-sop = "ops-sop/", managed-notifications = "managed-notifications/", rosa-claude-plugins = "rosa-claude-plugins/" }
          }
        }
      }
    }
  }

  expect_failures = [aws_s3_bucket_replication_configuration.content]
}

run "rejects_a_publisher_key_with_no_matching_prefix" {
  command = plan

  variables {
    content_publisher_role_arns = { unknown = "arn:aws:iam::123456789012:role/rosa-boundary-dev-publisher-unknown" }
  }

  expect_failures = [aws_iam_role_policy.content_publisher]
}

run "rejects_a_publisher_role_from_another_account" {
  command = plan

  variables {
    content_publisher_role_arns = { ops-sop = "arn:aws:iam::210987654321:role/rosa-boundary-dev-publisher-ops-sop" }
  }

  expect_failures = [aws_iam_role_policy.content_publisher]
}

# Consumer contract: local directories derive from prefix values, not source
# keys. Use a custom key so matching defaults cannot hide a mapping regression.
run "local_directory_derives_from_the_prefix_value_not_the_key" {
  command = apply

  variables {
    content_prefixes = { handbook = "ops-sop/v2/" }
    content_publisher_role_arns = {
      handbook = "arn:aws:iam::123456789012:role/rosa-boundary-dev-publisher-handbook"
    }
  }

  assert {
    condition = toset([
      for key, prefix in output.content_prefixes : trimsuffix(prefix, "/")
    ]) == toset(["ops-sop/v2"])
    error_message = "The exported custom prefix must map to ops-sop/v2, not the publisher key handbook."
  }

  assert {
    condition = (length([
      for key, prefix in output.content_prefixes : key if trimsuffix(prefix, "/") != key
      ]) == 1 &&
      aws_iam_role_policy.content_publisher["handbook"].role == "rosa-boundary-dev-publisher-handbook" &&
      one([
        for statement in jsondecode(aws_iam_role_policy.content_publisher["handbook"].policy).Statement :
        statement.Resource if statement.Sid == "PublishOwnPrefix"
    ]) == "${output.content_bucket_arn}/ops-sop/v2/*")
    error_message = "The custom key must select its identity while the prefix value selects the object grant and consumer path."
  }
}

# A '?' is an IAM single-character wildcard in both Resource ARNs and
# StringLike conditions, so '?bootstrap/' would render "<bucket>/?bootstrap/*"
# and match the reserved "_bootstrap/key-init".
run "rejects_a_single_character_wildcard_in_a_prefix" {
  command = plan

  variables {
    content_prefixes = { ops-sop = "?bootstrap/" }
  }

  expect_failures = [var.content_prefixes]
}

run "rejects_a_wildcard_that_would_span_other_prefixes" {
  command = plan

  variables {
    content_prefixes = { ops-sop = "ops-so?/", rosa-claude-plugins = "rosa-claude-plugins/" }
  }

  expect_failures = [var.content_prefixes]
}

run "rejects_iam_policy_variable_syntax_in_a_prefix" {
  command = plan

  variables {
    content_prefixes = { ops-sop = "$${aws:username}/" }
  }

  expect_failures = [var.content_prefixes]
}

# Whitespace and ':' would also break the space-delimited KEY:PREFIX handoff a
# content consumer parses.
run "rejects_whitespace_in_a_prefix" {
  command = plan

  variables {
    content_prefixes = { ops-sop = "ops sop/" }
  }

  expect_failures = [var.content_prefixes]
}

run "rejects_a_colon_in_a_prefix" {
  command = plan

  variables {
    content_prefixes = { ops-sop = "ops:sop/" }
  }

  expect_failures = [var.content_prefixes]
}

run "rejects_a_prefix_that_is_an_ancestor_of_the_reserved_prefix" {
  command = plan

  variables {
    content_prefixes = { ops-sop = "_/" }
  }

  expect_failures = [var.content_prefixes]
}

run "accepts_a_configurable_nested_prefix" {
  command = apply

  variables {
    content_prefixes = { ops-sop = "ops-sop/v2/", rosa-claude-plugins = "rosa-claude-plugins/" }
  }

  assert {
    condition     = output.content_prefixes["ops-sop"] == "ops-sop/v2/"
    error_message = "A safe nested path must stay configurable; the grammar hardening must not reduce this to single-segment prefixes."
  }
}

# PutRolePolicy takes a role name, not a path. A path-qualified ARN whose
# basename names a real role would attach the policy to that role, whose ARN is
# not the one supplied, so the input is rejected instead of normalised.
run "rejects_a_path_qualified_publisher_role_arn" {
  command = plan

  variables {
    content_publisher_role_arns = { ops-sop = "arn:aws:iam::123456789012:role/some/path/rosa-boundary-dev-publisher-ops-sop" }
  }

  expect_failures = [var.content_publisher_role_arns]
}

run "rejects_a_path_qualified_replication_role_arn" {
  command = plan

  variables {
    content_replication_role_arn = "arn:aws:iam::123456789012:role/some/path/rosa-boundary-dev-content-replication-role"
  }

  expect_failures = [var.content_replication_role_arn]
}

run "rejects_publishing_grants_on_the_task_role" {
  command = plan
  variables {
    content_publisher_role_arns = { ops-sop = "arn:aws:iam::123456789012:role/rosa-boundary-dev-task-role" }
  }
  expect_failures = [aws_iam_role_policy.content_publisher]
}

run "rejects_a_destination_with_a_different_prefix_map" {
  command = plan

  variables {
    content_replication_role_arn = "arn:aws:iam::123456789012:role/rosa-boundary-dev-content-replication-role"
    replication = {
      primary_region = "us-east-1"
      destinations = {
        "us-west-2" = {
          content = {
            bucket_arn       = "arn:aws:s3:::123456789012-rosa-boundary-dev-us-west-2-content"
            kms_key_arn      = "arn:aws:kms:us-west-2:123456789012:key/33333333-3333-3333-3333-333333333333"
            content_prefixes = { ops-sop = "ops-sop/v2/", managed-notifications = "managed-notifications/", rosa-claude-plugins = "rosa-claude-plugins/" }
          }
        }
      }
    }
  }

  expect_failures = [aws_s3_bucket_replication_configuration.content]
}

run "rejects_replication_grants_on_the_audit_role" {
  command = plan

  variables {
    content_replication_role_arn = "arn:aws:iam::123456789012:role/rosa-boundary-dev-s3-replication-role"
    replication = {
      primary_region = "us-east-1"
      destinations = {
        "us-west-2" = {
          content = {
            bucket_arn       = "arn:aws:s3:::123456789012-rosa-boundary-dev-us-west-2-content"
            kms_key_arn      = "arn:aws:kms:us-west-2:123456789012:key/33333333-3333-3333-3333-333333333333"
            content_prefixes = { ops-sop = "ops-sop/", managed-notifications = "managed-notifications/", rosa-claude-plugins = "rosa-claude-plugins/" }
          }
        }
      }
    }
  }

  expect_failures = [aws_iam_role_policy.content_replication]
}

run "replica_accepts_shared_populated_topology_without_source_grants" {
  command = apply
  variables {
    aws_region                   = "us-west-2"
    content_replication_role_arn = "arn:aws:iam::123456789012:role/rosa-boundary-dev-content-replication-role"
    replication = {
      primary_region = "us-east-1"
      destinations = {
        "us-west-2" = {
          content = {
            bucket_arn       = "arn:aws:s3:::123456789012-rosa-boundary-dev-us-west-2-content"
            kms_key_arn      = "arn:aws:kms:us-west-2:123456789012:key/33333333-3333-3333-3333-333333333333"
            content_prefixes = { ops-sop = "ops-sop/", managed-notifications = "managed-notifications/", rosa-claude-plugins = "rosa-claude-plugins/" }
          }
        }
      }
    }
  }

  assert {
    condition = (
      length(aws_s3_bucket_replication_configuration.content) == 0 &&
      length(aws_iam_role_policy.content_replication) == 0 &&
      length(output.content_replication_rule_ids) == 0
    )
    error_message = "Only the primary workspace may own source replication rules and grants."
  }
}

run "unpopulated_destinations_do_not_activate_content" {
  command = apply
  variables {
    replication = {
      primary_region = "us-east-1"
      destinations   = { us-west-2 = {}, eu-west-1 = { content = null } }
    }
  }
  assert {
    condition = (
      length(aws_s3_bucket_replication_configuration.content) == 0 &&
      length(aws_iam_role_policy.content_replication) == 0 &&
      length(output.content_replication_rule_ids) == 0
    )
    error_message = "Only the primary workspace may own source replication rules and grants."
  }
}

run "rejects_publisher_handoff_in_a_replica" {
  command = plan
  variables {
    replication                 = { primary_region = "us-west-2", destinations = {} }
    content_publisher_role_arns = { ops-sop = "arn:aws:iam::123456789012:role/rosa-boundary-dev-publisher-ops-sop" }
  }
  expect_failures = [aws_iam_role_policy.content_publisher]
}

run "rejects_invalid_primary_region" {
  command = plan
  variables {
    replication = { primary_region = "invalid", destinations = {} }
  }
  expect_failures = [var.replication]
}

run "rejects_invalid_region_key_even_without_content" {
  command = plan
  variables {
    replication = { primary_region = "us-east-1", destinations = { invalid = {} } }
  }
  expect_failures = [var.replication]
}

run "rejects_source_destination_even_without_content" {
  command = plan
  variables {
    replication = { primary_region = "us-east-1", destinations = { us-east-1 = {} } }
  }
  expect_failures = [var.replication]
}

run "replica_validates_bucket_metadata_too" {
  command = plan
  variables {
    aws_region                   = "us-west-2"
    content_replication_role_arn = "arn:aws:iam::123456789012:role/rosa-boundary-dev-content-replication-role"
    replication = {
      primary_region = "us-east-1"
      destinations = {
        "us-west-2" = {
          content = {
            bucket_arn       = "not-a-bucket-arn"
            kms_key_arn      = "arn:aws:kms:us-west-2:123456789012:key/33333333-3333-3333-3333-333333333333"
            content_prefixes = { ops-sop = "ops-sop/", managed-notifications = "managed-notifications/", rosa-claude-plugins = "rosa-claude-plugins/" }
          }
        }
      }
    }
  }

  expect_failures = [var.replication]
}

run "replica_validates_key_region_too" {
  command = plan
  variables {
    aws_region                   = "us-west-2"
    content_replication_role_arn = "arn:aws:iam::123456789012:role/rosa-boundary-dev-content-replication-role"
    replication = {
      primary_region = "us-east-1"
      destinations = {
        "us-west-2" = {
          content = {
            bucket_arn       = "arn:aws:s3:::123456789012-rosa-boundary-dev-us-west-2-content"
            kms_key_arn      = "arn:aws:kms:us-east-1:123456789012:key/33333333-3333-3333-3333-333333333333"
            content_prefixes = { ops-sop = "ops-sop/", managed-notifications = "managed-notifications/", rosa-claude-plugins = "rosa-claude-plugins/" }
          }
        }
      }
    }
  }

  expect_failures = [var.replication]
}

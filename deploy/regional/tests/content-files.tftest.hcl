# Mocked S3 Files contracts: rendered configuration, not live AWS enforcement.

mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/content-files-service" }
  }
  mock_resource "aws_s3files_file_system" {
    defaults = { arn = "arn:aws:s3files:us-east-1:123456789012:file-system/fs-0123456789abcdef0" }
  }
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

# Keep content and audit identities distinct under mocking.
override_resource {
  target = aws_s3_bucket.content
  values = {
    arn = "arn:aws:s3:::123456789012-rosa-boundary-dev-us-east-1-content"
    id  = "123456789012-rosa-boundary-dev-us-east-1-content"
  }
}

variables {
  aws_account_id       = "123456789012"
  aws_region           = "us-east-1"
  legacy_policy_region = "us-east-1"
  container_image      = "example.com/rosa-boundary:test"
  vpc_id               = "vpc-00000000000000000"
  subnet_ids           = ["subnet-00000000000000000", "subnet-11111111111111111"]
  keycloak_issuer_url  = "https://auth.example.com/auth/realms/EmployeeIDP"
  keycloak_thumbprint  = "0000000000000000000000000000000000000000"
  required_groups      = ["ai-sd-sre"]
  enable_kube_proxy    = false
}

# Real partition so interpolated IAM policy ARNs are valid under mocking.
override_data {
  target = data.aws_partition.current
  values = {
    partition = "aws"
    id        = "aws"
  }
}

# Two subnets in the same VPC, one per AZ (satisfies the Bedrock endpoint
# preconditions: same vpc_id, one distinct AZ per subnet).
override_data {
  target = data.aws_subnet.bedrock_runtime["subnet-00000000000000000"]
  values = {
    vpc_id               = "vpc-00000000000000000"
    availability_zone_id = "use1-az1"
  }
}
override_data {
  target = data.aws_subnet.bedrock_runtime["subnet-11111111111111111"]
  values = {
    vpc_id               = "vpc-00000000000000000"
    availability_zone_id = "use1-az2"
  }
}

# Each subnet's route table has a default route (satisfies subnet_outbound_routing).
override_data {
  target = data.aws_route_table.subnet[0]
  values = {
    routes = [{ cidr_block = "0.0.0.0/0", gateway_id = "igw-0", nat_gateway_id = "" }]
  }
}
override_data {
  target = data.aws_route_table.subnet[1]
  values = {
    routes = [{ cidr_block = "0.0.0.0/0", gateway_id = "igw-0", nat_gateway_id = "" }]
  }
}

override_data {
  target = data.aws_region.current
  values = { region = "us-east-1" }
}


run "default_files_and_mounts" {
  command = apply

  # Distinct identities catch accidental cross-prefix volume wiring.
  override_resource {
    target = aws_s3files_file_system.content["managed-notifications"]
    values = {
      arn = "arn:aws:s3files:us-east-1:123456789012:file-system/fs-0123456789abcdef0"
      id  = "fs-0123456789abcdef0"
    }
  }

  override_resource {
    target = aws_s3files_file_system.content["ops-sop"]
    values = {
      arn = "arn:aws:s3files:us-east-1:123456789012:file-system/fs-0123456789abcdef1"
      id  = "fs-0123456789abcdef1"
    }
  }

  override_resource {
    target = aws_s3files_file_system.content["rosa-claude-plugins"]
    values = {
      arn = "arn:aws:s3files:us-east-1:123456789012:file-system/fs-0123456789abcdef2"
      id  = "fs-0123456789abcdef2"
    }
  }

  assert {
    condition = (
      toset(keys(aws_s3files_file_system.content)) == toset(keys(var.content_prefixes)) &&
      toset(keys(aws_s3files_file_system_policy.content)) == toset(keys(var.content_prefixes)) &&
      alltrue([for key, fs in aws_s3files_file_system.content :
        fs.bucket == aws_s3_bucket.content.arn &&
        fs.prefix == var.content_prefixes[key] &&
        fs.role_arn == aws_iam_role.content_files.arn &&
        aws_s3files_file_system_policy.content[key].file_system_id == fs.id
      ])
    )
    error_message = "Each configured prefix must have its own S3 Files filesystem and policy, backed by the content bucket and service role."
  }
  assert {
    condition = (
      length(aws_ecs_task_definition.rosa_boundary.volume) == length(var.content_prefixes) + 3 &&
      alltrue([for key, prefix in var.content_prefixes :
        one([for v in aws_ecs_task_definition.rosa_boundary.volume : v if v.name == "content-${key}"]).s3files_volume_configuration[0].file_system_arn == aws_s3files_file_system.content[key].arn
      ]) &&
      alltrue([for key, prefix in var.content_prefixes :
        contains(one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "rosa-boundary"]).mountPoints,
        { sourceVolume = "content-${key}", containerPath = format("/opt/rosa-content/%s", trimsuffix(prefix, "/")), readOnly = true })
      ])
    )
    error_message = "Content volumes must use S3 Files ARNs and read-only mounts at prefix-derived paths, not ephemeral sync storage."
  }
  assert {
    condition = (
      length(jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions)) == 1 &&
      one(jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions)).name == "rosa-boundary" &&
      one(jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions)).cpu == var.container_cpu &&
      one(jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions)).dependsOn == []
    )
    error_message = "Without proxy there must be only the workload, with the entire CPU budget and no sync dependency."
  }
  assert {
    condition = (
      one([for v in aws_ecs_task_definition.rosa_boundary.volume : v if v.name == "sre-home"]).efs_volume_configuration[0].transit_encryption == "ENABLED" &&
      alltrue([for mount in [
        { sourceVolume = "sre-home", containerPath = "/home/sre", readOnly = false },
        { sourceVolume = "ocm-config", containerPath = "/home/sre/.config/ocm", readOnly = false },
        { sourceVolume = "kubeconfig", containerPath = "/home/sre/.kube", readOnly = false }
      ] : contains(one(jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions)).mountPoints, mount)]) &&
      length(one(jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions)).mountPoints) == length(var.content_prefixes) + 3
    )
    error_message = "Content migration must preserve the EFS home and writable task-scoped credential overlays."
  }
}

run "service_role_and_read_only_clients" {
  command = apply
  assert {
    condition = (
      aws_iam_role_policy.content_files.role == aws_iam_role.content_files.id &&
      aws_iam_role_policy.task_content_files.role == data.aws_iam_role.task.id &&
      one(jsondecode(aws_iam_role.content_files.assume_role_policy).Statement).Principal.Service == "elasticfilesystem.amazonaws.com" &&
      one(jsondecode(aws_iam_role.content_files.assume_role_policy).Statement).Action == "sts:AssumeRole" &&
      one(jsondecode(aws_iam_role.content_files.assume_role_policy).Statement).Condition.StringEquals["aws:SourceAccount"] == "123456789012" &&
      one(jsondecode(aws_iam_role.content_files.assume_role_policy).Statement).Condition.ArnLike["aws:SourceArn"] == "arn:aws:s3files:us-east-1:123456789012:file-system/*"
    )
    error_message = "Only the constrained AWS service may assume the separate synchronization role; clients use the existing task role."
  }
  assert {
    condition = (
      toset(flatten([for s in jsondecode(aws_iam_role_policy.task_content_files.policy).Statement : s.Action if s.Effect == "Allow"])) == toset(["s3files:ClientMount"]) &&
      alltrue([for s in jsondecode(aws_iam_role_policy.task_content_files.policy).Statement :
        toset(flatten([s.Resource])) == toset([for fs in aws_s3files_file_system.content : fs.arn]) if contains(flatten([s.Action]), "s3files:ClientMount")
      ]) &&
      length([for s in jsondecode(aws_iam_role_policy.task_content_files.policy).Statement : s if
        s.Effect == "Deny" &&
        toset(flatten([s.Action])) == toset(["s3files:ClientWrite", "s3files:ClientRootAccess"]) &&
        toset(flatten([s.Resource])) == toset([for fs in aws_s3files_file_system.content : fs.arn])
      ]) == 1
    )
    error_message = "Task clients may mount only configured filesystems and must explicitly be denied writes and root access."
  }
  assert {
    condition = length([for s in jsondecode(aws_iam_role_policy.task_content_files.policy).Statement : s if
      s.Effect == "Deny" &&
      toset(flatten([s.Action])) == toset(["s3:Put*", "s3:Delete*", "s3:AbortMultipartUpload", "s3:RestoreObject", "s3:Replicate*"]) &&
      toset(flatten([s.Resource])) == toset([aws_s3_bucket.content.arn, "${aws_s3_bucket.content.arn}/*"])
    ]) == 1
    error_message = "An explicit whole-content-bucket S3 mutation deny must prevent clients bypassing the read-only mount."
  }
  assert {
    condition = alltrue([for key, policy in aws_s3files_file_system_policy.content :
      length([for s in jsondecode(policy.policy).Statement : s if
        s.Effect == "Deny" && s.Principal == "*" &&
        toset(flatten([s.Action])) == toset(["s3files:ClientWrite", "s3files:ClientRootAccess"])
      ]) == 1
    ])
    error_message = "Every filesystem must deny writes and root access to all clients, independently of task identity permissions."
  }
  assert {
    condition = (
      aws_s3_bucket_notification.content.eventbridge &&
      one([for s in jsondecode(aws_iam_role_policy.content_files.policy).Statement : s if s.Sid == "SynchronizePublishedContent"]).Resource == local.content_object_arns &&
      one([for s in jsondecode(aws_iam_role_policy.content_files.policy).Statement : s if s.Sid == "UseContentKeyThroughS3"]).Resource == data.aws_kms_alias.content_s3.target_key_arn &&
      one([for s in jsondecode(aws_iam_role_policy.content_files.policy).Statement : s if s.Sid == "UseContentKeyThroughS3"]).Condition.StringLike["kms:EncryptionContext:aws:s3:arn"] == local.content_object_arns
    )
    error_message = "Service synchronization must use content object prefixes and the regional S3 key, with EventBridge enabled."
  }
}


run "filesystem_principal_tls_and_network_boundary" {
  command = apply
  assert {
    condition = alltrue([for key, policy in aws_s3files_file_system_policy.content :
      alltrue([for s in jsondecode(policy.policy).Statement : s.Resource == aws_s3files_file_system.content[key].arn]) &&
      length([for s in jsondecode(policy.policy).Statement : s if
        s.Sid == "AllowTaskMount" && s.Effect == "Allow" &&
        s.Principal == { AWS = data.aws_iam_role.task.arn } &&
        toset(flatten([s.Action])) == toset(["s3files:ClientMount"])
      ]) == 1 &&
      length([for s in jsondecode(policy.policy).Statement : s if
        s.Sid == "DenyOtherPrincipals" && s.Effect == "Deny" && s.Principal == "*" &&
        toset(flatten([s.Action])) == toset(["s3files:ClientMount"]) &&
        try(s.Condition.ArnNotEquals["aws:PrincipalArn"], "") == data.aws_iam_role.task.arn
      ]) == 1 &&
      length([for s in jsondecode(policy.policy).Statement : s if
        s.Sid == "DenyInsecureTransport" && s.Effect == "Deny" && s.Principal == "*" &&
        toset(flatten([s.Action])) == toset(["s3files:ClientMount", "s3files:ClientWrite", "s3files:ClientRootAccess"]) &&
        try(s.Condition.Bool["aws:SecureTransport"], "") == "false"
      ]) == 1
    ])
    error_message = "Every filesystem must allow only task-role mounts, explicitly deny other principals, and deny insecure transport."
  }
  assert {
    condition = (
      aws_security_group.content_files.vpc_id == var.vpc_id &&
      aws_vpc_security_group_ingress_rule.content_files_from_tasks.security_group_id == aws_security_group.content_files.id &&
      aws_vpc_security_group_ingress_rule.content_files_from_tasks.referenced_security_group_id == aws_security_group.fargate.id &&
      aws_vpc_security_group_ingress_rule.content_files_from_tasks.ip_protocol == "tcp" &&
      aws_vpc_security_group_ingress_rule.content_files_from_tasks.from_port == 2049 &&
      aws_vpc_security_group_ingress_rule.content_files_from_tasks.to_port == 2049 &&
      aws_vpc_security_group_ingress_rule.content_files_from_tasks.cidr_ipv4 == null &&
      aws_vpc_security_group_ingress_rule.content_files_from_tasks.cidr_ipv6 == null &&
      length(aws_s3files_mount_target.content) == length(var.content_prefixes) * 2 &&
      alltrue([for key, target in aws_s3files_mount_target.content :
        target.file_system_id == aws_s3files_file_system.content[split("/", key)[0]].id &&
        contains(var.subnet_ids, target.subnet_id) &&
        toset(target.security_groups) == toset([aws_security_group.content_files.id])
      ])
    )
    error_message = "Each prefix needs mount targets in the selected AZs protected by TCP 2049 from only the Fargate task security group."
  }
}

run "custom_nested_prefix_and_proxy" {
  command = apply
  variables {
    enable_kube_proxy          = true
    content_prefixes           = { publisher = "custom/nested/" }
    task_ephemeral_storage_gib = 25
  }
  assert {
    condition = (
      length(aws_s3files_file_system.content) == 1 &&
      aws_s3files_file_system.content["publisher"].prefix == "custom/nested/" &&
      length(aws_ecs_task_definition.rosa_boundary.volume) == 5 &&
      one([for v in aws_ecs_task_definition.rosa_boundary.volume : v if v.name == "content-publisher"]).s3files_volume_configuration[0].file_system_arn == aws_s3files_file_system.content["publisher"].arn &&
      contains(one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "rosa-boundary"]).mountPoints,
      { sourceVolume = "content-publisher", containerPath = "/opt/rosa-content/custom/nested", readOnly = true }) &&
      aws_ecs_task_definition.rosa_boundary.ephemeral_storage[0].size_in_gib == 25
    )
    error_message = "Map keys select volume names, nested prefix values select mount paths, and ephemeral storage remains independently configurable."
  }
  assert {
    condition = (
      toset([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c.name]) == toset(["rosa-boundary", "kube-proxy"]) &&
      sum([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c.cpu]) == var.container_cpu &&
      one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "rosa-boundary"]).cpu == var.container_cpu - 2 &&
      one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "kube-proxy"]).cpu == 2 &&
      one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "rosa-boundary"]).dependsOn == [{ containerName = "kube-proxy", condition = "HEALTHY" }] &&
      one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "kube-proxy"]).mountPoints == [{ sourceVolume = "proxy-tmp", containerPath = "/tmp", readOnly = false }]
    )
    error_message = "Only proxy CPU and its health dependency may reduce the main budget; proxy must not gain content or home mounts."
  }
}

run "invalid_task_ephemeral_storage_gib" {
  command = plan
  variables { task_ephemeral_storage_gib = 20 }
  expect_failures = [var.task_ephemeral_storage_gib]
}

# Mocked ECS content contracts: no AWS calls or real task launches.

mock_provider "aws" {
  override_during = plan
  mock_data "aws_kms_alias" {
    defaults = { target_key_arn = "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::boundary-test-audit" }
  }

  # IAM is now read via data sources, so supply valid ARNs at plan time.
  mock_data "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/rosa-boundary-test" }
  }
  mock_data "aws_iam_openid_connect_provider" {
    defaults = { arn = "arn:aws:iam::123456789012:oidc-provider/auth.example.com/auth/realms/EmployeeIDP" }
  }
}

# Keep content and audit identities distinct under mocking.
override_resource {
  override_during = plan
  target          = aws_s3_bucket.content
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
  override_during = plan
  target          = data.aws_partition.current
  values = {
    partition = "aws"
    id        = "aws"
  }
}

# Two subnets in the same VPC, one per AZ (satisfies the Bedrock endpoint
# preconditions: same vpc_id, one distinct AZ per subnet).
override_data {
  override_during = plan
  target          = data.aws_subnet.bedrock_runtime["subnet-00000000000000000"]
  values = {
    vpc_id               = "vpc-00000000000000000"
    availability_zone_id = "use1-az1"
  }
}
override_data {
  override_during = plan
  target          = data.aws_subnet.bedrock_runtime["subnet-11111111111111111"]
  values = {
    vpc_id               = "vpc-00000000000000000"
    availability_zone_id = "use1-az2"
  }
}

# Each subnet's route table has a default route (satisfies subnet_outbound_routing).
override_data {
  override_during = plan
  target          = data.aws_route_table.subnet[0]
  values = {
    routes = [{ cidr_block = "0.0.0.0/0", gateway_id = "igw-0", nat_gateway_id = "" }]
  }
}
override_data {
  override_during = plan
  target          = data.aws_route_table.subnet[1]
  values = {
    routes = [{ cidr_block = "0.0.0.0/0", gateway_id = "igw-0", nat_gateway_id = "" }]
  }
}

override_data {
  override_during = plan
  target          = data.aws_region.current
  values          = { region = "us-east-1" }
}

run "sidecar_contract" {
  command = plan
  assert {
    condition     = alltrue([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c.image == var.container_image])
    error_message = "All containers must reuse the task image."
  }
  assert {
    condition     = one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "rosa-boundary"]).cpu == var.container_cpu - var.content_sync_cpu
    error_message = "Without the proxy, the main workload must receive all CPU shares not reserved for sync."
  }
  assert {
    condition     = one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "content-sync"]).entryPoint == ["/bin/bash", "-c", join("\n", [file("./content-sync.sh"), "main"])]
    error_message = "Tested script must be embedded verbatim, with explicit main invocation."
  }
  assert {
    condition     = one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "content-sync"]).essential == false && one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "content-sync"]).mountPoints == [{ sourceVolume = "content", containerPath = "/opt/rosa-content", readOnly = false }]
    error_message = "Nonessential sync may mount only task content, never home or credentials."
  }
  assert {
    condition     = one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "rosa-boundary"]).dependsOn == [] && contains(one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "rosa-boundary"]).mountPoints, { sourceVolume = "content", containerPath = "/opt/rosa-content", readOnly = true })
    error_message = "Main must not wait for content and must mount it read-only."
  }
  assert {
    condition     = one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "content-sync"]).restartPolicy == { enabled = true, ignoredExitCodes = [0], restartAttemptPeriod = 60 }
    error_message = "Use supported restart policy, excluding graceful shutdown."
  }
}
run "proxy_preserved" {
  command = plan
  variables { enable_kube_proxy = true }
  assert {
    condition     = one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "rosa-boundary"]).dependsOn == [{ containerName = "kube-proxy", condition = "HEALTHY" }]
    error_message = "Only the existing proxy health dependency is permitted."
  }
}
run "cpu_budget_preserves_interactive_workload" {
  command = plan
  variables { enable_kube_proxy = true }
  assert {
    condition = (
      sum([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c.cpu]) == var.container_cpu &&
      one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "rosa-boundary"]).cpu == var.container_cpu - var.content_sync_cpu - 2 &&
      one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "kube-proxy"]).cpu == 2
    )
    error_message = "CPU shares must favor the interactive workload and fit the total task budget."
  }
}
run "invalid_content_sync_cpu_leaves_no_session_budget" {
  command = plan
  variables {
    container_cpu    = 256
    content_sync_cpu = 253
  }
  expect_failures = [var.content_sync_cpu]
}
run "invalid_content_sync_interval" {
  command = plan
  variables { content_sync_interval = 0 }
  expect_failures = [var.content_sync_interval]
}
run "invalid_content_sync_backoff" {
  command = plan
  variables { content_sync_backoff = 61 }
  expect_failures = [var.content_sync_backoff]
}
run "invalid_content_sync_timeout" {
  command = plan
  variables { content_sync_timeout = 0 }
  expect_failures = [var.content_sync_timeout]
}
run "invalid_content_sync_cpu" {
  command = plan
  variables { content_sync_cpu = 257 }
  expect_failures = [var.content_sync_cpu]
}
run "invalid_content_sync_memory" {
  command = plan
  variables { content_sync_memory = 513 }
  expect_failures = [var.content_sync_memory]
}
run "invalid_task_ephemeral_storage_gib" {
  command = plan
  variables { task_ephemeral_storage_gib = 20 }
  expect_failures = [var.task_ephemeral_storage_gib]
}

run "custom_prefix_values_and_budgets" {
  command = plan
  variables {
    content_prefixes           = { publisher = "custom/nested/" }
    content_sync_cpu           = 32
    content_sync_memory        = 96
    task_ephemeral_storage_gib = 25
  }
  assert {
    condition     = contains(one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "content-sync"]).environment, { name = "CONTENT_PREFIXES", value = "custom/nested/" })
    error_message = "Only prefix values determine the runtime paths."
  }
  assert {
    condition     = one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "content-sync"]).cpu == 32 && one([for c in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : c if c.name == "content-sync"]).memory == 96 && aws_ecs_task_definition.rosa_boundary.ephemeral_storage[0].size_in_gib == 25
    error_message = "Resource budgets must reach the task definition."
  }
  assert {
    condition     = length([for v in aws_ecs_task_definition.rosa_boundary.volume : v if v.name == "content" && length(v.efs_volume_configuration) == 0 && (v.host_path == null || v.host_path == "")]) == 1
    error_message = "Content must be task-scoped ephemeral storage, not EFS or a host path."
  }
}

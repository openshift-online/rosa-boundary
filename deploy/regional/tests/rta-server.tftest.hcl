# RTA_SERVER is an optional main-container default, not a proxy setting.
# These mocked plans verify rendered configuration and input validation only;
# they do not contact AWS or prove runtime connectivity or authentication.

mock_provider "aws" {
  mock_data "aws_kms_alias" {
    defaults = { target_key_arn = "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::boundary-test-audit" }
  }
  mock_data "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/rosa-boundary-test" }
  }
  mock_data "aws_iam_openid_connect_provider" {
    defaults = { arn = "arn:aws:iam::123456789012:oidc-provider/auth.example.com/auth/realms/EmployeeIDP" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1", name = "us-east-1" }
  }
}

mock_provider "archive" {}

# Content must not inherit the mocked audit bucket's identity.
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
  enable_kube_proxy    = true
}

override_data {
  target = data.aws_partition.current
  values = {
    partition = "aws"
    id        = "aws"
  }
}

# Satisfy endpoint and routing guards without live VPC data.
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

run "default_omits_rta_server" {
  command = plan

  assert {
    condition     = var.rta_server_url == ""
    error_message = "The regional module must leave the RTA server unconfigured by default."
  }
  assert {
    condition = alltrue([
      for container in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) :
      alltrue([for item in container.environment : item.name != "RTA_SERVER"])
    ])
    error_message = "An unset RTA origin must not emit RTA_SERVER in any container."
  }
}

run "configured_origin_only_reaches_main_container" {
  command = plan
  variables {
    rta_server_url = "https://rta.example.com"
  }

  assert {
    condition = toset([
      for container in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : container.name
    ]) == toset(["rosa-boundary", "kube-proxy"])
    error_message = "The proxy must be present so the isolation assertion is not vacuous."
  }
  assert {
    condition = [
      for item in one([
        for container in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) :
        container if container.name == "rosa-boundary"
      ]).environment : item.value if item.name == "RTA_SERVER"
    ] == ["https://rta.example.com"]
    error_message = "The main container must receive exactly one RTA_SERVER with the configured origin."
  }
  assert {
    condition = alltrue([
      for item in one([
        for container in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) :
        container if container.name == "kube-proxy"
      ]).environment : item.name != "RTA_SERVER"
    ])
    error_message = "RTA_SERVER must not leak into the kube-proxy sidecar."
  }
  assert {
    condition = alltrue(flatten([
      for container in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) : [
        for item in container.environment :
        !contains(["OCM_CONFIG", "OCM_KEYRING", "RTA_TIMEOUT"], item.name)
      ]
    ]))
    error_message = "Configuring RTA_SERVER must not introduce OCM credential or RTA timeout overrides."
  }
}

run "trailing_slash_is_normalized" {
  command = plan
  variables {
    rta_server_url = "https://rta.example.com/"
  }
  assert {
    condition = [
      for item in one([
        for container in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) :
        container if container.name == "rosa-boundary"
      ]).environment : item.value if item.name == "RTA_SERVER"
    ] == ["https://rta.example.com"]
    error_message = "The emitted RTA origin must have its optional trailing slash removed."
  }
}

run "minimum_port_is_accepted" {
  command = plan
  variables {
    rta_server_url = "https://rta.example.com:1"
  }
}

run "maximum_port_and_trailing_slash_are_accepted" {
  command = plan
  variables {
    rta_server_url = "https://rta.example.com:65535/"
  }
  assert {
    condition = [
      for item in one([
        for container in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions) :
        container if container.name == "rosa-boundary"
      ]).environment : item.value if item.name == "RTA_SERVER"
    ] == ["https://rta.example.com:65535"]
    error_message = "Normalization must preserve an explicit valid port."
  }
}

run "http_origin_is_rejected" {
  command = plan
  variables { rta_server_url = "http://rta.example.com" }
  expect_failures = [var.rta_server_url]
}

run "api_path_is_rejected" {
  command = plan
  variables { rta_server_url = "https://rta.example.com/api" }
  expect_failures = [var.rta_server_url]
}

run "userinfo_is_rejected" {
  command = plan
  variables { rta_server_url = "https://user:password@rta.example.com" }
  expect_failures = [var.rta_server_url]
}

run "leading_whitespace_is_rejected" {
  command = plan
  variables { rta_server_url = " https://rta.example.com" }
  expect_failures = [var.rta_server_url]
}

run "trailing_whitespace_is_rejected" {
  command = plan
  variables { rta_server_url = "https://rta.example.com " }
  expect_failures = [var.rta_server_url]
}

run "embedded_whitespace_is_rejected" {
  command = plan
  variables { rta_server_url = "https://rta .example.com" }
  expect_failures = [var.rta_server_url]
}

run "query_is_rejected" {
  command = plan
  variables { rta_server_url = "https://rta.example.com?mode=test" }
  expect_failures = [var.rta_server_url]
}

run "fragment_is_rejected" {
  command = plan
  variables { rta_server_url = "https://rta.example.com#fragment" }
  expect_failures = [var.rta_server_url]
}

run "invalid_hostname_is_rejected" {
  command = plan
  variables { rta_server_url = "https://rta_invalid.example.com" }
  expect_failures = [var.rta_server_url]
}

run "leading_hyphen_hostname_is_rejected" {
  command = plan
  variables { rta_server_url = "https://-rta.example.com" }
  expect_failures = [var.rta_server_url]
}

run "empty_hostname_label_is_rejected" {
  command = plan
  variables { rta_server_url = "https://rta..example.com" }
  expect_failures = [var.rta_server_url]
}

run "zero_port_is_rejected" {
  command = plan
  variables { rta_server_url = "https://rta.example.com:0" }
  expect_failures = [var.rta_server_url]
}

run "out_of_range_port_is_rejected" {
  command = plan
  variables { rta_server_url = "https://rta.example.com:65536" }
  expect_failures = [var.rta_server_url]
}

run "nonnumeric_port_is_rejected" {
  command = plan
  variables { rta_server_url = "https://rta.example.com:https" }
  expect_failures = [var.rta_server_url]
}

# Verifies the claude_default_model <-> bedrock_model_agreements consistency
# guard in variables.tf: claude_default_model must be a known Bedrock inference
# profile ID (a key in local.claude_inference_profile_foundation_models) that
# resolves to a foundation model present in bedrock_model_agreements. Bare
# foundation model IDs are rejected.
#
# mock_provider avoids any AWS credentials/API calls. The override_data blocks
# supply the few data-source values the module's preconditions and the
# subnet_outbound_routing check assert on, so each run fails (or passes) only on
# the input-variable validation under test.

mock_provider "aws" {
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

# Baseline inputs. The approved manifest remains a read-only validation contract;
# account Terraform now owns agreements and offer lookups.
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

# The shared Claude/pi/OpenCode default must map to its approved model.
run "default_sonnet55_profile_succeeds" {
  command = plan
  variables {
    bedrock_model_agreements = { "anthropic.claude-sonnet-5-5" = "offer-test" }
  }
  assert {
    condition     = var.claude_default_model == "us.anthropic.claude-sonnet-5-5"
    error_message = "Keep the shared default pinned to the reviewed Sonnet 5.5 US profile."
  }
  assert {
    condition = one([
      for item in jsondecode(aws_ecs_task_definition.rosa_boundary.container_definitions)[0].environment :
      item.value if item.name == "ANTHROPIC_MODEL"
    ]) == var.claude_default_model
    error_message = "The shared model must reach the task environment."
  }
}

run "haiku55_requires_matching_agreement" {
  command = plan
  variables {
    bedrock_model_agreements = { "anthropic.claude-sonnet-5" = "offer-test" }
    claude_default_model     = "us.anthropic.claude-haiku-5-5"
  }
  expect_failures = [var.claude_default_model]
}

run "approved_sonnet55_us_profile_succeeds" {
  command = plan
  variables {
    bedrock_model_agreements = { "anthropic.claude-sonnet-5-5" = "offer-test" }
    claude_default_model     = "us.anthropic.claude-sonnet-5-5"
  }
}

run "approved_sonnet55_eu_profile_succeeds" {
  command = plan
  variables {
    aws_region               = "eu-west-1"
    bedrock_model_agreements = { "anthropic.claude-sonnet-5-5" = "offer-test" }
    claude_default_model     = "eu.anthropic.claude-sonnet-5-5"
  }
}

run "sonnet55_requires_matching_agreement" {
  command = plan
  variables {
    bedrock_model_agreements = { "anthropic.claude-sonnet-5" = "offer-test" }
    claude_default_model     = "us.anthropic.claude-sonnet-5-5"
  }
  expect_failures = [var.claude_default_model]
}

run "us_claude_profile_rejected_in_europe" {
  command = plan
  variables {
    aws_region           = "eu-west-1"
    claude_default_model = "us.anthropic.claude-sonnet-5-5"
  }
  expect_failures = [var.claude_default_model]
}

run "us_codex_profile_rejected_in_asia" {
  command = plan
  variables {
    aws_region           = "ap-southeast-1"
    claude_default_model = "global.anthropic.claude-sonnet-5-5"
    codex_default_model  = "us.openai.gpt-6.1-sol"
  }
  expect_failures = [var.codex_default_model]
}

run "explicit_global_profiles_accepted_in_asia" {
  command = plan
  variables {
    aws_region           = "ap-southeast-1"
    claude_default_model = "global.anthropic.claude-sonnet-5-5"
    codex_default_model  = "global.openai.gpt-6.1-sol"
  }
}

run "approved_sonnet5_profile_succeeds" {
  command = plan

  variables {
    bedrock_model_agreements = { "anthropic.claude-sonnet-5" = "offer-test" }
    claude_default_model     = "us.anthropic.claude-sonnet-5"
  }

}

# Strictness: a bare foundation model ID is not an inference profile in the
# mapping -> validation fails.
run "bare_foundation_model_rejected" {
  command = plan

  variables {
    bedrock_model_agreements = { "anthropic.claude-sonnet-5" = "offer-test" }
    claude_default_model     = "anthropic.claude-sonnet-5"
  }


  expect_failures = [var.claude_default_model]
}

# Consistency: the Sonnet 5 profile resolves to anthropic.claude-sonnet-5, which
# is absent from bedrock_model_agreements -> validation fails.
run "unapproved_foundation_model_fails" {
  command = plan

  variables {
    bedrock_model_agreements = { "anthropic.claude-opus-5" = "offer-test" }
    claude_default_model     = "us.anthropic.claude-sonnet-5"
  }


  expect_failures = [var.claude_default_model]
}

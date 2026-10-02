# No real AWS calls: exercise the generated policy under staging-like inputs.
mock_provider "aws" {}

override_resource {
  target          = aws_iam_role.task
  override_during = plan
  values          = { arn = "arn:aws:iam::123456789012:role/rosa-boundary-stage-task-role" }
}

override_data {
  target = data.aws_partition.current
  values = { partition = "aws" }
}

override_data {
  target = data.aws_region.current
  values = { region = "us-east-1" }
}

override_data {
  target = data.aws_caller_identity.current
  values = { account_id = "123456789012" }
}

override_data {
  target = data.aws_subnet.bedrock_runtime["subnet-00000000000000001"]
  values = { vpc_id = "vpc-00000000000000000", availability_zone_id = "use1-az1" }
}

override_data {
  target = data.aws_subnet.bedrock_runtime["subnet-00000000000000002"]
  values = { vpc_id = "vpc-00000000000000000", availability_zone_id = "use1-az2" }
}

override_data {
  target = data.aws_route_table.subnet[0]
  values = { routes = [{ cidr_block = "0.0.0.0/0", nat_gateway_id = "nat-00000000000000001" }] }
}

override_data {
  target = data.aws_route_table.subnet[1]
  values = { routes = [{ cidr_block = "0.0.0.0/0", nat_gateway_id = "nat-00000000000000001" }] }
}

variables {
  aws_account_id      = "123456789012"
  aws_region          = "us-east-1"
  vpc_id              = "vpc-00000000000000000"
  subnet_ids          = ["subnet-00000000000000001", "subnet-00000000000000002"]
  container_image     = "example.invalid/rosa-boundary:test"
  keycloak_issuer_url = "https://example.invalid/realms/test"
  bedrock_allowed_models = {
    "anthropic.claude-sonnet-5" = {
      profile_id    = "us.anthropic.claude-sonnet-5"
      model_regions = ["us-east-1", "us-east-2", "us-west-2"]
    }
  }
}

run "selected_profile_only" {
  command = plan

  assert {
    condition = local.bedrock_allowed_resources == [
      "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet-5",
      "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-5",
      "arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-sonnet-5",
      "arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-sonnet-5",
    ]
    error_message = "The allowlist must name only the selected profile and its three exact backing model ARNs."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_role_policy.task_bedrock.policy).Statement :
      try(statement.NotResource, null) == local.bedrock_allowed_resources && statement.Effect == "Deny"
    ])
    error_message = "Other invocation resources must be explicitly denied."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_policy.task_bedrock_model["anthropic.claude-sonnet-5"].policy).Statement :
      try(statement.Condition.StringNotEqualsIfExists["bedrock:InferenceProfileArn"], "") == local.bedrock_allowed_profiles["anthropic.claude-sonnet-5"] && statement.Effect == "Deny"
    ])
    error_message = "Direct model calls and other profiles must be denied."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_policy.task_bedrock_model["anthropic.claude-sonnet-5"].policy).Statement :
      try(statement.Condition.StringEquals["bedrock:InferenceProfileArn"], "") == local.bedrock_allowed_profiles["anthropic.claude-sonnet-5"] && statement.Effect == "Allow"
    ])
    error_message = "Backing models must only be allowed through their corresponding profile."
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_policy.task_bedrock_model["anthropic.claude-sonnet-5"].policy).Statement :
      contains(try(statement.Action, []), "bedrock:GetInferenceProfile") && statement.Resource == [local.bedrock_allowed_profiles["anthropic.claude-sonnet-5"]]
    ])
    error_message = "Profile metadata reads must be scoped to approved profiles."
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_vpc_endpoint.bedrock_runtime.policy).Statement :
      statement.Principal.AWS == aws_iam_role.task.arn &&
      !strcontains(jsonencode(statement.Resource), "/*")
    ])
    error_message = "The Runtime endpoint must mirror only the selected resources and principal."
  }
}

run "empty_allowlist_denies_all" {
  command = plan

  variables {
    bedrock_allowed_models = {}
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_role_policy.task_bedrock.policy).Statement :
      try(statement.Resource, null) == "*" && statement.Effect == "Deny"
    ])
    error_message = "A deployment without approved models must deny all invocations."
  }
}

run "reject_unreviewed_profile_or_destinations" {
  command = plan

  variables {
    bedrock_allowed_models = {
      "anthropic.claude-sonnet-5" = {
        profile_id    = "global.anthropic.claude-sonnet-5"
        model_regions = ["us-east-1", "*"]
      }
    }
  }

  expect_failures = [var.bedrock_allowed_models]
}

run "stage_requires_reconciled_allowlist" {
  command = plan

  variables {
    stage                  = "stage"
    bedrock_allowed_models = {}
  }

  expect_failures = [var.bedrock_allowed_models]
}

run "five_model_policy_size" {
  command = plan

  variables {
    stage = "stage"
    bedrock_allowed_models = {
      "anthropic.claude-sonnet-5" = {
        profile_id    = "us.anthropic.claude-sonnet-5"
        model_regions = ["us-east-1", "us-east-2", "us-west-2"]
      }
      "anthropic.claude-opus-4-6-v1" = {
        profile_id    = "us.anthropic.claude-opus-4-6-v1"
        model_regions = ["us-east-1", "us-east-2", "us-west-2"]
      }
      "anthropic.claude-opus-4-8" = {
        profile_id    = "us.anthropic.claude-opus-4-8"
        model_regions = ["us-east-1", "us-east-2", "us-west-2"]
      }
      "anthropic.claude-opus-5" = {
        profile_id    = "us.anthropic.claude-opus-5"
        model_regions = ["us-east-1", "us-east-2", "us-west-2"]
      }
      "anthropic.claude-haiku-4-5-20251001-v1:0" = {
        profile_id    = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
        model_regions = ["us-east-1", "us-east-2", "us-west-2"]
      }
    }
  }

  assert {
    condition = alltrue([
      for model_id, policy in aws_iam_policy.task_bedrock_model :
      length(policy.policy) < 6144
    ]) && length(aws_iam_role_policy.task_bedrock.policy) < 4096
    error_message = "Each managed policy must fit the 6144-character limit; keep the shared inline deny small enough to coexist with other task-role inline policies."
  }
}

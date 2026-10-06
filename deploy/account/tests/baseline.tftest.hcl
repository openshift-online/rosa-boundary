# Mocked applies use only ephemeral Terraform test state, never AWS APIs.
mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws", dns_suffix = "amazonaws.com" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_bedrock_foundation_model_agreement_offers" {
    defaults = { offers = [{ offer_id = "offer-reviewed", offer_token = "token-test" }] }
  }
}

variables {
  aws_account_id                    = "123456789012"
  aws_region                        = "us-east-1"
  legacy_policy_region              = "us-east-1"
  legacy_role_tag_region            = "us-east-1"
  bedrock_budget_tag_region         = "us-east-1"
  bedrock_monthly_budget_usd        = 1000
  bedrock_budget_notification_email = "alerts@example.com"
  keycloak_issuer_url               = "https://auth.example.com/realms/sre"
  keycloak_thumbprint               = "0000000000000000000000000000000000000000"
}

override_resource {
  target = aws_iam_openid_connect_provider.keycloak
  values = { arn = "arn:aws:iam::123456789012:oidc-provider/auth.example.com/realms/sre" }
}

run "account_singletons_and_shared_contract_without_regional_resources" {
  command = apply
  assert {
    condition = (
      output.shared_roles.task.name == "rosa-boundary-dev-task-role" &&
      output.shared_roles.sre_shared.name == "rosa-boundary-dev-sre-shared" &&
      output.shared_roles.s3_replication == null &&
      length(output.shared_roles) == 8 &&
      output.regional_iam_contract == {
        account_role_name_prefix = "rosa-boundary-dev"
        legacy_policy_region     = "us-east-1"
      }
    )
    error_message = "One shared identity set and explicit policy ownership contract must replace regional identity copies."
  }
  assert {
    condition = (
      aws_budgets_budget.bedrock.name == "rosa-boundary-dev-bedrock-monthly" &&
      aws_budgets_budget.bedrock.limit_amount == "1000" &&
      aws_budgets_budget.bedrock.tags.Region == "us-east-1" &&
      length(aws_budgets_budget.bedrock.notification) == 3 &&
      toset([for n in aws_budgets_budget.bedrock.notification : n.threshold]) == toset([50, 80, 100]) &&
      alltrue([for n in aws_budgets_budget.bedrock.notification : n.subscriber_email_addresses == toset(["alerts@example.com"])])
    )
    error_message = "Retain the existing account budget, notifications and original Region tag."
  }
  assert {
    condition = (
      aws_iam_openid_connect_provider.keycloak.url == var.keycloak_issuer_url &&
      aws_iam_openid_connect_provider.keycloak.client_id_list == toset(["rosa-boundary-sre"]) &&
      aws_iam_openid_connect_provider.keycloak.tags.Name == "rosa-boundary-dev-keycloak-oidc" &&
      length(aws_iam_openid_connect_provider.stage_keycloak) == 0 &&
      length(aws_iam_openid_connect_provider.prod_keycloak) == 0
    )
    error_message = "OIDC providers remain account singletons with unchanged identities."
  }
  # Source-level assertions intentionally guard ownership, which AWS mocks cannot.
  assert {
    condition = (
      length(regexall("aws_iam_role_policy\\.", file("${path.module}/imports.tf"))) == 0 &&
      length(regexall("aws_iam_role_policy\\.", file("${path.module}/../regional/account-handoff.tf"))) == 0 &&
      length(regexall("terraform_remote_state|audit_bucket_arn|ecs_cluster_arn|efs_filesystem_arn|exec_session_kms_key_arn|create_investigation_function_arn", file("${path.module}/variables.tf"))) == 0 &&
      alltrue([for f in fileset("${path.module}/modules/shared-iam", "*.tf") :
        length(regexall("resource \\\"aws_iam_role_policy\\\"|inline_policy[[:space:]]*=|managed_policy_arns[[:space:]]*=|aws_iam_role_policies_exclusive|aws_iam_role_policy_attachments_exclusive", file("${path.module}/modules/shared-iam/${f}"))) == 0
      ]) &&
      length(flatten([for f in fileset("${path.module}/modules/shared-iam", "*.tf") : regexall("resource \\\"aws_iam_role_policy_attachment\\\"", file("${path.module}/modules/shared-iam/${f}"))])) == 3 &&
      alltrue([for f in fileset(path.module, "**/*.tf") :
        length(regexall("terraform_remote_state|aws_ecs_cluster\\.|aws_efs_file_system\\.|aws_s3_bucket\\.|aws_kms_key\\.|aws_cloudwatch_log_group\\.|aws_lambda_function\\.", file("${path.module}/${f}"))) == 0
      ])
    )
    error_message = "Account must not depend on regional resources, import regional policies, or exclusively reconcile shared role grants."
  }
}

run "optional_oidc_singletons" {
  command = apply
  variables {
    stage_keycloak_issuer_url = "https://stage.example.com/realms/sre"
    stage_oidc_client_id      = "stage-sre"
    stage_keycloak_thumbprint = "1111111111111111111111111111111111111111"
    prod_keycloak_issuer_url  = "https://prod.example.com/realms/sre"
    prod_oidc_client_id       = "prod-sre"
    prod_keycloak_thumbprint  = "2222222222222222222222222222222222222222"
  }
  override_resource {
    target = aws_iam_openid_connect_provider.stage_keycloak[0]
    values = { arn = "arn:aws:iam::123456789012:oidc-provider/stage.example.com/realms/sre" }
  }
  override_resource {
    target = aws_iam_openid_connect_provider.prod_keycloak[0]
    values = { arn = "arn:aws:iam::123456789012:oidc-provider/prod.example.com/realms/sre" }
  }
  assert {
    condition = (
      length(aws_iam_openid_connect_provider.stage_keycloak) == 1 &&
      length(aws_iam_openid_connect_provider.prod_keycloak) == 1 &&
      aws_iam_openid_connect_provider.stage_keycloak[0].client_id_list == toset(["stage-sre"]) &&
      aws_iam_openid_connect_provider.prod_keycloak[0].client_id_list == toset(["prod-sre"]) &&
      aws_iam_openid_connect_provider.stage_keycloak[0].tags.Name == "rosa-boundary-dev-stage-oidc" &&
      aws_iam_openid_connect_provider.prod_keycloak[0].tags.Name == "rosa-boundary-dev-prod-oidc"
    )
    error_message = "Optional OIDC providers must exist once per account."
  }
}

run "custom_shared_prefix" {
  command = apply
  variables { role_name_prefix = "boundary-shared" }
  assert {
    condition     = output.shared_roles.task.name == "boundary-shared-task-role" && output.regional_iam_contract.account_role_name_prefix == "boundary-shared"
    error_message = "A deliberate custom prefix must be exposed consistently to all regions."
  }
}

run "invalid_prefix_rejected" {
  command = plan
  variables { role_name_prefix = "prefix/invalid" }
  expect_failures = [var.role_name_prefix]
}

run "model_activation_preserves_manifest" {
  command = plan
  variables { bedrock_model_agreements = { "anthropic.claude-sonnet-5" = "offer-reviewed" } }
  assert {
    condition     = aws_bedrock_foundation_model_agreement.approved["anthropic.claude-sonnet-5"].model_id == "anthropic.claude-sonnet-5" && aws_bedrock_foundation_model_agreement.approved["anthropic.claude-sonnet-5"].offer_token == "token-test"
    error_message = "Account activation must preserve model ID and reviewed offer."
  }
}

run "wildcard_service_trust_region_rejected" {
  command = plan
  variables { bedrock_logging_source_regions = ["*"] }
  expect_failures = [var.bedrock_logging_source_regions]
}

run "legacy_bedrock_trust_cannot_be_silently_dropped" {
  command = plan
  variables { bedrock_logging_source_regions = ["us-west-2"] }
  expect_failures = [var.bedrock_logging_source_regions]
}

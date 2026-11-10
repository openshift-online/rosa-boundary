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

# Publisher trust derives claim keys from the provider ARN, so mocked applies
# need a structurally valid ARN rather than Terraform's random string.
override_resource {
  target = aws_iam_openid_connect_provider.github_actions[0]
  values = { arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }
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
      output.shared_roles.metrics_read == null &&
      output.shared_roles.reap_investigations.name == "rosa-boundary-dev-reap-investigations-lambda" &&
      length(output.shared_roles) == 10 &&
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
      alltrue([for f in fileset(path.module, "*.tf") :
        length(regexall("aws_iam_role_policy\\.", file("${path.module}/${f}"))) == 0
      ]) &&
      length(regexall("terraform_remote_state|audit_bucket_arn|ecs_cluster_arn|efs_filesystem_arn|exec_session_kms_key_arn|create_investigation_function_arn", file("${path.module}/variables.tf"))) == 0 &&
      alltrue([for f in fileset("${path.module}/modules/shared-iam", "*.tf") :
        length(regexall("resource \\\"aws_iam_role_policy\\\"|inline_policy[[:space:]]*=|managed_policy_arns[[:space:]]*=|aws_iam_role_policies_exclusive|aws_iam_role_policy_attachments_exclusive", file("${path.module}/modules/shared-iam/${f}"))) == 0
      ]) &&
      length(flatten([for f in fileset("${path.module}/modules/shared-iam", "*.tf") : regexall("resource \\\"aws_iam_role_policy_attachment\\\"", file("${path.module}/modules/shared-iam/${f}"))])) == 5 &&
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
    condition     = output.shared_roles.task.name == "boundary-shared-task-role" && output.shared_roles.reap_investigations.name == "boundary-shared-reap-investigations-lambda" && output.regional_iam_contract.account_role_name_prefix == "boundary-shared"
    error_message = "A deliberate custom prefix must be exposed consistently to all regions."
  }
}

run "invalid_prefix_rejected" {
  command = plan
  variables { role_name_prefix = "prefix/invalid" }
  expect_failures = [var.role_name_prefix]
}

# The shared-role prefix limit remains 36 with shorter custom source keys.
# Default publisher source keys have a stricter combined name-length limit.
run "longest_valid_prefix" {
  command = plan
  variables {
    role_name_prefix = "123456789012345678901234567890123456"
    content_publisher_sources = {
      ops-sop = { repository = "openshift/ops-sop", branch = "master" }
    }
  }
  assert {
    condition     = output.shared_roles.create_investigation.name == "123456789012345678901234567890123456-create-investigation-lambda"
    error_message = "The longest valid prefix must produce a 64-character IAM role name."
  }
}

run "too_long_prefix_rejected" {
  command = plan
  variables { role_name_prefix = "1234567890123456789012345678901234567" }
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

# ROSAENG-68823: the account root threads the metrics-read inputs through to
# the shared identity module, and creates identity only - never a grant.
run "metrics_read_identity_is_wired_through_the_account_root" {
  command = apply
  variables {
    enable_metrics_read_role            = true
    metrics_read_trusted_principal_arns = ["arn:aws:iam::210987654321:role/example-collector"]
    metrics_read_session_duration       = 7200
  }
  assert {
    condition = (
      output.shared_roles.metrics_read.name == "rosa-boundary-dev-metrics-read" &&
      length(output.shared_roles) == 10 &&
      output.shared_roles.s3_replication == null
    )
    error_message = "Enabling the metrics reader at the account root must surface the role through shared_roles."
  }
  # The grant lives in deploy/regional. That the account module declares no
  # inline policy is already enforced for every file by the ownership assertion
  # in account_singletons_and_shared_contract_without_regional_resources, so it
  # is deliberately not restated here.
}

# The account root creates or references the GitHub Actions OIDC
# provider and threads its ARN into the shared identity module. Trust-policy
# content is asserted in tests/content-publishing.tftest.hcl.

run "content_identities_exist_by_default" {
  command = apply
  assert {
    condition = (
      length(aws_iam_openid_connect_provider.github_actions) == 1 &&
      length(data.aws_iam_openid_connect_provider.github_actions) == 0 &&
      toset(keys(output.content_publisher_roles)) == toset(["ops-sop", "managed-notifications", "rosa-claude-plugins"]) &&
      toset(keys(output.content_publisher_role_arns)) == toset(["ops-sop", "managed-notifications", "rosa-claude-plugins"]) &&
      output.content_replication_role_arn != null &&
      output.github_actions_oidc_provider_arn == aws_iam_openid_connect_provider.github_actions[0].arn &&
      length(output.shared_roles) == 10
    )
    error_message = "Publishers, provider resolution and the dedicated content replication identity must always exist."
  }
}

run "create_mode_owns_one_provider_with_only_the_sts_audience" {
  command = apply
  override_resource {
    target = aws_iam_openid_connect_provider.github_actions[0]
    values = { arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }
  }
  assert {
    condition = (
      length(aws_iam_openid_connect_provider.github_actions) == 1 &&
      length(data.aws_iam_openid_connect_provider.github_actions) == 0 &&
      aws_iam_openid_connect_provider.github_actions[0].url == "https://token.actions.githubusercontent.com" &&
      aws_iam_openid_connect_provider.github_actions[0].client_id_list == toset(["sts.amazonaws.com"]) &&
      aws_iam_openid_connect_provider.github_actions[0].tags.Name == "rosa-boundary-dev-github-actions-oidc"
    )
    error_message = "Create mode must own exactly one GitHub provider, trusting only the sts.amazonaws.com audience."
  }
  # No thumbprint is pinned for this issuer. The Keycloak providers keep theirs.
  assert {
    condition = (
      length(regexall("thumbprint_list", file("${path.module}/github-oidc.tf"))) == 0 &&
      aws_iam_openid_connect_provider.keycloak.url == var.keycloak_issuer_url &&
      aws_iam_openid_connect_provider.keycloak.client_id_list == toset(["rosa-boundary-sre"])
    )
    error_message = "The GitHub provider must pin no thumbprint, and the Keycloak singletons must be untouched."
  }
  assert {
    condition = (
      output.github_actions_oidc_provider_arn == aws_iam_openid_connect_provider.github_actions[0].arn &&
      toset(keys(output.content_publisher_roles)) == toset(["ops-sop", "managed-notifications", "rosa-claude-plugins"]) &&
      toset(keys(output.content_publisher_role_arns)) == toset(["ops-sop", "managed-notifications", "rosa-claude-plugins"]) &&
      output.content_publisher_roles["rosa-claude-plugins"].subject == "repo:openshift-online/rosa-claude-plugins:ref:refs/heads/main" &&
      output.content_replication_role_arn != null &&
      length(output.shared_roles) == 10
    )
    error_message = "The account root must publish the content contract without changing the shared_roles contract."
  }
}

run "reference_mode_reads_an_existing_provider_and_creates_none" {
  command = apply
  variables {
    create_github_actions_oidc_provider = false
  }
  override_data {
    target = data.aws_iam_openid_connect_provider.github_actions[0]
    values = { arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }
  }
  # Mocked data proves the wiring only: that this mode reads rather than
  # creates, and that the ARN reaches the trust policies and the output. It
  # cannot show that such a provider exists in any real account - that lookup
  # fails the plan there, and the account inventory is a separate prerequisite.
  assert {
    condition = (
      length(aws_iam_openid_connect_provider.github_actions) == 0 &&
      length(data.aws_iam_openid_connect_provider.github_actions) == 1 &&
      output.github_actions_oidc_provider_arn == data.aws_iam_openid_connect_provider.github_actions[0].arn &&
      length(output.content_publisher_roles) == 3
    )
    error_message = "Reference mode must not create a provider, and must still publish a usable provider ARN."
  }
}

# Adoption is the highest-risk provider mode, and its import block is only
# evaluated when BOTH flags are on: a default-off plan proves nothing about it.
# This run forces that evaluation, so the import block's for_each collection
# and its to-address index are checked by Terraform rather than assumed.
#
# Limitation: a mocked provider cannot perform a real import, so this does not
# prove the import ID resolves to an existing provider in any account - that
# stays a per-account plan review before enabling. What it does prove is that
# the import configuration is valid and targets the one managed instance; a
# wrong to-index fails here with "Configuration for import target does not
# exist", which is how this run was confirmed to be sensitive rather than
# vacuous.
run "adoption_mode_evaluates_the_import_target" {
  command = plan
  variables {
    adopt_existing_resources = true
  }
  override_resource {
    target = aws_iam_openid_connect_provider.github_actions[0]
    values = { arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }
  }
  assert {
    condition     = length(aws_iam_openid_connect_provider.github_actions) == 1
    error_message = "Adoption must manage exactly the one provider instance the import block targets."
  }
  # The import ID must be derived from the issuer local, not restated, or a
  # future issuer change would adopt the wrong provider ARN.
  assert {
    condition = (
      length(regexall("oidc-provider/\\$\\{local\\.github_actions_issuer_host\\}", file("${path.module}/github-oidc.tf"))) == 1 &&
      length(regexall("oidc-provider/token\\.actions\\.githubusercontent\\.com\"", file("${path.module}/github-oidc.tf"))) == 0
    )
    error_message = "The adopt-mode import ID must derive the issuer host from the issuer URL local."
  }
}

run "adoption_is_inert_when_the_handoff_switch_is_off" {
  command = plan
  variables {
    adopt_existing_resources = false
  }
  override_resource {
    target = aws_iam_openid_connect_provider.github_actions[0]
    values = { arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }
  }
  assert {
    condition     = length(aws_iam_openid_connect_provider.github_actions) == 1
    error_message = "Create mode must still manage the provider when adoption is off."
  }
}

run "replication_identity_is_independent_of_the_publishers" {
  command = apply
  assert {
    condition = (
      length(aws_iam_openid_connect_provider.github_actions) == 1 &&
      length(output.content_publisher_roles) == 3 &&
      output.content_replication_role_arn != null &&
      output.shared_roles.s3_replication == null &&
      length(output.shared_roles) == 10
    )
    error_message = "Content replication can be enabled alongside unconditional publishers without enabling audit replication."
  }
}

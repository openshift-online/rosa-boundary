mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws", dns_suffix = "amazonaws.com" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
}

variables {
  project                        = "rosa-boundary"
  stage                          = "dev"
  role_name_prefix               = "rosa-boundary-dev"
  legacy_role_tag_region         = "us-west-2"
  bedrock_logging_source_regions = ["us-west-2"]
  tags                           = { Owner = "sre" }
  enable_s3_replication_role     = true
  keycloak_provider_arn          = "arn:aws:iam::123456789012:oidc-provider/auth.example.com/realms/sre"
  stage_keycloak_provider_arn    = "arn:aws:iam::123456789012:oidc-provider/stage.example.com/realms/sre"
  prod_keycloak_provider_arn     = "arn:aws:iam::123456789012:oidc-provider/prod.example.com/realms/sre"
  stage_keycloak_issuer_url      = "https://stage.example.com/realms/sre"
  prod_keycloak_issuer_url       = "https://prod.example.com/realms/sre"
  oidc_client_id                 = "rosa-boundary-sre"
  stage_oidc_client_id           = "stage-sre"
  prod_oidc_client_id            = "prod-sre"
  oidc_session_duration          = 7200
  enable_uuid_allowlist          = true
  allowed_uuids                  = ["11111111-1111-1111-1111-111111111111"]
  enable_oidc_group_enforcement  = true
  required_oidc_role             = "ai-sd-sre"

  enable_metrics_read_role            = false
  metrics_read_trusted_principal_arns = []
  metrics_read_session_duration       = 3600

  # Publishers are always present; their detailed trust assertions live in
  # content-publishing.tftest.hcl. The dedicated replication identity is also always present.
  github_actions_provider_arn        = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  github_actions_audience            = "sts.amazonaws.com"
  content_publisher_session_duration = 3600
  content_publisher_sources = {
    ops-sop               = { repository = "openshift/ops-sop", branch = "master" }
    managed-notifications = { repository = "openshift/managed-notifications", branch = "master" }
    rosa-claude-plugins   = { repository = "openshift-online/rosa-claude-plugins", branch = "main" }
  }
}

run "legacy_identity_trust_tags_and_common_attachments" {
  command = apply
  module { source = "./modules/shared-iam" }
  assert {
    condition = toset([for r in output.roles : r.name if r != null]) == toset([
      "rosa-boundary-dev-execution-role", "rosa-boundary-dev-task-role",
      "rosa-boundary-dev-sre-shared", "rosa-boundary-dev-lambda-invoker",
      "rosa-boundary-dev-create-investigation-lambda", "rosa-boundary-dev-reap-tasks-lambda",
      "rosa-boundary-dev-reap-investigations-lambda",
      "rosa-boundary-dev-bedrock-invocation-logging", "rosa-boundary-dev-s3-replication-role"
    ])
    error_message = "All nine shared identity names, including the investigation reaper, must survive migration."
  }
  assert {
    condition = (
      jsondecode(aws_iam_role.sre_shared.assume_role_policy) == jsondecode(aws_iam_role.lambda_invoker.assume_role_policy) &&
      length(jsondecode(aws_iam_role.sre_shared.assume_role_policy).Statement) == 3 &&
      jsondecode(aws_iam_role.sre_shared.assume_role_policy).Statement[0].Principal.Federated == var.keycloak_provider_arn &&
      jsondecode(aws_iam_role.sre_shared.assume_role_policy).Statement[1].Principal.Federated == var.stage_keycloak_provider_arn &&
      jsondecode(aws_iam_role.sre_shared.assume_role_policy).Statement[2].Principal.Federated == var.prod_keycloak_provider_arn &&
      alltrue([for s in jsondecode(aws_iam_role.sre_shared.assume_role_policy).Statement :
        toset(s.Action) == toset(["sts:AssumeRoleWithWebIdentity", "sts:TagSession"]) &&
        s.Condition.StringEquals["aws:RequestTag/roles"] == "ai-sd-sre" &&
        toset(s.Condition.StringEquals["aws:RequestTag/uuid"]) == toset(var.allowed_uuids)
      ]) &&
      jsondecode(aws_iam_role.sre_shared.assume_role_policy).Statement[0].Condition.StringEquals["auth.example.com/realms/sre:aud"] == "rosa-boundary-sre" &&
      jsondecode(aws_iam_role.sre_shared.assume_role_policy).Statement[1].Condition.StringEquals["stage.example.com/realms/sre:aud"] == "stage-sre" &&
      jsondecode(aws_iam_role.sre_shared.assume_role_policy).Statement[2].Condition.StringEquals["prod.example.com/realms/sre:aud"] == "prod-sre" &&
      aws_iam_role.sre_shared.max_session_duration == 7200 && aws_iam_role.lambda_invoker.max_session_duration == 3600
    )
    error_message = "Keep OIDC trust principals, audiences, session tags and durations."
  }
  assert {
    condition = (
      jsondecode(aws_iam_role.execution.assume_role_policy).Statement[0].Principal.Service == "ecs-tasks.amazonaws.com" &&
      jsondecode(aws_iam_role.task.assume_role_policy) == jsondecode(aws_iam_role.execution.assume_role_policy) &&
      jsondecode(aws_iam_role.create_investigation_lambda.assume_role_policy).Statement[0].Principal.Service == "lambda.amazonaws.com" &&
      jsondecode(aws_iam_role.reap_tasks_lambda.assume_role_policy) == jsondecode(aws_iam_role.create_investigation_lambda.assume_role_policy) &&
      jsondecode(aws_iam_role.reap_investigations_lambda.assume_role_policy) == jsondecode(aws_iam_role.create_investigation_lambda.assume_role_policy) &&
      jsondecode(aws_iam_role.s3_replication[0].assume_role_policy).Statement[0].Principal.Service == "s3.amazonaws.com" &&
      jsondecode(aws_iam_role.bedrock_invocation_logging.assume_role_policy).Statement[0].Condition == {
        StringEquals = { "aws:SourceAccount" = "123456789012" }
        ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock:us-west-2:123456789012:*" }
      }
    )
    error_message = "Preserve service trust and Bedrock confused-deputy restrictions."
  }
  assert {
    condition = (
      aws_iam_role_policy_attachment.execution_managed.policy_arn == "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy" &&
      aws_iam_role_policy_attachment.execution_managed.role == aws_iam_role.execution.name &&
      aws_iam_role_policy_attachment.create_investigation_lambda_basic.policy_arn == "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole" &&
      aws_iam_role_policy_attachment.create_investigation_lambda_basic.role == aws_iam_role.create_investigation_lambda.name &&
      aws_iam_role_policy_attachment.reap_tasks_lambda_basic.policy_arn == aws_iam_role_policy_attachment.create_investigation_lambda_basic.policy_arn &&
      aws_iam_role_policy_attachment.reap_tasks_lambda_basic.role == aws_iam_role.reap_tasks_lambda.name &&
      aws_iam_role_policy_attachment.reap_investigations_lambda_basic.policy_arn == aws_iam_role_policy_attachment.create_investigation_lambda_basic.policy_arn &&
      aws_iam_role_policy_attachment.reap_investigations_lambda_basic.role == aws_iam_role.reap_investigations_lambda.name &&
      aws_iam_role_policy_attachment.reap_investigations_lambda_vpc.policy_arn == "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole" &&
      aws_iam_role_policy_attachment.reap_investigations_lambda_vpc.role == aws_iam_role.reap_investigations_lambda.name &&
      alltrue([for r in [aws_iam_role.execution, aws_iam_role.task, aws_iam_role.sre_shared, aws_iam_role.lambda_invoker, aws_iam_role.create_investigation_lambda, aws_iam_role.reap_tasks_lambda, aws_iam_role.reap_investigations_lambda, aws_iam_role.bedrock_invocation_logging, aws_iam_role.s3_replication[0]] :
        r.tags.Region == "us-west-2" && r.tags.Project == "rosa-boundary" && r.tags.Stage == "dev" && r.tags.ManagedBy == "Terraform" && r.tags.Owner == "sre"
      ]) &&
      aws_iam_role.sre_shared.tags.Name == "rosa-boundary-dev-sre-shared" &&
      aws_iam_role.lambda_invoker.tags.Name == "rosa-boundary-dev-lambda-invoker"
    )
    error_message = "Common attachments are owned once and legacy/custom identity tags remain intact."
  }
}

run "explicit_multi_region_bedrock_trust" {
  command = apply
  module { source = "./modules/shared-iam" }
  variables { bedrock_logging_source_regions = ["us-west-2", "us-east-1"] }
  assert {
    condition = jsondecode(aws_iam_role.bedrock_invocation_logging.assume_role_policy).Statement[0].Condition == {
      StringEquals = { "aws:SourceAccount" = "123456789012" }
      ArnLike      = { "aws:SourceArn" = ["arn:aws:bedrock:us-west-2:123456789012:*", "arn:aws:bedrock:us-east-1:123456789012:*"] }
    }
    error_message = "Only explicitly approved regions may share logging service trust; SourceAccount must remain restricted."
  }
}

run "empty_uuid_allowlist_fails_closed" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables { allowed_uuids = [] }
  expect_failures = [aws_iam_role.sre_shared]
}

# ROSAENG-68823: external metrics collector identity.

run "metrics_read_role_is_opt_in_and_carries_no_grant" {
  command = apply
  module { source = "./modules/shared-iam" }
  assert {
    condition     = length(aws_iam_role.metrics_read) == 0 && output.roles.metrics_read == null
    error_message = "The external metrics reader must not exist unless it is explicitly enabled."
  }
  # Ownership: the permission grant belongs to the regional root. This module
  # must declare the identity only, so enabling it can never create a policy.
  assert {
    condition     = length(regexall("resource \\\"aws_iam_role_policy\\\"|inline_policy[[:space:]]*=|managed_policy_arns[[:space:]]*=", file("${path.module}/metrics-read.tf"))) == 0
    error_message = "metrics-read.tf must declare identity and trust only; its grant is owned by deploy/regional."
  }
}

run "metrics_read_trust_is_an_explicit_caller_allowlist" {
  command = apply
  module { source = "./modules/shared-iam" }
  variables {
    enable_metrics_read_role      = true
    metrics_read_session_duration = 7200
    metrics_read_trusted_principal_arns = [
      "arn:aws:iam::210987654321:role/example-collector",
      "arn:aws:sts::210987654321:assumed-role/example-collector-jump/example-session",
    ]
  }
  assert {
    condition = (
      output.roles.metrics_read.name == "rosa-boundary-dev-metrics-read" &&
      aws_iam_role.metrics_read[0].name == "rosa-boundary-dev-metrics-read" &&
      aws_iam_role.metrics_read[0].max_session_duration == 7200 &&
      aws_iam_role.metrics_read[0].tags.Name == "rosa-boundary-dev-metrics-read" &&
      aws_iam_role.metrics_read[0].tags.Region == "us-west-2" &&
      aws_iam_role.metrics_read[0].tags.Project == "rosa-boundary" &&
      trimspace(aws_iam_role.metrics_read[0].description) != ""
    )
    error_message = "The metrics reader must keep its name, tags, bounded session duration and description."
  }
  # Absence is asserted on the decoded key set, not with can(): can() swallows
  # every error, so a future shape change would satisfy it silently.
  assert {
    condition = (
      length(jsondecode(aws_iam_role.metrics_read[0].assume_role_policy).Statement) == 1 &&
      jsondecode(aws_iam_role.metrics_read[0].assume_role_policy).Statement[0].Effect == "Allow" &&
      jsondecode(aws_iam_role.metrics_read[0].assume_role_policy).Statement[0].Action == "sts:AssumeRole" &&
      toset(jsondecode(aws_iam_role.metrics_read[0].assume_role_policy).Statement[0].Principal.AWS) == toset(var.metrics_read_trusted_principal_arns) &&
      !contains(keys(jsondecode(aws_iam_role.metrics_read[0].assume_role_policy).Statement[0]), "Condition") &&
      !contains(keys(jsondecode(aws_iam_role.metrics_read[0].assume_role_policy).Statement[0].Principal), "Service") &&
      !contains(keys(jsondecode(aws_iam_role.metrics_read[0].assume_role_policy).Statement[0].Principal), "Federated")
    )
    error_message = "Trust must be exactly sts:AssumeRole for the configured AWS callers, with no service/federated principal and no extra condition."
  }
  # Principal.AWS is a list, so comparing it to the string "*" would always be
  # false and prove nothing. Check membership instead.
  assert {
    condition = (
      !contains(jsondecode(aws_iam_role.metrics_read[0].assume_role_policy).Statement[0].Principal.AWS, "*") &&
      length([for p in jsondecode(aws_iam_role.metrics_read[0].assume_role_policy).Statement[0].Principal.AWS : p if strcontains(p, "*") || endswith(p, ":root")]) == 0
    )
    error_message = "No trusted caller may be a wildcard, contain a wildcard, or be an account root."
  }
}

run "enabled_metrics_read_role_without_a_caller_fails_closed" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables { enable_metrics_read_role = true }
  expect_failures = [aws_iam_role.metrics_read]
}

run "metrics_read_rejects_a_wildcard_role_name" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    enable_metrics_read_role            = true
    metrics_read_trusted_principal_arns = ["arn:aws:iam::210987654321:role/*"]
  }
  expect_failures = [var.metrics_read_trusted_principal_arns]
}

run "metrics_read_rejects_an_account_root_caller" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    enable_metrics_read_role            = true
    metrics_read_trusted_principal_arns = ["arn:aws:iam::210987654321:root"]
  }
  expect_failures = [var.metrics_read_trusted_principal_arns]
}

run "metrics_read_rejects_a_bare_wildcard_caller" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    enable_metrics_read_role            = true
    metrics_read_trusted_principal_arns = ["*"]
  }
  expect_failures = [var.metrics_read_trusted_principal_arns]
}

run "metrics_read_rejects_a_repeated_caller" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    enable_metrics_read_role = true
    metrics_read_trusted_principal_arns = [
      "arn:aws:iam::210987654321:role/example-collector",
      "arn:aws:iam::210987654321:role/example-collector",
    ]
  }
  expect_failures = [var.metrics_read_trusted_principal_arns]
}

run "metrics_read_rejects_an_unbounded_session" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    enable_metrics_read_role            = true
    metrics_read_trusted_principal_arns = ["arn:aws:iam::210987654321:role/example-collector"]
    metrics_read_session_duration       = 86400
  }
  expect_failures = [var.metrics_read_session_duration]
}

run "metrics_read_rejects_a_caller_with_surrounding_whitespace" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    enable_metrics_read_role            = true
    metrics_read_trusted_principal_arns = ["arn:aws:iam::210987654321:role/example-collector "]
  }
  expect_failures = [var.metrics_read_trusted_principal_arns]
}

run "metrics_read_rejects_a_session_below_the_minimum" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    enable_metrics_read_role            = true
    metrics_read_trusted_principal_arns = ["arn:aws:iam::210987654321:role/example-collector"]
    metrics_read_session_duration       = 1800
  }
  expect_failures = [var.metrics_read_session_duration]
}

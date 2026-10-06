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
}

run "legacy_identity_trust_tags_and_common_attachments" {
  command = apply
  module { source = "./modules/shared-iam" }
  assert {
    condition = toset([for r in output.roles : r.name]) == toset([
      "rosa-boundary-dev-execution-role", "rosa-boundary-dev-task-role",
      "rosa-boundary-dev-sre-shared", "rosa-boundary-dev-lambda-invoker",
      "rosa-boundary-dev-create-investigation-lambda", "rosa-boundary-dev-reap-tasks-lambda",
      "rosa-boundary-dev-bedrock-invocation-logging", "rosa-boundary-dev-s3-replication-role"
    ])
    error_message = "All eight legacy identity names must survive migration."
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
      alltrue([for r in [aws_iam_role.execution, aws_iam_role.task, aws_iam_role.sre_shared, aws_iam_role.lambda_invoker, aws_iam_role.create_investigation_lambda, aws_iam_role.reap_tasks_lambda, aws_iam_role.bedrock_invocation_logging, aws_iam_role.s3_replication[0]] :
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

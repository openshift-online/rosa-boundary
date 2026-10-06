# Mocked applies expose rendered grant scopes without touching AWS or live state.
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

run "legacy_policy_names_ownership_and_original_scopes" {
  command = apply
  assert {
    condition = toset([
      aws_iam_role_policy.execution_secrets.name, aws_iam_role_policy.task_s3.name,
      aws_iam_role_policy.task_bedrock.name, aws_iam_role_policy.task_ecs_exec.name,
      aws_iam_role_policy.task_ssm_logging.name, aws_iam_role_policy.task_kms.name,
      aws_iam_role_policy.sre_shared_ecs_exec.name, aws_iam_role_policy.lambda_invoker.name,
      aws_iam_role_policy.create_investigation_lambda_ecs.name, aws_iam_role_policy.create_investigation_lambda_efs.name,
      aws_iam_role_policy.reap_tasks_lambda_ecs.name, aws_iam_role_policy.bedrock_invocation_logging.name,
      aws_iam_role_policy.s3_replication[0].name
      ]) == toset([
      "secrets-manager-access", "s3-audit-access", "bedrock-access", "ecs-exec-access",
      "ssm-session-logging", "kms-exec-session", "ecs-exec-abac", "invoke-create-investigation",
      "ecs-task-management", "efs-access-point-management", "ecs-task-reaping",
      "write-model-invocations", "s3-replication-policy"
    ])
    error_message = "All thirteen legacy inline policy identities must remain in their original regional state."
  }
  assert {
    condition = alltrue([for f in fileset(path.module, "*.tf") :
      length(regexall("resource \\\"aws_iam_role\\\"|resource \\\"aws_iam_role_policy_attachment\\\"|resource \\\"aws_iam_openid_connect_provider\\\"|aws_iam_role_policies_exclusive|aws_iam_role_policy_attachments_exclusive", file("${path.module}/${f}"))) == 0
    ]) && length(regexall("from = aws_iam_role_policy\\.", file("${path.module}/account-handoff.tf"))) == 0
    error_message = "Regional state owns no identities/common attachments and must never release or exclusively reconcile regional grants."
  }
  assert {
    condition = (
      data.aws_iam_role.task.name == "rosa-boundary-dev-task-role" &&
      aws_iam_role_policy.task_s3.role == data.aws_iam_role.task.id &&
      aws_iam_role_policy.execution_secrets.role == data.aws_iam_role.execution.id &&
      aws_iam_role_policy.sre_shared_ecs_exec.role == data.aws_iam_role.sre_shared.id &&
      aws_iam_role_policy.lambda_invoker.role == data.aws_iam_role.lambda_invoker.id &&
      aws_iam_role_policy.create_investigation_lambda_ecs.role == data.aws_iam_role.create_investigation_lambda.id &&
      aws_iam_role_policy.reap_tasks_lambda_ecs.role == data.aws_iam_role.reap_tasks_lambda.id &&
      aws_iam_role_policy.bedrock_invocation_logging.role == data.aws_iam_role.bedrock_invocation_logging.id &&
      aws_iam_role_policy.s3_replication[0].role == data.aws_iam_role.s3_replication[0].id
    )
    error_message = "Grants attach only to looked-up shared account roles."
  }
  assert {
    condition = jsondecode(aws_iam_role_policy.task_s3.policy) == {
      Version = "2012-10-17"
      Statement = [
        { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${aws_s3_bucket.audit.arn}/*" },
        { Effect = "Allow", Action = ["s3:ListBucket"], Resource = aws_s3_bucket.audit.arn }
      ]
      } && (
      jsondecode(aws_iam_role_policy.s3_replication[0].policy).Statement[0].Resource == aws_s3_bucket.audit.arn &&
      jsondecode(aws_iam_role_policy.s3_replication[0].policy).Statement[1].Resource == "${aws_s3_bucket.audit.arn}/*" &&
      jsondecode(aws_iam_role_policy.s3_replication[0].policy).Statement[2].Resource == "${var.audit_replication_bucket_arn}/*"
    )
    error_message = "Audit write/list and optional replication grants retain exact approved bucket scopes."
  }
  assert {
    condition = (
      jsondecode(aws_iam_role_policy.task_kms.policy).Statement[0].Resource == aws_kms_key.exec_session.arn &&
      jsondecode(aws_iam_role_policy.task_ssm_logging.policy).Statement[0].Resource == "*" &&
      jsondecode(aws_iam_role_policy.task_ssm_logging.policy).Statement[1].Resource == [aws_cloudwatch_log_group.ssm_sessions.arn, "${aws_cloudwatch_log_group.ssm_sessions.arn}:*"] &&
      jsondecode(aws_iam_role_policy.bedrock_invocation_logging.policy).Statement[0].Resource == "${aws_cloudwatch_log_group.bedrock_invocations.arn}:log-stream:aws/bedrock/modelinvocations" &&
      jsondecode(aws_iam_role_policy.execution_secrets.policy).Statement[0].Resource == "arn:aws:secretsmanager:us-east-1:123456789012:secret:rosa-boundary/*"
    )
    error_message = "KMS, logging and secret grants retain original local-resource scopes."
  }
  assert {
    condition = (
      jsondecode(aws_iam_role_policy.task_bedrock.policy).Statement[0].Resource == ["arn:aws:bedrock:*:*:inference-profile/*", "arn:aws:bedrock:*:*:foundation-model/*"] &&
      jsondecode(aws_iam_role_policy.task_bedrock.policy).Statement[1].Resource == ["arn:aws:bedrock:us-east-1:123456789012:inference-profile/*", "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/*"] &&
      jsondecode(aws_iam_role_policy.task_ecs_exec.policy).Statement[0].Action == ["ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel", "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel"]
    )
    error_message = "Preserve Bedrock profile and ECS Exec permissions, including baseline wildcard scopes."
  }
  assert {
    condition = (
      jsondecode(aws_iam_role_policy.sre_shared_ecs_exec.policy).Statement[0].Resource == [aws_ecs_cluster.main.arn] &&
      jsondecode(aws_iam_role_policy.sre_shared_ecs_exec.policy).Statement[1].Condition.StringEquals["ecs:ResourceTag/uuid"] == "$${aws:PrincipalTag/uuid}" &&
      jsondecode(aws_iam_role_policy.sre_shared_ecs_exec.policy).Statement[2].Resource == "arn:aws:ecs:us-east-1:123456789012:task/${aws_ecs_cluster.main.name}/*" &&
      jsondecode(aws_iam_role_policy.sre_shared_ecs_exec.policy).Statement[4].Resource == aws_efs_file_system.sre_home.arn &&
      jsondecode(aws_iam_role_policy.sre_shared_ecs_exec.policy).Statement[5].Resource == "arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/*" &&
      jsondecode(aws_iam_role_policy.sre_shared_ecs_exec.policy).Statement[5].Condition.StringEquals["aws:ResourceTag/ManagedBy"] == "rosa-boundary-lambda"
    )
    error_message = "Retain ABAC enforcement and region/account-scoped managed EFS cleanup."
  }
  assert {
    condition = (
      jsondecode(aws_iam_role_policy.lambda_invoker.policy).Statement[0].Action == "lambda:InvokeFunction" &&
      jsondecode(aws_iam_role_policy.lambda_invoker.policy).Statement[0].Resource == local.create_investigation_function_arn &&
      jsondecode(aws_iam_role_policy.create_investigation_lambda_ecs.policy).Statement[1].Resource == [data.aws_iam_role.task.arn, data.aws_iam_role.execution.arn] &&
      jsondecode(aws_iam_role_policy.create_investigation_lambda_efs.policy).Statement[0].Resource == aws_efs_file_system.sre_home.arn &&
      jsondecode(aws_iam_role_policy.reap_tasks_lambda_ecs.policy).Statement[0].Condition.StringEquals["ecs:cluster"] == aws_ecs_cluster.main.arn &&
      jsondecode(aws_iam_role_policy.reap_tasks_lambda_ecs.policy).Statement[1].Resource == "arn:aws:ecs:us-east-1:123456789012:task/${aws_ecs_cluster.main.name}/*" &&
      jsondecode(aws_iam_role_policy.reap_tasks_lambda_ecs.policy).Statement[2].Condition["ForAnyValue:StringLike"]["ecs:ResourceTag/deadline"] == "*"
    )
    error_message = "Preserve exact Lambda invocation, PassRole, filesystem and deadline-reaper scopes."
  }
}

run "additional_region_names_cannot_collide_with_legacy_grants" {
  command = apply
  variables { aws_region = "us-west-2" }
  override_data {
    target = data.aws_region.current
    values = { region = "us-west-2", name = "us-west-2" }
  }
  assert {
    condition = toset([
      aws_iam_role_policy.execution_secrets.name, aws_iam_role_policy.task_s3.name,
      aws_iam_role_policy.task_bedrock.name, aws_iam_role_policy.task_ecs_exec.name,
      aws_iam_role_policy.task_ssm_logging.name, aws_iam_role_policy.task_kms.name,
      aws_iam_role_policy.sre_shared_ecs_exec.name, aws_iam_role_policy.lambda_invoker.name,
      aws_iam_role_policy.create_investigation_lambda_ecs.name, aws_iam_role_policy.create_investigation_lambda_efs.name,
      aws_iam_role_policy.reap_tasks_lambda_ecs.name, aws_iam_role_policy.bedrock_invocation_logging.name,
      aws_iam_role_policy.s3_replication[0].name
      ]) == toset([
      "secrets-manager-access-us-west-2", "s3-audit-access-us-west-2", "bedrock-access-us-west-2", "ecs-exec-access-us-west-2",
      "ssm-session-logging-us-west-2", "kms-exec-session-us-west-2", "ecs-exec-abac-us-west-2", "invoke-create-investigation-us-west-2",
      "ecs-task-management-us-west-2", "efs-access-point-management-us-west-2", "ecs-task-reaping-us-west-2",
      "write-model-invocations-us-west-2", "s3-replication-policy-us-west-2"
    ]) && data.aws_iam_role.task.name == "rosa-boundary-dev-task-role"
    error_message = "Additional regions share identities but must use distinct policy names for every regional grant."
  }
  assert {
    condition = (
      jsondecode(aws_iam_role_policy.execution_secrets.policy).Statement[0].Resource == "arn:aws:secretsmanager:us-west-2:123456789012:secret:rosa-boundary/*" &&
      jsondecode(aws_iam_role_policy.sre_shared_ecs_exec.policy).Statement[2].Resource == "arn:aws:ecs:us-west-2:123456789012:task/${aws_ecs_cluster.main.name}/*" &&
      jsondecode(aws_iam_role_policy.sre_shared_ecs_exec.policy).Statement[5].Resource == "arn:aws:elasticfilesystem:us-west-2:123456789012:access-point/*" &&
      jsondecode(aws_iam_role_policy.task_bedrock.policy).Statement[1].Resource == ["arn:aws:bedrock:us-west-2:123456789012:inference-profile/*", "arn:aws:bedrock:us-west-2:123456789012:application-inference-profile/*"]
    )
    error_message = "A second region must render its own scopes, never copy the legacy region's grants."
  }
}

run "legacy_owner_is_explicit_not_hardcoded" {
  command = plan
  variables {
    aws_region           = "us-west-2"
    legacy_policy_region = "us-west-2"
  }
  assert {
    condition     = aws_iam_role_policy.task_s3.name == "s3-audit-access" && local.regional_policy_suffix == ""
    error_message = "The designated legacy owner may be any AWS region; do not hardcode us-east-1."
  }
}

run "invalid_legacy_region_rejected" {
  command = plan
  variables { legacy_policy_region = "" }
  expect_failures = [var.legacy_policy_region]
}

run "custom_identity_contract_and_optional_replication" {
  command = plan
  variables {
    account_role_name_prefix     = "boundary-shared"
    audit_replication_bucket_arn = ""
    audit_replication_account_id = ""
  }
  assert {
    condition = (
      data.aws_iam_role.execution.name == "boundary-shared-execution-role" &&
      data.aws_iam_role.task.name == "boundary-shared-task-role" &&
      data.aws_iam_role.sre_shared.name == "boundary-shared-sre-shared" &&
      data.aws_iam_role.lambda_invoker.name == "boundary-shared-lambda-invoker" &&
      data.aws_iam_role.create_investigation_lambda.name == "boundary-shared-create-investigation-lambda" &&
      data.aws_iam_role.reap_tasks_lambda.name == "boundary-shared-reap-tasks-lambda" &&
      data.aws_iam_role.bedrock_invocation_logging.name == "boundary-shared-bedrock-invocation-logging" &&
      length(data.aws_iam_role.s3_replication) == 0 && length(aws_iam_role_policy.s3_replication) == 0
    )
    error_message = "Every regional lookup must honor the shared prefix contract; disabled regional replication adds no identity lookup or grant."
  }
}

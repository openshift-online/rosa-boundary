# Account state owns these roles and providers. Name-based lookups preserve the
# regional interface; this state owns regional grants, never role identities.
locals {
  account_role_name_prefix = var.account_role_name_prefix != "" ? var.account_role_name_prefix : "${var.project}-${var.stage}"
  # Designate exactly one legacy policy owner across every regional workspace.
  # Other regions cannot overwrite its inline policies on these shared roles.
  regional_policy_suffix = var.aws_region == var.legacy_policy_region ? "" : "-${var.aws_region}"
}

data "aws_iam_role" "execution" {
  name = "${local.account_role_name_prefix}-execution-role"
}
data "aws_iam_role" "task" {
  name = "${local.account_role_name_prefix}-task-role"
}
data "aws_iam_role" "sre_shared" {
  name = "${local.account_role_name_prefix}-sre-shared"
}
data "aws_iam_role" "lambda_invoker" {
  name = "${local.account_role_name_prefix}-lambda-invoker"
}
data "aws_iam_role" "create_investigation_lambda" {
  name = "${local.account_role_name_prefix}-create-investigation-lambda"
}
data "aws_iam_role" "reap_tasks_lambda" {
  name = "${local.account_role_name_prefix}-reap-tasks-lambda"
}
data "aws_iam_role" "bedrock_invocation_logging" {
  name = "${local.account_role_name_prefix}-bedrock-invocation-logging"
}
data "aws_iam_role" "s3_replication" {
  count = var.audit_replication_bucket_arn != "" ? 1 : 0
  name  = "${local.account_role_name_prefix}-s3-replication-role"
}

data "aws_iam_openid_connect_provider" "keycloak" {
  url = var.keycloak_issuer_url
}
data "aws_iam_openid_connect_provider" "stage_keycloak" {
  count = var.stage_keycloak_issuer_url != "" ? 1 : 0
  url   = var.stage_keycloak_issuer_url
}
data "aws_iam_openid_connect_provider" "prod_keycloak" {
  count = var.prod_keycloak_issuer_url != "" ? 1 : 0
  url   = var.prod_keycloak_issuer_url
}

# Optional adoption: identities, common attachments and account singletons only.
# Regional inline policies stay in their original state; never import them here.
import {
  for_each = var.adopt_existing_resources && var.enable_s3_replication_role ? { existing = true } : {}
  to       = module.shared_iam.aws_iam_role.s3_replication[0]
  id       = "${local.role_name_prefix}-s3-replication-role"
}
import {
  for_each = var.adopt_existing_resources ? { existing = true } : {}
  to       = module.shared_iam.aws_iam_role.execution
  id       = "${local.role_name_prefix}-execution-role"
}
import {
  for_each = var.adopt_existing_resources ? { existing = true } : {}
  to       = module.shared_iam.aws_iam_role_policy_attachment.execution_managed
  id       = "${local.role_name_prefix}-execution-role/arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
import {
  for_each = var.adopt_existing_resources ? { existing = true } : {}
  to       = module.shared_iam.aws_iam_role.task
  id       = "${local.role_name_prefix}-task-role"
}
import {
  for_each = var.adopt_existing_resources ? { existing = true } : {}
  to       = module.shared_iam.aws_iam_role.sre_shared
  id       = "${local.role_name_prefix}-sre-shared"
}
import {
  for_each = var.adopt_existing_resources ? { existing = true } : {}
  to       = module.shared_iam.aws_iam_role.lambda_invoker
  id       = "${local.role_name_prefix}-lambda-invoker"
}
import {
  for_each = var.adopt_existing_resources ? { existing = true } : {}
  to       = module.shared_iam.aws_iam_role.create_investigation_lambda
  id       = "${local.role_name_prefix}-create-investigation-lambda"
}
import {
  for_each = var.adopt_existing_resources ? { existing = true } : {}
  to       = module.shared_iam.aws_iam_role_policy_attachment.create_investigation_lambda_basic
  id       = "${local.role_name_prefix}-create-investigation-lambda/arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
import {
  for_each = var.adopt_existing_resources ? { existing = true } : {}
  to       = module.shared_iam.aws_iam_role.reap_tasks_lambda
  id       = "${local.role_name_prefix}-reap-tasks-lambda"
}
import {
  for_each = var.adopt_existing_resources ? { existing = true } : {}
  to       = module.shared_iam.aws_iam_role_policy_attachment.reap_tasks_lambda_basic
  id       = "${local.role_name_prefix}-reap-tasks-lambda/arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
import {
  for_each = var.adopt_existing_resources ? { existing = true } : {}
  to       = module.shared_iam.aws_iam_role.bedrock_invocation_logging
  id       = "${local.role_name_prefix}-bedrock-invocation-logging"
}
import {
  for_each = var.adopt_existing_resources ? { existing = true } : {}
  to       = aws_iam_openid_connect_provider.keycloak
  id       = "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:oidc-provider/${trimprefix(var.keycloak_issuer_url, "https://")}"
}
import {
  for_each = var.adopt_existing_resources && var.stage_keycloak_issuer_url != "" ? { existing = true } : {}
  to       = aws_iam_openid_connect_provider.stage_keycloak[0]
  id       = "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:oidc-provider/${trimprefix(var.stage_keycloak_issuer_url, "https://")}"
}
import {
  for_each = var.adopt_existing_resources && var.prod_keycloak_issuer_url != "" ? { existing = true } : {}
  to       = aws_iam_openid_connect_provider.prod_keycloak[0]
  id       = "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:oidc-provider/${trimprefix(var.prod_keycloak_issuer_url, "https://")}"
}
import {
  for_each = var.adopt_existing_resources ? { existing = true } : {}
  to       = aws_budgets_budget.bedrock
  id       = "${var.aws_account_id}:${var.project}-${var.stage}-bedrock-monthly"
}

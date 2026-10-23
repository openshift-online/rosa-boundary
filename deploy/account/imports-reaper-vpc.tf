# Temporary: migrate aws_iam_role_policy_attachment.reap_investigations_lambda_vpc from regional to account workspace.
# Once both workspaces apply successfully with zero changes, delete this file via a follow-up PR.

import {
  for_each = var.adopt_existing_resources ? { existing = true } : {}
  to       = module.shared_iam.aws_iam_role_policy_attachment.reap_investigations_lambda_vpc
  id       = "${local.role_name_prefix}-reap-investigations-lambda/arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

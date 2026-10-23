# Import VPC policy attachment from regional state migration
# This attachment was originally in deploy/regional but should be account-level
# because it's a shared permission, not region-specific.
#
# Guarded by var.adopt_existing_resources to allow fresh bootstrap deployments
# where the resource doesn't exist yet.
#
# After this import succeeds and both workspaces apply cleanly, this file can be deleted.

import {
  for_each = var.adopt_existing_resources ? { existing = true } : {}
  to       = module.shared_iam.aws_iam_role_policy_attachment.reap_investigations_lambda_vpc
  id       = "${local.role_name_prefix}-reap-investigations-lambda/arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

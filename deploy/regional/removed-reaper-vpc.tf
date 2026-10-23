# Temporary: migrate aws_iam_role_policy_attachment.reap_investigations_lambda_vpc from regional to account workspace.
# The resource is moved to deploy/account/modules/shared-iam/lambda-reap-investigations.tf.
# Once both workspaces apply successfully with zero changes, delete this file via a follow-up PR.

removed {
  from = aws_iam_role_policy_attachment.reap_investigations_lambda_vpc

  lifecycle {
    destroy = false
  }
}

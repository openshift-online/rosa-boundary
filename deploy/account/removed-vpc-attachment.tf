# Temporary: remove reap_investigations_lambda_vpc from state due to identity drift.
# The resource exists in AWS but Terraform detects drift (delete) during refresh because
# the identity block in state doesn't match. Removing it from state allows the import
# block in imports-reaper-vpc.tf to re-import it cleanly.
# Delete this file after the import completes successfully.

removed {
  from = module.shared_iam.aws_iam_role_policy_attachment.reap_investigations_lambda_vpc

  lifecycle {
    destroy = false
  }
}

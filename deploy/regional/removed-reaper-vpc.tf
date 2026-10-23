# Remove VPC policy attachment from regional state (moved to account workspace)
# The AWS resource is NOT destroyed - only removed from this workspace's state.
# This attachment is now managed in deploy/account/modules/shared-iam/
#
# After this removal succeeds and both workspaces apply cleanly, this file can be deleted.

removed {
  from = aws_iam_role_policy_attachment.reap_investigations_lambda_vpc

  lifecycle {
    destroy = false
  }
}

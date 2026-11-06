# ROSAENG-68823: optional identity for an external metrics collector.
#
# Identity and trust only. The permissions this role carries are an inline
# grant owned by the regional root, like every other grant on an account-owned
# role - see deploy/regional/iam.tf and the ownership table in README.md.
#
# Off by default. With enable_metrics_read_role = false nothing is created, and
# with it true but no caller named the plan fails rather than producing a role
# no one can assume.
#
# This is the only identity here assumed from outside the account, so its trust
# is an explicit allowlist of caller role ARNs - never an account root, never a
# wildcard, never a service principal.
#
# Activation is sequenced: this role must exist before the regional workspace
# can enable its grant, because the regional root looks the role up by name.
# Enabling both in one change is not safe; see README.md.
resource "aws_iam_role" "metrics_read" {
  count                = var.enable_metrics_read_role ? 1 : 0
  name                 = "${var.role_name_prefix}-metrics-read"
  description          = "Read-only CloudWatch metric access for an external metrics collector. Permissions are granted by the regional root."
  max_session_duration = var.metrics_read_session_duration

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = var.metrics_read_trusted_principal_arns }
    }]
  })

  lifecycle {
    precondition {
      condition     = length(var.metrics_read_trusted_principal_arns) > 0
      error_message = "metrics_read_trusted_principal_arns must name at least one caller when enable_metrics_read_role is true."
    }
  }

  tags = merge(local.common_tags, {
    Name = "${var.role_name_prefix}-metrics-read"
  })
}

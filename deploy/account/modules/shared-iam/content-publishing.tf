# Content publishing and replication identities.
#
# Identity and trust only. Like every other shared role here, the permissions
# these roles carry are owned by the regional root - see deploy/regional and
# the ownership table in README.md. Nothing in this file references a bucket,
# a KMS key, a region or another Terraform state.
#
# Publishers always exist for the configured sources. The dedicated content
# replication identity also always exists, independently of audit replication.
#
# This file attaches no permissions to either identity, and the content grants
# are a later regional change. Until those land, a role is assumable
# but holds no content access from this configuration. That is a statement
# about what is declared here, not a guarantee that no resource-based policy
# anywhere else in the account names the role: check the account if that
# matters. The interim is the intended fail-safe, as for the metrics reader.

locals {
  # Only the host part of the issuer, which is what IAM uses to prefix the
  # claim condition keys. Derived from the provider ARN rather than restated,
  # so the condition keys can never disagree with the trusted principal.
  github_actions_claim_prefix = var.github_actions_provider_arn != "" ? split("oidc-provider/", var.github_actions_provider_arn)[1] : ""
}

# One identity per source repository, never one shared identity for all three.
# Separate roles are what stops a compromised workflow in one repository from
# writing another repository's content once the regional grants exist.
#
# The subject is built from a fixed template, so no input can turn a branch
# ref into a pull-request, merge-ref or environment subject: validation rejects
# a value carrying its own ":" segment, a "*" or a full ref. Which repositories
# and branches are trusted is a different question - that is the configured
# source map, and changing it, to a fork or another branch, is a deliberate
# configuration change rather than something validation prevents. The defaults
# pin the three agreed sources, and the tests assert the rendered subject set.
# StringEquals, a scalar subject and a single fixed audience are the operator
# half of the boundary - do not relax any of them.
resource "aws_iam_role" "content_publisher" {
  for_each = var.content_publisher_sources

  name                 = "${var.role_name_prefix}-publisher-${each.key}"
  description          = "GitHub Actions content publisher for ${each.value.repository} on ${each.value.branch}. Permissions are granted by the regional root."
  max_session_duration = var.content_publisher_session_duration

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = var.github_actions_provider_arn }
      Condition = {
        StringEquals = {
          "${local.github_actions_claim_prefix}:aud" = var.github_actions_audience
          "${local.github_actions_claim_prefix}:sub" = "repo:${each.value.repository}:ref:refs/heads/${each.value.branch}"
        }
      }
    }]
  })

  lifecycle {
    precondition {
      condition     = var.github_actions_provider_arn != ""
      error_message = "github_actions_provider_arn must be set; the account root resolves it by creating or looking up the GitHub Actions OIDC provider."
    }
  }

  tags = merge(local.common_tags, {
    Name = "${var.role_name_prefix}-publisher-${each.key}"
  })
}

# A dedicated replication identity, separate from the audit replication role.
# Trust is S3 service only, with no condition, matching the audit role in
# iam.tf exactly; the two differ in name, description and tags alone. Adding a
# confused-deputy condition here that the deployed audit role does not have
# would create a failure mode that could only surface later, during the
# regional replication work. Harden both together, with live verification.
resource "aws_iam_role" "content_replication" {
  name        = "${var.role_name_prefix}-content-replication-role"
  description = "S3 replication for Boundary content buckets, separate from audit replication. Permissions are granted by the regional root."
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "s3.amazonaws.com" } }]
  })

  tags = merge(local.common_tags, {
    Name = "${var.role_name_prefix}-content-replication-role"
  })
}

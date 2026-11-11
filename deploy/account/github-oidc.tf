# The account's GitHub Actions OIDC provider.
#
# Account-global, like every other identity in this root: no bucket, key or
# regional resource is referenced, and no other Terraform state is read.
#
# An account may already have this provider, so three modes are supported and
# the account's own inventory decides which one applies:
#
#   create    create_github_actions_oidc_provider = true  (default)
#             This state creates and owns the provider.
#   reference create_github_actions_oidc_provider = false
#             The provider is looked up by issuer URL and NOT managed here.
#   adopt     create_github_actions_oidc_provider = true
#             and adopt_existing_resources = true
#             The existing provider is imported into this state.
#
# AWS allows one provider per issuer URL per account, so none of these can
# silently create a duplicate: the wrong mode fails loudly and without
# destroying anything. Choosing the mode, and reviewing that account's actual
# plan, are prerequisites of deploying the account root - see README.md.
locals {
  github_actions_issuer_url = "https://token.actions.githubusercontent.com"

  # IAM stores and addresses a provider by issuer host, without the scheme, so
  # the import ID and the condition keys both need this form. Derive it rather
  # than restating the host: a stale copy would adopt the wrong provider.
  github_actions_issuer_host = replace(local.github_actions_issuer_url, "https://", "")

  # Deliberately not a variable: the publisher trust
  # policies must not be able to accept a second or different audience.
  github_actions_audience = "sts.amazonaws.com"

  github_actions_provider_managed   = var.create_github_actions_oidc_provider
  github_actions_provider_looked_up = !var.create_github_actions_oidc_provider

  github_actions_provider_arn = (
    local.github_actions_provider_managed ? aws_iam_openid_connect_provider.github_actions[0].arn :
    data.aws_iam_openid_connect_provider.github_actions[0].arn
  )
}

# No thumbprint is pinned. The argument is optional and computed on the AWS
# provider this root uses, and AWS maintains the trust chain for this issuer,
# so pinning a rotating fingerprint would add a liability without adding a
# control. That is a statement about this configuration, not a prediction that
# adopting an existing provider in a given account produces an empty plan:
# review that account's plan before enabling.
resource "aws_iam_openid_connect_provider" "github_actions" {
  count          = local.github_actions_provider_managed ? 1 : 0
  url            = local.github_actions_issuer_url
  client_id_list = [local.github_actions_audience]
  tags = merge(var.tags, {
    Name = "${var.project}-${var.stage}-github-actions-oidc"
  })
}

# Reference mode: another owner keeps the provider; this state only reads it.
# In an account that has no such provider, this lookup fails the plan rather
# than creating one behind the operator's back.
data "aws_iam_openid_connect_provider" "github_actions" {
  count = local.github_actions_provider_looked_up ? 1 : 0
  url   = local.github_actions_issuer_url
}

# Adoption into this state, using the same declarative mechanism as the Bedrock
# model agreements. Inert unless adopt_existing_resources is enabled, which is
# the existing handoff switch and is off in every deployed workspace.
import {
  for_each = local.github_actions_provider_managed && var.adopt_existing_resources ? toset([0]) : toset([])
  to       = aws_iam_openid_connect_provider.github_actions[each.key]
  id       = "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:oidc-provider/${local.github_actions_issuer_host}"
}

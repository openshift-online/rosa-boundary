output "shared_roles" {
  description = "Account-global identities consumed by all regional roots via IAM data lookups."
  value       = module.shared_iam.roles
}

output "regional_iam_contract" {
  description = "Copy these two inputs to every regional root. Only legacy_policy_region uses unsuffixed inline policy names; every other region appends -<aws_region>. Grants are a union, not region isolation."
  value = {
    account_role_name_prefix = local.role_name_prefix
    legacy_policy_region     = var.legacy_policy_region
  }
}

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.keycloak.arn
}

output "bedrock_budget_name" {
  value = aws_budgets_budget.bedrock.name
}

# The stable contract downstream regional grants and publishing
# workflows consume. Role names and map keys do not change with configuration.
output "content_publisher_roles" {
  description = "Content publisher identities keyed by source key (ops-sop, managed-notifications, rosa-claude-plugins), each with its name, ARN, source repository, branch and exact trust subject."
  value       = module.shared_iam.content_publisher_roles
}

output "content_publisher_role_arns" {
  description = "Content publisher role ARNs keyed by source key. This is the value a publishing workflow assumes."
  value       = { for key, role in module.shared_iam.content_publisher_roles : key => role.arn }
}

output "content_replication_role_arn" {
  description = "ARN of the dedicated content replication identity, consumed by the regional content replication configuration."
  value       = module.shared_iam.content_replication_role.arn
}

output "github_actions_oidc_provider_arn" {
  description = "ARN of the account's GitHub Actions OIDC provider, whether this state created it or referenced an existing one, so consumers need not know which."
  value       = local.github_actions_provider_arn
}

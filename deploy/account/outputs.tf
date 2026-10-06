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

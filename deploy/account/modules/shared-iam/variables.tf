variable "project" { type = string }
variable "stage" { type = string }
variable "role_name_prefix" { type = string }
variable "tags" { type = map(string) }
variable "keycloak_provider_arn" { type = string }
variable "stage_keycloak_provider_arn" { type = string }
variable "prod_keycloak_provider_arn" { type = string }
variable "stage_keycloak_issuer_url" { type = string }
variable "prod_keycloak_issuer_url" { type = string }
variable "oidc_client_id" { type = string }
variable "stage_oidc_client_id" { type = string }
variable "prod_oidc_client_id" { type = string }
variable "oidc_session_duration" {
  type = number
  validation {
    condition     = var.oidc_session_duration >= 3600 && var.oidc_session_duration <= 43200
    error_message = "oidc_session_duration must be between 3600 and 43200 seconds."
  }
}
variable "enable_uuid_allowlist" { type = bool }
variable "allowed_uuids" {
  type = list(string)
  validation {
    condition     = alltrue([for uuid in var.allowed_uuids : can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", uuid))])
    error_message = "Each allowed_uuids entry must be a lowercase UUID."
  }
}
variable "enable_oidc_group_enforcement" { type = bool }
variable "required_oidc_role" {
  type = string
  validation {
    condition     = var.required_oidc_role == "" || length(trimspace(var.required_oidc_role)) > 0
    error_message = "required_oidc_role must not be blank when set."
  }
}
variable "legacy_role_tag_region" { type = string }
variable "bedrock_logging_source_regions" { type = list(string) }
variable "enable_s3_replication_role" { type = bool }
# ROSAENG-68823: external metrics collector identity. The matching permission
# grant is a separate, independently gated regional input.
variable "enable_metrics_read_role" { type = bool }
variable "metrics_read_session_duration" {
  type = number
  validation {
    condition     = var.metrics_read_session_duration >= 3600 && var.metrics_read_session_duration <= 43200
    error_message = "metrics_read_session_duration must be between 3600 and 43200 seconds."
  }
}
variable "metrics_read_trusted_principal_arns" {
  type = list(string)
  validation {
    condition     = alltrue([for arn in var.metrics_read_trusted_principal_arns : can(regex("^arn:aws[a-z0-9-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]+(/[A-Za-z0-9+=,.@_-]+)*$", arn)) || can(regex("^arn:aws[a-z0-9-]*:sts::[0-9]{12}:assumed-role/[A-Za-z0-9+=,.@_-]+/[A-Za-z0-9+=,.@_-]+$", arn))])
    error_message = "Each trusted caller must be a complete IAM role ARN (arn:aws:iam::<account-id>:role/<name>) or STS assumed-role session ARN. Account roots, service principals, partial names and wildcards are rejected. IAM itself rejects a partial wildcard such as role/*, but it ACCEPTS a bare * as an anonymous principal, which would make this role assumable by anyone in the partition: this validation is what prevents that."
  }
  validation {
    condition     = length(distinct(var.metrics_read_trusted_principal_arns)) == length(var.metrics_read_trusted_principal_arns)
    error_message = "metrics_read_trusted_principal_arns must not repeat a caller."
  }
}

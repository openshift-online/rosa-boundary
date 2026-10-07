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

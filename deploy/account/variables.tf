variable "aws_account_id" {
  description = "Target account; also guards the provider and defines import IDs."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "AWS account ID must be exactly 12 digits."
  }
}

variable "aws_region" {
  description = "Provider API endpoint region; retain the original endpoint for model activation. Regional permission scopes are owned by regional roots, not this provider."
  type        = string
}

variable "project" {
  type    = string
  default = "rosa-boundary"
}

variable "stage" {
  type    = string
  default = "dev"
  validation {
    condition     = contains(["dev", "stage", "prod"], var.stage)
    error_message = "Stage must be one of: dev, stage, prod."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "default_tags" {
  description = "Provider default tags; copy the original regional deployment's values."
  type        = map(string)
  default     = {}
}

variable "ignored_tag_keys" {
  type    = list(string)
  default = []
}

variable "adopt_existing_resources" {
  description = "Enable declarative imports during the existing regional-to-account state handoff only."
  type        = bool
  default     = false
}

variable "role_name_prefix" {
  description = "One shared identity prefix for all regional stacks. Empty preserves project-stage."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^[A-Za-z0-9_+=,.@-]{1,37}$", var.role_name_prefix != "" ? var.role_name_prefix : "${var.project}-${var.stage}"))
    error_message = "Role prefixes must use IAM name characters, with at most 37 characters."
  }
}

variable "legacy_policy_region" {
  description = "Exactly one regional state retains the legacy unsuffixed inline policy names. Copy to every regional root; do not change after migration without coordinated policy renames."
  type        = string
  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", var.legacy_policy_region))
    error_message = "legacy_policy_region must be an explicit AWS region name."
  }
}

variable "legacy_role_tag_region" {
  description = "Retain the original Region tag on shared roles; also the default Bedrock logging source region. This is not a regional resource dependency."
  type        = string
  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", var.legacy_role_tag_region))
    error_message = "legacy_role_tag_region must be an explicit AWS region name."
  }
}

variable "bedrock_logging_source_regions" {
  description = "Explicit source-region allowlist for shared Bedrock logging service trust. Empty retains only legacy_role_tag_region; include the legacy region when adding others."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for region in var.bedrock_logging_source_regions : can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", region))]) && length(distinct(var.bedrock_logging_source_regions)) == length(var.bedrock_logging_source_regions) && (length(var.bedrock_logging_source_regions) == 0 || contains(var.bedrock_logging_source_regions, var.legacy_role_tag_region))
    error_message = "Use unique, explicit AWS regions, never wildcards, and retain the legacy source region."
  }
}

variable "enable_s3_replication_role" {
  description = "Create the shared replication identity if any regional stack enables replication; no bucket ARN is needed. Keep enabled until all regional replication policies are removed."
  type        = bool
  default     = false
}

variable "oidc_session_duration" {
  type    = number
  default = 3600
}
variable "enable_uuid_allowlist" {
  type    = bool
  default = false
}
variable "allowed_uuids" {
  type    = list(string)
  default = []
}
variable "enable_oidc_group_enforcement" {
  type    = bool
  default = true
}
variable "required_oidc_role" {
  type    = string
  default = "ai-sd-sre"
}

variable "bedrock_budget_tag_region" {
  description = "Original budget's Region tag, explicitly retained although Budgets is account-global."
  type        = string
}

variable "bedrock_model_agreements" {
  description = "Original approved model-to-offer manifest; manage activation once per account using the original aws_region endpoint. Supply the same manifest to regional roots for default-model validation."
  type        = map(string)
  default     = {}
}

variable "bedrock_monthly_budget_usd" {
  description = "Copy the original monthly limit; notifications do not stop inference."
  type        = number
  validation {
    condition     = var.bedrock_monthly_budget_usd > 0
    error_message = "The Bedrock monthly budget must be greater than zero."
  }
}

variable "bedrock_budget_notification_email" {
  description = "Copy the original notification destination."
  type        = string
  validation {
    condition     = can(regex("^[^[:space:]@]+@[^[:space:]@]+\\.[^[:space:]@]+$", var.bedrock_budget_notification_email))
    error_message = "The Bedrock budget notification destination must be an email address."
  }
}

variable "keycloak_issuer_url" {
  type = string
}

variable "keycloak_thumbprint" {
  type      = string
  sensitive = true
}

variable "oidc_client_id" {
  type    = string
  default = "rosa-boundary-sre"
}

variable "stage_keycloak_issuer_url" {
  type    = string
  default = ""
}

variable "stage_keycloak_thumbprint" {
  type    = string
  default = ""
}

variable "stage_oidc_client_id" {
  type    = string
  default = ""
}

variable "prod_keycloak_issuer_url" {
  type    = string
  default = ""
}

variable "prod_keycloak_thumbprint" {
  type    = string
  default = ""
}

variable "prod_oidc_client_id" {
  type    = string
  default = ""
}

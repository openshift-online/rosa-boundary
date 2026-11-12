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

variable "enable_lambda_ecr_source" {
  description = "Create the ordinary Lambda publication source in this account/region; does not change any deployed Lambda or configure replication."
  type        = bool
  default     = false
}

# Transitional input: PR plans can run before the meta-workspace renames its
# existing HCP variable. Remove only after both account workspaces have applied
# the generic replication input and no callers supply this legacy value.
variable "lambda_ecr_replication_regions" {
  description = "Deprecated migration fallback. Use replication; if both inputs are supplied their destination Regions must match."
  type        = list(string)
  default     = []

  validation {
    condition = (
      length(distinct(var.lambda_ecr_replication_regions)) == length(var.lambda_ecr_replication_regions) &&
      alltrue([for region in var.lambda_ecr_replication_regions : can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", region)) && region != var.aws_region])
    )
    error_message = "Legacy replication destinations must be unique explicit Regions other than aws_region."
  }

  validation {
    condition     = var.replication == null || length(var.lambda_ecr_replication_regions) == 0 ? true : toset(var.lambda_ecr_replication_regions) == toset(keys(var.replication.destinations))
    error_message = "Legacy lambda_ecr_replication_regions must match replication destination keys during migration; independent ECR/S3 Region choices are not supported."
  }
}

variable "replication" {
  description = "Shared ECR and published-content S3 topology. Pass the same value to the account and regional roots. Null disables replication; destination keys select ECR Regions, and optional content metadata activates S3 after destination bootstrap."
  type = object({
    primary_region = string
    destinations = map(object({
      content = optional(object({
        bucket_arn       = string
        kms_key_arn      = string
        content_prefixes = map(string)
      }))
    }))
  })
  default = null

  validation {
    condition = var.replication == null ? true : (
      can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", var.replication.primary_region)) &&
      alltrue([for region in keys(var.replication.destinations) : can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", region)) && region != var.replication.primary_region])
    )
    error_message = "Replication requires explicit AWS Regions and destinations other than primary_region."
  }

  validation {
    condition     = var.replication == null ? true : var.replication.primary_region == var.aws_region
    error_message = "The account provider aws_region must equal replication.primary_region; changing the provider endpoint is a coordinated migration."
  }
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
    condition     = can(regex("^[A-Za-z0-9_+=,.@-]{1,36}$", var.role_name_prefix != "" ? var.role_name_prefix : "${var.project}-${var.stage}"))
    error_message = "Role prefixes must use IAM name characters, with at most 36 characters."
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

# ROSAENG-68823
variable "enable_metrics_read_role" {
  description = "Create the identity an external metrics collector assumes to read this account's CloudWatch metrics. Identity and trust only: the permissions come from the regional root's enable_metrics_read_grant, which must be enabled in a later, separate apply because it looks this role up by name."
  type        = bool
  default     = false
}

variable "metrics_read_trusted_principal_arns" {
  description = "Callers allowed to assume the metrics-read role. Prefer a complete IAM role ARN, arn:aws:iam::<caller-account-id>:role/<caller-role>. An STS assumed-role session ARN is also accepted but pins trust to one session name and breaks silently if the caller renames its sessions. Account roots, service principals and wildcards are rejected. An empty list with enable_metrics_read_role = true fails the plan rather than creating a role nobody can assume."
  type        = list(string)
  default     = []
}

variable "metrics_read_session_duration" {
  description = "Maximum session duration in seconds for the metrics-read role. A collector refreshes often and needs no long session."
  type        = number
  default     = 3600
}

variable "create_github_actions_oidc_provider" {
  description = "Create and own the GitHub Actions OIDC provider in this state. Set false to reference a provider another state owns, looked up by issuer URL. Combine with adopt_existing_resources to import an existing provider instead. Check the account's actual providers, and review its plan, before enabling."
  type        = bool
  default     = true
}

variable "content_publisher_sources" {
  description = "Source repositories that may publish content, keyed by a stable short identifier used in the role name and the outputs. Each branch is a plain default-branch name, not a ref: the trust subject is built as repo:<repository>:ref:refs/heads/<branch>. Note rosa-claude-plugins uses main while the other two use master. Validation constrains syntax: wildcards, colons, full refs and empty values are rejected, so no input can become a pull-request, merge-ref or environment subject. It does not restrict which owner, repository or branch you configure - changing those is a deliberate, reviewable change, and these defaults are what pin the three agreed sources."
  type = map(object({
    repository = string
    branch     = string
  }))
  default = {
    ops-sop               = { repository = "openshift/ops-sop", branch = "master" }
    managed-notifications = { repository = "openshift/managed-notifications", branch = "master" }
    rosa-claude-plugins   = { repository = "openshift-online/rosa-claude-plugins", branch = "main" }
  }
}

variable "content_publisher_session_duration" {
  description = "Maximum session duration in seconds for the content publisher roles. A publishing workflow is short-lived and needs no long session."
  type        = number
  default     = 3600
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

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
# Content publishing and replication identities. Identity and
# trust only; the matching grants are separate regional inputs.
# Resolved by the account root, which always creates or looks up the provider.
# A resource precondition rejects a module that was not given one.
variable "github_actions_provider_arn" { type = string }
# The same audience the account root puts in the provider's client ID list.
# Passed in rather than restated here so the provider and the trust policies
# cannot drift apart; there is deliberately no account-root variable for it, so
# a workspace cannot widen the audience.
variable "github_actions_audience" {
  type = string
  validation {
    condition     = var.github_actions_audience != "" && !strcontains(var.github_actions_audience, "*")
    error_message = "github_actions_audience must be a non-empty exact audience."
  }
}
variable "content_publisher_session_duration" {
  type = number
  validation {
    condition     = var.content_publisher_session_duration >= 3600 && var.content_publisher_session_duration <= 43200
    error_message = "content_publisher_session_duration must be between 3600 and 43200 seconds."
  }
}
variable "content_publisher_sources" {
  type = map(object({
    repository = string
    branch     = string
  }))
  # The subject is built as repo:<repository>:ref:refs/heads/<branch>, so these
  # rules constrain SYNTAX, not which repositories are trusted. They stop a
  # value from carrying its own ":" segment or a "*", which is what would turn
  # one input into a pull-request, environment or wildcard subject. They do not
  # - and are not meant to - stop someone changing owner/name or branch: that
  # is a deliberate configuration change, reviewed like any other, and the
  # defaults are what pin the three agreed sources.
  #
  # Rejecting "*" is defence in depth rather than the primary control. Under
  # StringEquals, which this module always emits, a "*" in the value is a
  # literal character and matches no real token, so such a subject would be
  # inert rather than broad. The validation matters because it keeps a stored
  # value from becoming a live wildcard if the operator were ever changed to
  # StringLike, where "*" and "?" are metacharacters.
  validation {
    condition = alltrue([
      for key, source in var.content_publisher_sources :
      can(regex("^[a-z0-9][a-z0-9-]{0,20}$", key)) &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$", source.repository)) &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]*$", source.branch)) &&
      !startswith(source.branch, "refs/")
    ])
    error_message = "Each source key must be at most 21 lowercase alphanumeric/hyphen characters, each repository exactly owner/name, and each branch a plain branch name. Wildcards, colons, whitespace, empty values and full refs such as refs/heads/master or refs/pull/1/merge are rejected."
  }
  validation {
    condition     = length(distinct([for source in var.content_publisher_sources : "${source.repository}:${source.branch}"])) == length(var.content_publisher_sources)
    error_message = "content_publisher_sources must not map two keys to the same repository and branch."
  }
  validation {
    condition     = length(var.content_publisher_sources) > 0
    error_message = "content_publisher_sources must name at least one source."
  }
  validation {
    condition     = alltrue([for key, source in var.content_publisher_sources : length("${var.role_name_prefix}-publisher-${key}") <= 64])
    error_message = "Each publisher role name must fit the 64-character IAM limit; shorten the source key or the role prefix."
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

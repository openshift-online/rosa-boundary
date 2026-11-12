variable "notification_url" {
  type      = string
  default   = null
  sensitive = true
}

variable "ocm_client_id" {
  type      = string
  sensitive = true
}

variable "backplane_client_id" {
  type      = string
  sensitive = true
}


variable "ocm_client_secret" {
  type      = string
  sensitive = true
}

variable "backplane_client_secret" {
  type      = string
  sensitive = true
}

variable "aws_region" {
  description = "Deployment AWS region — interpolated into the regional workspace's app_config (actions.aws_allowed_regions) and set as its aws_region workspace variable."
  type        = string
  default     = "us-east-1"
}

# tflint-ignore: terraform_unused_declarations
variable "_deletion_approvals" {
  type = list(object({
    address    = string
    expires_at = string
  }))
  default = []
}

# Aurora master password. Authored in Vault — this root only passes it through
# to the regional workspace. See docs/database-and-compute.md.
variable "db_password" {
  type      = string
  sensitive = true
}

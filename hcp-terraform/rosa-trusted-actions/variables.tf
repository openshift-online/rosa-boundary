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
  description = "Deployment AWS region — set as the regional workspace's aws_region workspace variable."
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

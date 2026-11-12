variable "notification_url" {
  type      = string
  default   = null
  sensitive = true
}

# tflint-ignore: terraform_unused_declarations
variable "_deletion_approvals" {
  description = "Short-lived approvals for resource deletions evaluated by the rosa-deletion-protection OPA policy."
  type = list(object({
    address    = string
    expires_at = string
    reason     = optional(string)
  }))
  default = []
}

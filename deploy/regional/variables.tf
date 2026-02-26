variable "project" {
  description = "Project name (used in resource naming)"
  type        = string
  default     = "rosa-boundary"
}

variable "stage" {
  description = "Environment stage (e.g., dev, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.stage)
    error_message = "Stage must be one of: dev, staging, prod"
  }
}

variable "retention_days" {
  description = "Retention period in days (must be valid for both S3 Object Lock and CloudWatch Logs)"
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.retention_days)
    error_message = "Retention days must be a valid CloudWatch Logs retention period"
  }
}

variable "container_image" {
  description = "Container image URI for rosa-boundary"
  type        = string
}

variable "container_cpu" {
  description = "CPU units for the Fargate task (256, 512, 1024, 2048, 4096)"
  type        = number
  default     = 1024

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096], var.container_cpu)
    error_message = "CPU must be one of: 256, 512, 1024, 2048, 4096"
  }
}

variable "container_memory" {
  description = "Memory (MB) for the Fargate task"
  type        = number
  default     = 2048

  validation {
    condition     = var.container_memory >= 512 && var.container_memory <= 30720
    error_message = "Memory must be between 512 MB and 30720 MB (30 GB)"
  }
}

variable "kube_proxy_port" {
  description = "Port the kube-proxy sidecar listens on (localhost only)"
  type        = number
  default     = 8001
}

variable "vpc_id" {
  description = "VPC ID where Fargate tasks will run"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for Fargate tasks and EFS mount targets (must be in same VPC)"
  type        = list(string)

  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "At least 2 subnets are required for high availability"
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 7

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention must be a valid CloudWatch Logs retention period"
  }
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "keycloak_issuer_url" {
  description = "Keycloak OIDC issuer URL (e.g., https://keycloak.example.com/realms/sre-ops)"
  type        = string
}

variable "keycloak_thumbprint" {
  description = "SHA1 thumbprint of Keycloak TLS certificate"
  type        = string
  sensitive   = true
}

variable "oidc_client_id" {
  description = "Keycloak client ID for AWS integration"
  type        = string
  default     = "aws-sre-access"
}

variable "oidc_session_duration" {
  description = "Max session duration for OIDC role (seconds)"
  type        = number
  default     = 3600 # 1 hour
}

variable "task_timeout_default" {
  description = "Default task timeout in seconds (0 = no timeout)"
  type        = number
  default     = 3600

  validation {
    condition     = var.task_timeout_default >= 0 && var.task_timeout_default <= 86400
    error_message = "Task timeout must be between 0 and 86400 seconds (24 hours)"
  }
}

variable "audit_replication_bucket_arn" {
  description = "ARN of the destination S3 bucket in the audit account for cross-account replication. If empty, replication is disabled."
  type        = string
  default     = ""
}

variable "audit_replication_account_id" {
  description = "AWS account ID of the audit account that owns the replication destination bucket. Required when audit_replication_bucket_arn is set."
  type        = string
  default     = ""

  validation {
    condition     = var.audit_replication_bucket_arn == "" || var.audit_replication_account_id != ""
    error_message = "audit_replication_account_id is required when audit_replication_bucket_arn is set."
  }
}

variable "reaper_schedule_minutes" {
  description = "How often the task reaper Lambda runs (in minutes)"
  type        = number
  default     = 15

  validation {
    condition     = var.reaper_schedule_minutes >= 1 && var.reaper_schedule_minutes <= 1440
    error_message = "Reaper schedule must be between 1 and 1440 minutes (24 hours)"
  }
}

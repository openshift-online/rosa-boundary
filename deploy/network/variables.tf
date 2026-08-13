variable "aws_account_id" {
  description = "AWS account ID used as a provider deployment guard via allowed_account_ids"
  type        = string
  default     = "150100906299"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "AWS account ID must be exactly 12 digits."
  }
}

variable "aws_region" {
  description = "AWS region for all network resources"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "Must be a valid AWS region identifier (e.g., us-east-1)."
  }
}

variable "project" {
  description = "Project name (used in resource naming)"
  type        = string
  default     = "rosa-boundary"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*$", var.project))
    error_message = "Project must start with a lowercase letter and contain only lowercase letters, digits, and hyphens."
  }
}

variable "stage" {
  description = "Environment stage (used in resource naming)"
  type        = string
  default     = "stage"

  validation {
    condition     = contains(["dev", "stage", "prod"], var.stage)
    error_message = "Stage must be one of: dev, stage, prod."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.80.0.0/20"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be a valid IPv4 CIDR block (e.g., 10.80.0.0/20)."
  }
}

variable "availability_zones" {
  description = "Availability zones for subnet placement (one public and one private subnet per AZ)"
  type        = list(string)
  default = [
    "us-east-1a",
    "us-east-1b",
  ]

  validation {
    condition     = length(var.availability_zones) >= 2
    error_message = "At least 2 availability zones are required."
  }

  validation {
    condition = (
      length(var.availability_zones) == length(var.public_subnet_cidrs) &&
      length(var.availability_zones) == length(var.private_subnet_cidrs)
    )
    error_message = "The number of availability_zones, public_subnet_cidrs, and private_subnet_cidrs must be equal."
  }

  validation {
    condition = alltrue([
      for az in var.availability_zones : startswith(az, var.aws_region)
    ])
    error_message = "All availability_zones must be in the configured aws_region."
  }
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (one per AZ)"
  type        = list(string)
  default = [
    "10.80.0.0/24",
    "10.80.1.0/24",
  ]

  validation {
    condition     = length(var.public_subnet_cidrs) >= 2
    error_message = "At least 2 public subnet CIDRs are required."
  }

  validation {
    condition     = alltrue([for cidr in var.public_subnet_cidrs : can(cidrnetmask(cidr))])
    error_message = "All public_subnet_cidrs must be valid IPv4 CIDR blocks."
  }
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (one per AZ)"
  type        = list(string)
  default = [
    "10.80.8.0/24",
    "10.80.9.0/24",
  ]

  validation {
    condition     = length(var.private_subnet_cidrs) >= 2
    error_message = "At least 2 private subnet CIDRs are required."
  }

  validation {
    condition     = alltrue([for cidr in var.private_subnet_cidrs : can(cidrnetmask(cidr))])
    error_message = "All private_subnet_cidrs must be valid IPv4 CIDR blocks."
  }

  validation {
    condition = (
      length(var.public_subnet_cidrs) == length(toset(var.public_subnet_cidrs)) &&
      length(var.private_subnet_cidrs) == length(toset(var.private_subnet_cidrs)) &&
      length(setintersection(toset(var.public_subnet_cidrs), toset(var.private_subnet_cidrs))) == 0
    )
    error_message = "Subnet CIDRs must be unique within and across public and private lists."
  }
}

variable "nat_strategy" {
  description = "NAT gateway deployment: one_per_az for HA (one NAT per AZ), single for cost-optimized (shared NAT in first AZ)"
  type        = string
  default     = "single"

  validation {
    condition     = contains(["one_per_az", "single"], var.nat_strategy)
    error_message = "NAT strategy must be one_per_az or single."
  }
}

variable "additional_tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# tflint-ignore: terraform_unused_declarations
variable "_deletion_approvals" {
  description = "Time-limited deletion approvals for the rosa-deletion-protection OPA policy. Each entry must specify the full Terraform resource address and an RFC 3339 expiration timestamp. The reason field is not evaluated by the policy but serves as inline documentation."
  type = list(object({
    address    = string
    expires_at = string
    reason     = optional(string)
  }))
  default = []
}

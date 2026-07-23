variable "aws_account_id" {
  description = "AWS account ID used as a provider deployment guard via allowed_account_ids"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "AWS account ID must be exactly 12 digits."
  }
}

variable "aws_region" {
  description = "AWS region for all network resources"
  type        = string

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
  description = "Environment stage (e.g., dev, staging, prod)"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.stage)
    error_message = "Stage must be one of: dev, staging, prod."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC. Must be approved and non-overlapping with Backplane/VPN ranges."
  type        = string

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid CIDR block (e.g., 10.1.0.0/16)."
  }
}

variable "availability_zones" {
  description = "Availability zones for subnet placement. One public and one private subnet is created per AZ."
  type        = list(string)

  validation {
    condition     = length(var.availability_zones) >= 2
    error_message = "At least 2 availability zones are required for high availability."
  }
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (one per AZ, must match length of availability_zones)"
  type        = list(string)

  validation {
    condition     = length(var.public_subnet_cidrs) >= 2
    error_message = "At least 2 public subnet CIDRs are required."
  }

  validation {
    condition     = alltrue([for cidr in var.public_subnet_cidrs : can(cidrhost(cidr, 0))])
    error_message = "All public_subnet_cidrs must be valid CIDR blocks."
  }
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (one per AZ, must match length of availability_zones)"
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_cidrs) >= 2
    error_message = "At least 2 private subnet CIDRs are required."
  }

  validation {
    condition     = alltrue([for cidr in var.private_subnet_cidrs : can(cidrhost(cidr, 0))])
    error_message = "All private_subnet_cidrs must be valid CIDR blocks."
  }
}

variable "nat_strategy" {
  description = "NAT gateway deployment strategy: one_per_az for HA (one NAT per AZ), single for cost-optimized (shared NAT in first AZ)"
  type        = string
  default     = "one_per_az"

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

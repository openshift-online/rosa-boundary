terraform {
  required_version = ">= 1.13.4"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.aws_account_id]
}

check "subnet_cidr_count_match" {
  assert {
    condition = (
      length(var.availability_zones) == length(var.public_subnet_cidrs) &&
      length(var.availability_zones) == length(var.private_subnet_cidrs)
    )
    error_message = "The number of availability_zones, public_subnet_cidrs, and private_subnet_cidrs must be equal."
  }
}

check "no_duplicate_subnet_cidrs" {
  assert {
    condition = (
      length(var.public_subnet_cidrs) == length(toset(var.public_subnet_cidrs)) &&
      length(var.private_subnet_cidrs) == length(toset(var.private_subnet_cidrs)) &&
      length(setintersection(toset(var.public_subnet_cidrs), toset(var.private_subnet_cidrs))) == 0
    )
    error_message = "Subnet CIDRs must be unique within and across public and private lists."
  }
}

check "availability_zones_match_region" {
  assert {
    condition = alltrue([
      for az in var.availability_zones : startswith(az, var.aws_region)
    ])
    error_message = "All availability_zones must be in the configured aws_region."
  }
}

locals {
  name_prefix = "${var.project}-${var.stage}"

  nat_count = var.nat_strategy == "one_per_az" ? length(var.availability_zones) : 1

  common_tags = merge(var.additional_tags, {
    Project   = var.project
    Stage     = var.stage
    Region    = var.aws_region
    ManagedBy = "Terraform"
  })
}

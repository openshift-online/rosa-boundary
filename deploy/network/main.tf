terraform {
  required_version = "1.16.0"

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

  default_tags {
    tags = var.default_tags
  }

  # Tags managed outside this deployment, excluded from reconciliation.
  ignore_tags {
    keys = var.ignored_tag_keys
  }
}

data "aws_region" "current" {}

locals {
  name_prefix = "${var.project}-${var.stage}"

  nat_count = var.nat_strategy == "one_per_az" ? length(var.availability_zones) : 1

  common_tags = merge(var.additional_tags, {
    Project   = var.project
    Stage     = var.stage
    Region    = data.aws_region.current.region
    ManagedBy = "Terraform"
  })
}

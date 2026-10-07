terraform {
  required_version = ">= 1.15, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  common_tags = merge(var.tags, {
    Project   = var.project
    Stage     = var.stage
    Region    = var.legacy_role_tag_region
    ManagedBy = "Terraform"
  })
}

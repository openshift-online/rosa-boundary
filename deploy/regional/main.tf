terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Look up route tables for provided subnets to validate outbound connectivity
data "aws_route_table" "subnet" {
  count     = length(var.subnet_ids)
  subnet_id = var.subnet_ids[count.index]
}

# Local values for naming convention
locals {
  bucket_name = "${data.aws_caller_identity.current.account_id}-${var.project}-${var.stage}-${data.aws_region.current.name}"

  common_tags = merge(var.tags, {
    Project   = var.project
    Stage     = var.stage
    Region    = data.aws_region.current.name
    ManagedBy = "Terraform"
  })
}

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

# Look up route tables for provided subnets to validate outbound connectivity.
# Uses aws_route_tables (plural) to detect explicit associations per subnet,
# falling back to the VPC main route table for subnets without one.
data "aws_route_table" "main" {
  vpc_id = var.vpc_id

  filter {
    name   = "association.main"
    values = ["true"]
  }
}

data "aws_route_tables" "subnet" {
  count = length(var.subnet_ids)

  filter {
    name   = "association.subnet-id"
    values = [var.subnet_ids[count.index]]
  }
}

data "aws_route_table" "subnet" {
  count          = length(var.subnet_ids)
  route_table_id = length(data.aws_route_tables.subnet[count.index].ids) > 0 ? data.aws_route_tables.subnet[count.index].ids[0] : data.aws_route_table.main.id
}

# Validate that all subnets have outbound routing for Fargate ECR access
check "subnet_outbound_routing" {
  assert {
    condition = alltrue([
      for rt in data.aws_route_table.subnet : anytrue([
        for route in rt.routes :
          route.cidr_block == "0.0.0.0/0" &&
          (route.nat_gateway_id != "" || route.gateway_id != "")
      ])
    ])
    error_message = "One or more subnets in subnet_ids lack a default route (0.0.0.0/0) via a NAT gateway or internet gateway. Fargate tasks in these subnets cannot reach ECR. Verify route table associations for each subnet."
  }
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

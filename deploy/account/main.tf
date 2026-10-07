# Public registry hashicorp/aws; constraints match deploy/regional.
terraform {
  required_version = ">= 1.15, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# IAM and Budgets are account-global. Identity creation has no dependency on
# regional resources, resource ARNs, or another Terraform state.
provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.aws_account_id]
  default_tags {
    tags = var.default_tags
  }
  ignore_tags {
    keys = var.ignored_tag_keys
  }
}

data "aws_partition" "current" {}

locals {
  common_tags = merge(var.tags, {
    Project   = var.project
    Stage     = var.stage
    Region    = var.bedrock_budget_tag_region
    ManagedBy = "Terraform"
  })
}

locals {
  role_name_prefix = var.role_name_prefix != "" ? var.role_name_prefix : "${var.project}-${var.stage}"
}

# One shared identity set. Do not configure inline_policy, managed_policy_arns,
# or exclusive assignment resources: regional states augment these roles.
module "shared_iam" {
  source = "./modules/shared-iam"

  project                        = var.project
  stage                          = var.stage
  legacy_role_tag_region         = var.legacy_role_tag_region
  bedrock_logging_source_regions = length(var.bedrock_logging_source_regions) > 0 ? var.bedrock_logging_source_regions : [var.legacy_role_tag_region]
  role_name_prefix               = local.role_name_prefix
  tags                           = var.tags
  enable_s3_replication_role     = var.enable_s3_replication_role
  keycloak_provider_arn          = aws_iam_openid_connect_provider.keycloak.arn
  stage_keycloak_provider_arn    = var.stage_keycloak_issuer_url != "" ? aws_iam_openid_connect_provider.stage_keycloak[0].arn : ""
  prod_keycloak_provider_arn     = var.prod_keycloak_issuer_url != "" ? aws_iam_openid_connect_provider.prod_keycloak[0].arn : ""
  stage_keycloak_issuer_url      = var.stage_keycloak_issuer_url
  prod_keycloak_issuer_url       = var.prod_keycloak_issuer_url
  oidc_client_id                 = var.oidc_client_id
  stage_oidc_client_id           = var.stage_oidc_client_id
  prod_oidc_client_id            = var.prod_oidc_client_id
  oidc_session_duration          = var.oidc_session_duration
  enable_uuid_allowlist          = var.enable_uuid_allowlist
  allowed_uuids                  = var.allowed_uuids
  enable_oidc_group_enforcement  = var.enable_oidc_group_enforcement
  required_oidc_role             = var.required_oidc_role
}

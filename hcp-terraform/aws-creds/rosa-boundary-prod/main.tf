terraform {
  required_version = ">= 1.15, < 2.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    tfe = {
      source  = "hashicorp/tfe"
      version = "0.82.0"
    }
  }
}

# IAM/OIDC resources are account-scoped, not region-specific.
provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["514903006123"]
}

provider "tfe" {
  organization = "hp-platform-engineering"
}

module "aws_dynamic_creds" {
  source  = "app.terraform.io/hp-platform-engineering/aws-dynamic-creds/tfe"
  version = "0.0.15"

  organization     = "hp-platform-engineering"
  aws_account_name = "rosa-boundary-prod"

  role_groups = {
    default = {
      projects = {
        rosa-boundary = {
          # Authorize workload workspaces separately after registration.
          workspace_names = [
            "rosa-boundary-prod-aws-creds",
            "rosa-boundary-prod-account",
            "rosa-boundary-prod-network-us-east-1",
            "rosa-boundary-prod-regional-us-east-1",
          ]
        }
      }
    }
  }
}

data "aws_caller_identity" "current" {}

output "account_id" {
  description = "AWS account ID confirmed by the provider"
  value       = data.aws_caller_identity.current.account_id
}

output "caller_arn" {
  description = "ARN of the identity used for the bootstrap apply"
  value       = data.aws_caller_identity.current.arn
}

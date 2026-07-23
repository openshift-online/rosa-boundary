terraform {
  required_version = "1.15.8"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    tfe = {
      source  = "hashicorp/tfe"
      version = "0.79.0"
    }
  }
}

provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["150100906299"]
}

provider "tfe" {
  organization = "hp-platform-engineering"
}

module "aws_dynamic_creds" {
  source  = "app.terraform.io/hp-platform-engineering/aws-dynamic-creds/tfe"
  version = "0.0.14"

  organization     = "hp-platform-engineering"
  aws_account_name = "rosa-boundary-stage"

  role_groups = {
    default = {
      projects = {
        rosa-boundary = {
          workspace_names = [
            "rosa-boundary-stage-aws-creds",
            "rosa-boundary-stage-network",
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

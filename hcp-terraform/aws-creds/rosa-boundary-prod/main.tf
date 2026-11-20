terraform {
  required_version = ">= 1.15, < 2.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    tfe = {
      source  = "hashicorp/tfe"
      version = "0.83.0"
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
            "rosa-boundary-prod-network-us-west-2",
            "rosa-boundary-prod-regional-us-west-2",
          ]
        }
      }
    }

    rosa-trusted-actions = {
      plan_role_policy_arns = [
        "arn:aws:iam::aws:policy/ReadOnlyAccess",
        aws_iam_policy.rosa_trusted_actions_plan_secrets.arn,
      ]
      projects = {
        rosa-trusted-actions = {
          workspace_names = [
            "rosa-trusted-actions-prod-global",
            "rosa-trusted-actions-prod",
          ]
        }
      }
    }
  }
}

resource "aws_iam_policy" "rosa_trusted_actions_plan_secrets" {
  name        = "rosa-trusted-actions-plan-read-secret"
  description = "Lets the rosa-trusted-actions prod plan role read its own Secrets Manager secret version during terraform plan/refresh."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = ["arn:aws:secretsmanager:us-east-1:514903006123:secret:rosa-trusted-actions/ta-??????"]
    }]
  })
}

data "aws_caller_identity" "current" {}

output "account_id" {
  description = "AWS account ID confirmed by the provider"
  value       = data.aws_caller_identity.current.account_id
}

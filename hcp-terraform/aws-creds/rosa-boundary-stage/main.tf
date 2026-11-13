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

provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["150100906299"]
}

provider "tfe" {
  organization = "hp-platform-engineering"
}

module "aws_dynamic_creds" {
  source  = "app.terraform.io/hp-platform-engineering/aws-dynamic-creds/tfe"
  version = "0.0.15"

  organization     = "hp-platform-engineering"
  aws_account_name = "rosa-boundary-stage"

  role_groups = {
    default = {
      projects = {
        rosa-boundary = {
          workspace_names = [
            "rosa-boundary-stage-aws-creds",
            "rosa-boundary-stage-account",
            "rosa-boundary-stage-network",
            "rosa-boundary-stage-network-us-west-2",
            "rosa-boundary-stage-regional",
            "rosa-boundary-stage-regional-us-west-2",
          ]
        }
      }
    }

    # Separate from "default" so rosa-trusted-actions' plan role can carry a
    # permission the shared ReadOnlyAccess policy deliberately excludes,
    # without widening rosa-boundary's own plan role to match. apply role
    # keeps the module default (AdministratorAccess) -- rosa-trusted-actions/
    # terraform/ only needs a plan-phase addition, not an apply-phase one.
    rosa-trusted-actions = {
      plan_role_policy_arns = [
        "arn:aws:iam::aws:policy/ReadOnlyAccess",
        aws_iam_policy.rosa_trusted_actions_plan_secrets.arn,
      ]
      projects = {
        rosa-trusted-actions = {
          workspace_names = [
            "rosa-trusted-actions-global",
            "rosa-trusted-actions-stage",
          ]
        }
      }
    }
  }
}

# ReadOnlyAccess intentionally excludes secretsmanager:GetSecretValue.
# terraform/global/secrets.tf's aws_secretsmanager_secret_version.app is read
# on every plan/refresh regardless of its lifecycle.ignore_changes (that only
# suppresses the diff, not the read), so the plan role needs this explicitly.
resource "aws_iam_policy" "rosa_trusted_actions_plan_secrets" {
  name        = "rosa-trusted-actions-plan-read-secret"
  description = "Lets the rosa-trusted-actions plan role read its own Secrets Manager secret version during terraform plan/refresh."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = ["arn:aws:secretsmanager:us-east-1:150100906299:secret:rosa-trusted-actions/ta-??????"]
    }]
  })
}

data "aws_caller_identity" "current" {}

output "account_id" {
  description = "AWS account ID confirmed by the provider"
  value       = data.aws_caller_identity.current.account_id
}

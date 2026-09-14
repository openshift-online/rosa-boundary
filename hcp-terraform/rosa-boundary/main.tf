terraform {
  required_version = ">= 1.15, < 2.0"

  required_providers {
    tfe = {
      source  = "hashicorp/tfe"
      version = "0.80.0"
    }
  }
}

provider "tfe" {
  organization = "hp-platform-engineering"
}

module "rosa_boundary" {
  source  = "app.terraform.io/hp-platform-engineering/workspaces/tfe"
  version = "0.0.15"

  organization      = "hp-platform-engineering"
  project_name      = "rosa-boundary"
  meta_project_name = "meta-rosa"
  notification_url  = var.notification_url

  notification = {
    triggers = [
      "run:needs_attention",
      "run:errored",
      "assessment:check_failure",
      "assessment:drifted",
      "assessment:failed",
    ]
  }

  workspaces = {
    rosa-boundary-stage-network = {
      terraform_version  = "1.16.0"
      working_directory  = "deploy/network"
      github_repo_org    = "openshift-online"
      github_repo_name   = "rosa-boundary"
      variable_set_names = ["rosa-boundary-rosa-boundary-stage-default-aws-dynamic-creds"]
      variables = [
        {
          key      = "default_tags"
          value    = <<-EOT
            {
              owner         = "app-sre"
              service-phase = "stage"
            }
          EOT
          category = "terraform"
          hcl      = true
        },
        {
          key      = "ignored_tag_keys"
          value    = <<-EOT
            [
              "app",
              "app-code",
              "cost-center",
              "managed_by_integration",
              "organization",
            ]
          EOT
          category = "terraform"
          hcl      = true
        },
      ]
    }

    rosa-boundary-stage-aws-creds = {
      terraform_version = "1.16.0"
      working_directory = "hcp-terraform/aws-creds/rosa-boundary-stage"
      github_repo_org   = "openshift-online"
      github_repo_name  = "rosa-boundary"
      variable_set_names = [
        "rosa-boundary-tfe-creds",
        "rosa-boundary-rosa-boundary-stage-default-aws-dynamic-creds",
      ]
      variables = []
    }

    rosa-boundary-stage-regional = {
      terraform_version = "1.16.0"
      working_directory = "deploy/regional"
      github_repo_org   = "openshift-online"
      github_repo_name  = "rosa-boundary"
      # Apply successful plans automatically, including plans from workspace run triggers.
      auto_apply             = true
      auto_apply_run_trigger = true
      variable_set_names     = ["rosa-boundary-rosa-boundary-stage-default-aws-dynamic-creds"]
      variables = [
        {
          key      = "aws_account_id"
          value    = "150100906299"
          category = "terraform"
        },
        {
          key      = "aws_region"
          value    = "us-east-1"
          category = "terraform"
        },
        {
          key      = "stage"
          value    = "stage"
          category = "terraform"
        },
        {
          key      = "vpc_id"
          value    = "vpc-008ef33919b443f10"
          category = "terraform"
        },
        {
          key      = "subnet_ids"
          value    = "[\"subnet-0042826174855e520\", \"subnet-0f9392e3159168d6f\"]"
          category = "terraform"
          hcl      = true
        },
        {
          key      = "container_image"
          value    = "quay.io/redhat-user-workloads/rosa-tenant/rosa-boundary:c79a45da4e603c0b36576122cdadd3f2087a11fc"
          category = "terraform"
        },
        {
          key      = "keycloak_issuer_url"
          value    = "https://auth.redhat.com/auth/realms/EmployeeIDP"
          category = "terraform"
        },
        {
          key       = "keycloak_thumbprint"
          value     = "6541cf7958127d300fe86fd7ff324e836c75b53b"
          category  = "terraform"
          sensitive = true
        },
        {
          key      = "required_groups"
          value    = "[\"ai-sd-sre\"]"
          category = "terraform"
          hcl      = true
        },
        {
          key      = "abac_tag_key"
          value    = "uuid"
          category = "terraform"
        },
        {
          key      = "allowed_uuids"
          value    = "[\"7b5e6e92-0d75-11e7-851d-28d244ea5a6d\", \"a97b94a0-4b53-11ec-abc9-0a58ac14e8ca\", \"1e750c90-503c-11ec-bc06-0a58ac147a77\", \"9f1c4a70-a139-11e9-97cb-001a4a0a0044\"]"
          category = "terraform"
          hcl      = true
        },
        {
          key      = "enable_uuid_allowlist"
          value    = "false"
          category = "terraform"
        },
        {
          key      = "enable_oidc_group_enforcement"
          value    = "true"
          category = "terraform"
        },
        {
          key      = "required_oidc_role"
          value    = "ai-sd-sre"
          category = "terraform"
        },
        {
          key      = "lambda_package_type"
          value    = "Image"
          category = "terraform"
        },
        {
          key      = "lambda_image_repository"
          value    = "redhat-user-workloads/rosa-tenant/create-investigation-lambda"
          category = "terraform"
        },
        {
          key      = "lambda_image_tag"
          value    = "37a38113f6c98f0f5ff4821a5360eca77d2a9607"
          category = "terraform"
        },
        {
          key      = "default_tags"
          value    = <<-EOT
            {
              owner         = "app-sre"
              service-phase = "stage"
            }
          EOT
          category = "terraform"
          hcl      = true
        },
        {
          key      = "ignored_tag_keys"
          value    = <<-EOT
            [
              "app",
              "app-code",
              "cost-center",
              "managed_by_integration",
              "organization",
            ]
          EOT
          category = "terraform"
          hcl      = true
        },
        {
          key      = "log_retention_days"
          value    = "90"
          category = "terraform"
        },
        {
          key      = "_deletion_approvals"
          value    = <<-EOT
            [
              {
                address    = "aws_lambda_function.create_investigation"
                expires_at = "2026-08-20T23:59:59Z"
                reason     = "ZIP Lambda replaced by container image (ROSAENG-64685)"
              }
            ]
          EOT
          category = "terraform"
          hcl      = true
        },
      ]
    }
  }
}

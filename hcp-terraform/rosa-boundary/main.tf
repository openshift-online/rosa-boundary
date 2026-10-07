terraform {
  required_version = ">= 1.15, < 2.0"

  required_providers {
    tfe = {
      source  = "hashicorp/tfe"
      version = "0.81.0"
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

    rosa-boundary-stage-account = {
      terraform_version = "1.16.0"
      working_directory = "deploy/account"
      github_repo_org   = "openshift-online"
      github_repo_name  = "rosa-boundary"
      # A plan before adoption will propose duplicates of regional-owned objects.
      # Workspace variable below: adopt_existing_resources = false.
      # Change its value to true only for the reviewed import handoff.
      # Never apply until the regional release and account imports are reviewed.
      auto_apply             = false
      auto_apply_run_trigger = false
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
          # ROSAENG-68790: retain role names when identities move to separate account-level state.
          key      = "role_name_prefix"
          value    = "rosa-boundary-stage"
          category = "terraform"
        },
        {
          # ROSAENG-68790: retain existing policy names during the account-level resource migration.
          key      = "legacy_policy_region"
          value    = "us-east-1"
          category = "terraform"
        },
        {
          # ROSAENG-68790: retain original IAM role tags in the separate account-level state.
          key      = "legacy_role_tag_region"
          value    = "us-east-1"
          category = "terraform"
        },
        {
          # ROSAENG-68790: retain the budget's Region tag when moving it to account-level state.
          key      = "bedrock_budget_tag_region"
          value    = "us-east-1"
          category = "terraform"
        },
        {
          key      = "bedrock_monthly_budget_usd"
          value    = "2500"
          category = "terraform"
        },
        {
          key      = "bedrock_budget_notification_email"
          value    = "rosa-boundary-access@redhat.com"
          category = "terraform"
        },
        {
          # Retain the entire approved regional manifest for account adoption.
          key      = "bedrock_model_agreements"
          value    = <<-EOT
            {
              "anthropic.claude-sonnet-5" = "offer-2ykemehpsyf7g"
              "anthropic.claude-opus-4-6-v1" = "offer-ee7a27hh4hr62"
              "anthropic.claude-opus-4-8" = "offer-wdkl4yk6s7uu4"
              "anthropic.claude-opus-5" = "offer-f3u6lgbrem3zs"
              "anthropic.claude-haiku-4-5-20251001-v1:0" = "offer-fudwqbphlos64"
              "openai.gpt-6-sol" = "offer-pycji3sz5gpcc"
              "openai.gpt-6-luna" = "offer-gmo53nkzc5or6"
            }
          EOT
          category = "terraform"
          hcl      = true
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
          key      = "oidc_client_id"
          value    = "rosa-boundary-sre"
          category = "terraform"
        },
        {
          key      = "oidc_session_duration"
          value    = "3600"
          category = "terraform"
        },
        {
          key      = "enable_uuid_allowlist"
          value    = "false"
          category = "terraform"
        },
        {
          key      = "allowed_uuids"
          value    = "[\"7b5e6e92-0d75-11e7-851d-28d244ea5a6d\", \"a97b94a0-4b53-11ec-abc9-0a58ac14e8ca\", \"1e750c90-503c-11ec-bc06-0a58ac147a77\", \"9f1c4a70-a139-11e9-97cb-001a4a0a0044\"]"
          category = "terraform"
          hcl      = true
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
          key      = "enable_s3_replication_role"
          value    = "false"
          category = "terraform"
        },
        {
          # Adoption is enabled only in the later, reviewed state-transfer PR.
          key      = "adopt_existing_resources"
          value    = "false"
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
      ]
    }

    rosa-boundary-stage-regional = {
      terraform_version = "1.16.0"
      working_directory = "deploy/regional"
      github_repo_org   = "openshift-online"
      github_repo_name  = "rosa-boundary"
      # ROSAENG-68790: hold regional applies before account-level resources move state.
      # Keep both settings disabled until the migration and smoke tests finish.
      auto_apply             = false
      auto_apply_run_trigger = false
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
          key      = "bedrock_model_agreements"
          value    = <<-EOT
            {
              "anthropic.claude-sonnet-5" = "offer-2ykemehpsyf7g"
              "anthropic.claude-opus-4-6-v1" = "offer-ee7a27hh4hr62"
              "anthropic.claude-opus-4-8" = "offer-wdkl4yk6s7uu4"
              "anthropic.claude-opus-5" = "offer-f3u6lgbrem3zs"
              "anthropic.claude-haiku-4-5-20251001-v1:0" = "offer-fudwqbphlos64"
              "openai.gpt-6-sol" = "offer-pycji3sz5gpcc"
              "openai.gpt-6-luna" = "offer-gmo53nkzc5or6"
            }
          EOT
          category = "terraform"
          hcl      = true
        },
        {
          key      = "claude_default_model"
          value    = "us.anthropic.claude-sonnet-5"
          category = "terraform"
        },
        {
          key      = "stage"
          value    = "stage"
          category = "terraform"
        },
        {
          key      = "bedrock_monthly_budget_usd"
          value    = "2500"
          category = "terraform"
        },
        {
          key      = "bedrock_budget_notification_email"
          value    = "rosa-boundary-access@redhat.com"
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
          value    = "quay.io/redhat-user-workloads/rosa-tenant/rosa-boundary:884fc38ddc1e4d31f922cf13ad954984f53fa8c3"
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
          value    = "884fc38ddc1e4d31f922cf13ad954984f53fa8c3"
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

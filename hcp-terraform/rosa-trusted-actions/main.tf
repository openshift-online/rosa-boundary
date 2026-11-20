terraform {
  required_version = ">= 1.15, < 2.0"
  required_providers {
    tfe = {
      source  = "hashicorp/tfe"
      version = "0.84.0"
    }
  }
}

provider "tfe" {
  organization = "hp-platform-engineering"
}

module "rosa_trusted_actions" {
  source  = "app.terraform.io/hp-platform-engineering/workspaces/tfe"
  version = "0.0.23"

  organization      = "hp-platform-engineering"
  project_name      = "rosa-trusted-actions"
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
    # ── Global workspace ───────────────────────────────────────────────────────
    # Run once per account before any regional workspace.
    # Manages: IAM, Secrets Manager, ACM validation CNAME.
    # Outputs are consumed directly by regional workspaces via terraform_remote_state.
    rosa-trusted-actions-global = {
      terraform_version      = "1.16.0"
      auto_apply             = true
      auto_apply_run_trigger = true
      working_directory      = "components/trusted-actions/terraform/global"
      github_repo_org        = "openshift-online"
      github_repo_name       = "rosa-boundary"
      variable_set_names     = ["rosa-trusted-actions-rosa-boundary-stage-rosa-trusted-actions-aws-dynamic-creds"]
      # Lets the regional workspace read this workspace's outputs via
      # terraform_remote_state — required for the regional root's
      # terraform_remote_state block to resolve ARNs/bucket names.
      remote_state_consumer_workspaces = ["rosa-trusted-actions-stage"]
      variables = [
        {
          key         = "aws_region"
          value       = "us-east-1"
          category    = "terraform"
          description = "Provider region for the global workspace."
        },
        {
          key      = "environment"
          value    = "stage"
          category = "terraform"
        },
        {
          key      = "s3_bucket_name_suffix"
          value    = "rosa-trusted-actions"
          category = "terraform"
        },
        {
          key         = "public_zone",
          value       = "dev0.rosav1.devshift.net",
          category    = "terraform",
          description = "The public hosted zone to create for certificate creation"
        },
        {
          key         = "internal_fqdn"
          value       = "rosa-trusted-actions.dev0.rosav1.devshift.net"
          category    = "terraform"
          description = "Used only to obtain the ACM validation CNAME token. Must match all regional workspaces."
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
        # public_zone_id: add when the public apex zone is available.
        # {
        #   key      = "public_zone_id"
        #   value    = "Z0123456789ABCDEF"
        #   category = "terraform"
        # },
      ]
    }

    # ── Regional workspace: us-east-1 stage ────────────────────────────────────
    # Apply after rosa-trusted-actions-global.
    # IAM ARNs and the Secrets Manager ARN are read directly from the global
    # workspace state via terraform_remote_state — no manual copying. The S3
    # bucket is created in this workspace (s3_bucket_name_suffix must match
    # the global workspace's value).
    rosa-trusted-actions-stage = {
      terraform_version      = "1.16.0"
      auto_apply             = true
      auto_apply_run_trigger = true
      working_directory      = "components/trusted-actions/terraform/regional"
      github_repo_org        = "openshift-online"
      github_repo_name       = "rosa-boundary"
      # Queues a regional run whenever the global workspace applies
      # successfully (module-managed run trigger, resolved by name since
      # it's a sibling workspace in this same module invocation).
      source_workspaces  = ["rosa-trusted-actions-global"]
      variable_set_names = ["rosa-trusted-actions-rosa-boundary-stage-rosa-trusted-actions-aws-dynamic-creds"]
      variables = [
        {
          key         = "aws_region"
          value       = var.aws_region
          category    = "terraform"
          description = "AWS region for this deployment."
        },
        {
          key      = "environment"
          value    = "stage"
          category = "terraform"
        },
        {
          key         = "s3_bucket_name_suffix"
          value       = "rosa-trusted-actions"
          category    = "terraform"
          description = "Must match the global workspace's s3_bucket_name_suffix — used to build this region's bucket name."
        },
        {
          key      = "vpc_id"
          value    = "vpc-008ef33919b443f10"
          category = "terraform"
        },
        {
          key      = "public_subnet_ids"
          value    = jsonencode(["subnet-01821c41d92b0f8b1", "subnet-0f52e06526c080dfa"])
          category = "terraform"
          hcl      = true
        },
        {
          key      = "private_subnet_ids"
          value    = jsonencode(["subnet-0042826174855e520", "subnet-0f9392e3159168d6f"])
          category = "terraform"
          hcl      = true
        },
        {
          key      = "container_image"
          value    = "quay.io/redhat-user-workloads/rosa-tenant/rosa-trusted-actions@sha256:d51a737176307ee43f92c0667688a39d191dc656396bcaa3294dd9fbc649c331"
          category = "terraform"
        },
        {
          key         = "app_config"
          value       = <<-YAML
            actions:
              # allowed_cluster_regions is deliberately unset: actions reach
              # clusters in every region, as they did before the setting
              # existed. Add it (e.g. [${var.aws_region}]) only as a decision
              # to confine this deployment.
              allowed_namespaces: []
              allowed_secrets: []
            ocm:
              base_url: https://api.stage.openshift.com
              client_id: ${var.ocm_client_id}
            backplane:
              base_url: https://api.stage.backplane.openshift.com
              client_id: ${var.backplane_client_id}
            roles:
              - id: SREP
                amsResource: BackplaneOsdSrepResource
              - id: ConfigurationAnomalyDetection
                amsResource: BackplaneOsdCadResource
              - id: ROSAAiAgent
                amsResource: BackplaneOsdAiAgentResource
            workers:
              concurrency: 4
              poll_interval: 5s
              execution_timeout: 2m
          YAML
          category    = "terraform"
          description = "Complete application config file (config.yaml) uploaded to S3. The Go loader applies env-over-file precedence, so settings here must not also be env vars on the task definition."
        },
        {
          key         = "internal_fqdn"
          value       = "rosa-trusted-actions.dev0.rosav1.devshift.net"
          category    = "terraform"
          description = "Private FQDN — must match the value in the global workspace."
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
          key       = "ocm_client_secret"
          value     = var.ocm_client_secret
          category  = "terraform"
          sensitive = true
        },
        {
          key       = "backplane_client_secret"
          value     = var.backplane_client_secret
          category  = "terraform"
          sensitive = true
        }
      ]
    }

    # ── Global workspace: prod (514903006123) ──────────────────────────────────
    # IAM + Secrets + ACM validation CNAME for the prod account. Apply once
    # before rosa-trusted-actions-prod-us-east-1. Separate from the stage global because
    # IAM roles/policies are account-scoped and live in disjoint AWS accounts.
    rosa-trusted-actions-prod-global = {
      terraform_version      = "1.16.0"
      auto_apply             = true
      auto_apply_run_trigger = true
      working_directory      = "components/trusted-actions/terraform/global"
      github_repo_org        = "openshift-online"
      github_repo_name       = "rosa-boundary"
      variable_set_names     = ["rosa-trusted-actions-rosa-boundary-prod-rosa-trusted-actions-aws-dynamic-creds"]
      remote_state_consumer_workspaces = ["rosa-trusted-actions-prod-us-east-1"]
      variables = [
        {
          key         = "aws_region"
          value       = "us-east-1"
          category    = "terraform"
          description = "Provider region for the global workspace."
        },
        {
          key      = "environment"
          value    = "prod"
          category = "terraform"
        },
        {
          key      = "s3_bucket_name_suffix"
          value    = "rosa-trusted-actions"
          category = "terraform"
        },
        {
          key         = "public_zone"
          value       = ""
          category    = "terraform"
          description = "Prod public hosted zone apex — set once the prod zone exists (or use public_zone_id to adopt an existing zone)."
        },
        {
          key         = "internal_fqdn"
          value       = ""
          category    = "terraform"
          description = "Prod internal FQDN (Private Hosted Zone name). Must match rosa-trusted-actions-prod-us-east-1. Leave empty until DNS is ready."
        },
        {
          key      = "default_tags"
          value    = <<-EOT
            {
              owner         = "app-sre"
              service-phase = "prod"
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

    # ── Regional workspace: us-east-1 prod (514903006123) ───────────────────────
    # Reuses rosa-boundary-prod's VPC (vpc-0f7b78f35f6edd98b) in the same account/region
    # as boundary prod Region A. Prod-global must be applied first so
    # terraform_remote_state can read IAM ARNs and the Secrets Manager ARN.
    rosa-trusted-actions-prod-us-east-1 = {
      terraform_version      = "1.16.0"
      auto_apply             = true
      auto_apply_run_trigger = true
      working_directory      = "components/trusted-actions/terraform/regional"
      github_repo_org        = "openshift-online"
      github_repo_name       = "rosa-boundary"
      source_workspaces      = ["rosa-trusted-actions-prod-global"]
      variable_set_names     = ["rosa-trusted-actions-rosa-boundary-prod-rosa-trusted-actions-aws-dynamic-creds"]
      variables = [
        {
          key         = "aws_region"
          value       = "us-east-1"
          category    = "terraform"
          description = "AWS region for this deployment — prod Region A."
        },
        {
          key      = "environment"
          value    = "prod"
          category = "terraform"
        },
        {
          key         = "s3_bucket_name_suffix"
          value       = "rosa-trusted-actions"
          category    = "terraform"
          description = "Must match the global workspace's s3_bucket_name_suffix."
        },
        {
          key      = "vpc_id"
          value    = "vpc-0f7b78f35f6edd98b"
          category = "terraform"
        },
        {
          key      = "public_subnet_ids"
          value    = jsonencode(["REPLACE_WITH_PROD_PUBLIC_SUBNET_A", "REPLACE_WITH_PROD_PUBLIC_SUBNET_B"])
          category = "terraform"
          hcl      = true
        },
        {
          key      = "private_subnet_ids"
          value    = jsonencode(["subnet-07b28f6e5fb8d80c6", "subnet-0af708edfc074a605"])
          category = "terraform"
          hcl      = true
        },
        {
          key      = "container_image"
          value    = "quay.io/redhat-user-workloads/rosa-tenant/rosa-trusted-actions@sha256:REPLACE_WITH_PROD_IMAGE_DIGEST"
          category = "terraform"
        },
        {
          key         = "app_config"
          value       = <<-YAML
            actions:
              aws_allowed_regions: [us-east-1]
              allowed_namespaces: []
              allowed_secrets: []
            ocm:
              base_url: https://api.openshift.com
              client_id: $${var.ocm_client_id}
            backplane:
              base_url: https://api.backplane.openshift.com
              client_id: $${var.backplane_client_id}
            roles:
              - id: SREP
                amsResource: BackplaneOsdSrepResource
              - id: ConfigurationAnomalyDetection
                amsResource: BackplaneOsdCadResource
              - id: ROSAAiAgent
                amsResource: BackplaneOsdAiAgentResource
            workers:
              concurrency: 4
              poll_interval: 5s
              execution_timeout: 2m
          YAML
          category    = "terraform"
          description = "Complete application config file (config.yaml) uploaded to S3. Prod OCM/Backplane use non-stage base URLs."
        },
        {
          key         = "internal_fqdn"
          value       = ""
          category    = "terraform"
          description = "Prod Private Hosted Zone FQDN — must match rosa-trusted-actions-prod-global. Leave empty until DNS is ready."
        },
        {
          key      = "enable_worm"
          value    = "true"
          category = "terraform"
        },
        {
          key      = "retention_days"
          value    = "90"
          category = "terraform"
        },
        {
          key      = "default_tags"
          value    = <<-EOT
            {
              owner         = "app-sre"
              service-phase = "prod"
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
          key       = "ocm_client_secret"
          value     = var.ocm_client_secret
          category  = "terraform"
          sensitive = true
        },
        {
          key       = "backplane_client_secret"
          value     = var.backplane_client_secret
          category  = "terraform"
          sensitive = true
        }
      ]
    }
  }
}

# ── State sharing ─────────────────────────────────────────────────────────────
# Grants the regional workspace read access to the global workspace's state
# via the module's own remote_state_consumer_workspaces field (see the global
# workspace definition above) rather than a second tfe_workspace_settings
# resource here, which would fight the module's tfe_workspace_settings.this
# for the same workspace and strand the setting on the next unrelated update.

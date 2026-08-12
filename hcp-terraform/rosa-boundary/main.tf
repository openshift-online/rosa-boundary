terraform {
  required_version = "1.15.8"

  required_providers {
    tfe = {
      source  = "hashicorp/tfe"
      version = "0.79.0"
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

  workspaces = {
    rosa-boundary-stage-network = {
      terraform_version  = "1.15.8"
      working_directory  = "deploy/network"
      github_repo_org    = "openshift-online"
      github_repo_name   = "rosa-boundary"
      variable_set_names = ["rosa-boundary-rosa-boundary-stage-default-aws-dynamic-creds"]
      variables          = []
    }

    rosa-boundary-stage-aws-creds = {
      terraform_version = "1.15.8"
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
      terraform_version      = "1.15.8"
      working_directory      = "deploy/regional"
      github_repo_org        = "openshift-online"
      github_repo_name       = "rosa-boundary"
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
      ]
    }
  }
}

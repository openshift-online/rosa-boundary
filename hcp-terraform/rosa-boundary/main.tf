terraform {
  required_version = "1.15.8"

  required_providers {
    tfe = {
      source  = "hashicorp/tfe"
      version = "0.79.0"
    }
  }
}

module "rosa_boundary" {
  source  = "app.terraform.io/hp-platform-engineering/workspaces/tfe"
  version = "0.0.14"

  organization      = "hp-platform-engineering"
  project_name      = "rosa-boundary"
  meta_project_name = "meta-rosa"
  notification_url  = var.notification_url

  workspaces = {
    rosa-boundary-stage-network = {
      terraform_version = "1.15.8"
      working_directory = "deploy/network"
      github_repo_org   = "openshift-online"
      github_repo_name  = "rosa-boundary"
      execution_mode    = "local"
      variables         = []
    }

    rosa-boundary-stage-aws-creds = {
      terraform_version = "1.15.8"
      working_directory = "hcp-terraform/aws-creds/rosa-boundary-stage"
      github_repo_org   = "openshift-online"
      github_repo_name  = "rosa-boundary"
      execution_mode    = "local"
      variables         = []
    }
  }
}

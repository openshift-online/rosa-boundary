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
      variables = [
        { key = "aws_account_id", value = "150100906299", category = "terraform" },
        { key = "aws_region", value = "us-east-1", category = "terraform" },
        { key = "stage", value = "stage", category = "terraform" },
        { key = "vpc_cidr", value = "10.80.0.0/20", category = "terraform" },
        { key = "availability_zones", value = "[\"us-east-1a\", \"us-east-1b\"]", category = "terraform", hcl = true },
        { key = "public_subnet_cidrs", value = "[\"10.80.0.0/24\", \"10.80.1.0/24\"]", category = "terraform", hcl = true },
        { key = "private_subnet_cidrs", value = "[\"10.80.8.0/24\", \"10.80.9.0/24\"]", category = "terraform", hcl = true },
        { key = "nat_strategy", value = "single", category = "terraform" },
      ]
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
  }
}

terraform {
  cloud {
    organization = "hp-platform-engineering"
    workspaces {
      name = "rosa-boundary-prod-aws-creds"
    }
  }
}

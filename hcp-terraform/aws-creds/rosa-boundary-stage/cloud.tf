terraform {
  cloud {
    organization = "hp-platform-engineering"
    workspaces {
      name = "rosa-boundary-stage-aws-creds"
    }
  }
}

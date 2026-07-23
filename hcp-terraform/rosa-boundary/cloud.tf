terraform {
  cloud {
    organization = "hp-platform-engineering"
    workspaces {
      name = "meta-rosa-rosa-boundary"
    }
  }
}

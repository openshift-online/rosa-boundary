# Preserve the existing HCP variable resources when migrating from the ECR-only
# input to the shared ECR/S3 object. The key and HCL value update in place; no
# workspace, AWS replication configuration, or HCP variable should be deleted.
# Keep these moves for workspaces that have not yet applied the migration.
moved {
  from = module.rosa_boundary.tfe_variable.this["rosa-boundary-stage-account:terraform:lambda_ecr_replication_regions"]
  to   = module.rosa_boundary.tfe_variable.this["rosa-boundary-stage-account:terraform:replication"]
}

moved {
  from = module.rosa_boundary.tfe_variable.this["rosa-boundary-prod-account:terraform:lambda_ecr_replication_regions"]
  to   = module.rosa_boundary.tfe_variable.this["rosa-boundary-prod-account:terraform:replication"]
}

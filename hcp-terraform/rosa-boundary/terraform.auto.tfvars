# Approve only the four obsolete HCP Lambda repository variables removed by
# the coordinated staging and production regional ECR cutover.
_deletion_approvals = [
  {
    address    = "module.rosa_boundary.tfe_variable.this[\"rosa-boundary-stage-regional:terraform:lambda_image_repository\"]"
    expires_at = "2026-11-17T23:59:59Z"
    reason     = "Remove the obsolete staging east Lambda Quay repository override (ROSAENG-67186)"
  },
  {
    address    = "module.rosa_boundary.tfe_variable.this[\"rosa-boundary-stage-regional-us-west-2:terraform:lambda_image_repository\"]"
    expires_at = "2026-11-17T23:59:59Z"
    reason     = "Remove the obsolete staging west Lambda Quay repository override (ROSAENG-67186)"
  },
  {
    address    = "module.rosa_boundary.tfe_variable.this[\"rosa-boundary-prod-regional-us-east-1:terraform:lambda_image_repository\"]"
    expires_at = "2026-11-17T23:59:59Z"
    reason     = "Remove the obsolete production east Lambda Quay repository override (ROSAENG-76115)"
  },
  {
    address    = "module.rosa_boundary.tfe_variable.this[\"rosa-boundary-prod-regional-us-west-2:terraform:lambda_image_repository\"]"
    expires_at = "2026-11-17T23:59:59Z"
    reason     = "Remove the obsolete production west Lambda Quay repository override (ROSAENG-76115)"
  },
]

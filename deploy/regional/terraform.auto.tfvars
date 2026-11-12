# Approve only the legacy Lambda Quay cache rule removal for the regional ECR cutover.
# The rosa-deletion-protection policy checks this exact address and expiry.
_deletion_approvals = [
  {
    address    = "aws_ecr_pull_through_cache_rule.quay[0]"
    expires_at = "2026-11-17T23:59:59Z"
    reason     = "Retire Lambda Quay cache after cutover to ordinary regional ECR (ROSAENG-67186, ROSAENG-76115)"
  },
]

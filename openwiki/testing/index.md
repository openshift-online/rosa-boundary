# Files

- [Trusted Actions testing and CI](trusted-actions-testing.md) - Describes the Trusted Actions component's unit, integration, and mock-dependency testing strategy, its Make targets and Codecov patch-coverage gate, and the Konflux Tekton pipelines that build and push its image on PR and push events in this monorepo.
- [Boundary Infrastructure Verification (Terraform Tests)](verification.md) - Explains Boundary's Terraform test strategy — mock-provider-based .tftest.hcl suites under deploy/account and deploy/regional that validate IAM ownership, content storage, replication topology, ECR/Lambda wiring, and input-variable guards without touching real AWS — plus the one Python-based replication-topology check that uses a different mechanism.

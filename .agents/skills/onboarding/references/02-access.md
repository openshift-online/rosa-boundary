# Step 2 — License and registry access

Prerequisites: tools installed sufficiently to run
`python3 .agents/skills/onboarding/scripts/check.py 2`. This checks executables,
not entitlement. Access may be requested early, but may not be assumed granted.

Ask the user to complete:
- [LocalStack workspace invitation and private token configuration](../../../../docs/runbooks/contributor-local-setup.md#2-request-localstack-access).
  They must obtain a licensed workspace token and set the ignored
  tests/localstack/.env themselves. Do not ask them to paste the token.
- [HCP organization/team and private-module access](../../../../docs/runbooks/contributor-local-setup.md#3-arrange-access-for-the-full-terraformbuild-checks).
  They must complete `terraform login app.terraform.io` interactively.
- Any registry login needed for base images/downloads.

**Halt until they respond**, including when access requests are pending. On
resume, ask for confirmation without secrets. Do not inspect Terraform credential
files. Token presence is asserted in step 4; license activation is proven only by
successful startup, and private-module access by isolated initialization in step 5.
HCP login grants no deployment approval. Next: step 3.

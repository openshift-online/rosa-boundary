# Step 7 — Approved live verification and PR handoff

Prerequisites:
`python3 .agents/skills/onboarding/scripts/check.py 7 --summary /private/path/summary.json`.
Reconfirm step 5 provenance, personal-dev account/region, non-admin Keycloak SRE
access and approved provider settings. Missing/stale sessions require user
authentication: explain it and **halt until they respond**.

Use [personal-dev bootstrap](../../../../docs/runbooks/personal-dev-bootstrap.md)
as the canonical account → network → image → regional → isolated CLI → smoke/audit/
cleanup sequence. Delegate execution boundaries to
[boundary-live-verification](../../boundary-live-verification/SKILL.md): read it,
inventory first, bind to the exact changeset/artifacts, review plans and obtain
explicit approval before AWS mutations, publication or investigation creation.
Onboarding itself is not approval. Never target staging or production.

For a **new** personal installation only, an optional extracted helper is
`bash .agents/skills/onboarding/scripts/populate-account-tfvars.sh`.
Prerequisites: approved personal STS identity, explicitly selected REGION, Python,
reviewed example/current account tfvars, and no existing deployment being migrated.
Ask approval to write the private file and **halt until they respond**.
The helper preserves existing settings, rejects mismatched accounts/non-dev
files, and makes only a read-only STS request; it is not an apply. Review the
result privately with [account configuration guidance](../../../../docs/runbooks/personal-dev-bootstrap.md).
It derives a default budget email from Git/username unless BUDGET_EMAIL is set;
have the user confirm the recipient, budget amount and notification delivery.
Region/tag initialization is not a state migration tool. Verify Keycloak
thumbprint/client/trust independently; budget alerts do not cap spending.

Pause for every external action/approval and record a resumable substep. Do not
collapse a fresh-account deployment into a single preapproved block. Completion
requires live results, artifact provenance, audit evidence and cleanup status;
otherwise report the exact pending boundary, not onboarding fully verified.

Finally follow [upstream branch and PR requirements](../../../../CONTRIBUTING.md#open-a-pr-from-an-upstream-branch).
Ask the user for missing upstream write access and halt; do not silently use a
fork. Do not push or open a PR without their request/approval.

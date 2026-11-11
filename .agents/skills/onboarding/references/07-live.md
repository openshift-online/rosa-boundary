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

Before planning, complete or revalidate step 6's
[deployment input checklist](06-personal-access.md#deployment-input-checklist).
Inventory matching AWS resources as well as state: missing local state alone does
not prove Terraform never ran. Conversely, an existing network does not prove
account identities or regional workloads exist. Reuse an owned network rather
than recreating it; do not automatically import/adopt existing resources.

## Deployment command map

These are **separate gated actions**, run from the repository root, not a script
to execute as a batch. Verify the current Make recipes and variables first.
The [bootstrap runbook](../../../../docs/runbooks/personal-dev-bootstrap.md)
remains canonical for configuration and full instructions.

| Layer | Prepare and plan | Only after approval of that plan |
| --- | --- | --- |
| Account identities | `make -C deploy/account init`, `make -C deploy/account validate`, `make -C deploy/account plan` | `make -C deploy/account apply` |
| Network, if new or changing | `make -C deploy/network init`, `make -C deploy/network validate`, `make -C deploy/network plan` | `make -C deploy/network apply` |
| Task image | Inspect the approved existing image's platform/digest and pull access, or use the root Makefile's approved build target | Publish/copy only to the approved destination if needed; do not create ECR resources merely because an image is on Quay. |
| Regional workload | Complete private tfvars/`.env`; `make -C deploy/regional init`, `make -C deploy/regional validate`, `make -C deploy/regional plan` | `make -C deploy/regional apply` (builds Lambda dependencies first) |

An ECS task image can use a reachable public registry; verify private-subnet
egress and runtime pull access rather than assuming an ECR mirror is required.
Lambda Image packaging has separate ECR/seeding requirements; the ECS task image
is not a Lambda artifact. For ZIP packaging, build through
`make -C deploy/regional build-lambda` before reviewing package hashes in the plan.
The apply target rebuilds dependencies: verify deployed code hashes against the
approved artifacts, and do not assume rebuilds are byte-for-byte identical.

For each root, present account/Region, resource counts, replacements/deletions,
IAM/trust changes, audit/retention effects and costs before requesting approval.
Explicitly call out regional **account/Region-wide Bedrock text invocation
logging** (potential unredacted prompts/responses and separate log/S3 readers)
and audit **COMPLIANCE Object Lock**, which prevents early object deletion.
A budget alert is not a spend cutoff. Approval of account identities does not
approve these later regional effects. A no-change plan needs no apply.

Use the owning Makefile rather than direct Terraform apply or the targeted,
auto-approved regional `lambda` target. When using saved plans, keep them private,
bind approval to the reviewed plan and verify its fingerprint/artifacts before
apply. Terraform `-detailed-exitcode` returns 2 for proposed changes (Make may
report it as an error); distinguish this from a planning failure.

After each approved apply, independently check AWS readiness/artifact identifiers
and run a follow-up plan. If it proposes new changes or replacements, preserve
the complete output, stop for review and report the difference; do not keep
applying to chase convergence. Record created/changed/deleted resource addresses,
identifiers, revision/digests, state/backend locations, validation results,
unverified behavior and remaining work in a private handoff. Keep state, saved
plans, credentials and sensitive configuration out of Git. An apply or clean plan
does not prove login, task image pulling, ABAC or audit delivery.

## Optional account configuration helper

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

# Dev execution and reuse gates

This is an operator workflow, **not an unattended deployment script**. Confirm commands against current source/Makefiles and current CLI help; do not execute the examples before reviewing the target and receiving approval. The [personal-dev bootstrap guide](../../../../docs/runbooks/personal-dev-bootstrap.md) documents a fresh-account setup. Never assume a contributor's account/issuer/region is a universal default. The [regional README](../../../../deploy/regional/README.md), [account README](../../../../deploy/account/README.md), [testing guide](../../../../docs/testing.md), and [investigation workflow](../../../../docs/runbooks/investigation-workflow.md) provide context, but current source and live state govern.

## Local profile and run ledger

From repo root, initialize a per-contributor profile once (do not pass passwords or tokens):

```bash
python3 .agents/skills/boundary-live-verification/scripts/dev_state.py profile add \
  --name my-dev --account-id "$APPROVED_ACCOUNT" --region "$APPROVED_REGION" \
  --oidc-base-url "$CONTRIBUTOR_OIDC_BASE_URL" --realm "$REALM" --client-id "$CLIENT_ID"
python3 .agents/skills/boundary-live-verification/scripts/dev_state.py profile show --name my-dev
```

The profile lives at `${XDG_CONFIG_HOME:-~/.config}/rosa-boundary-live-verification/profiles/<name>.json` (0600). Runs live at `${XDG_STATE_HOME:-~/.local/state}/rosa-boundary-live-verification/<name>/runs/<uuid>.json` (0600). Avoid pointing XDG directories into a checkout or cloud-synced folder; neither profile nor ledger belongs in Git or EFS. The `profile show` output omits the OIDC URL. The ledger records *claims* supplied by the operator; it performs no AWS calls or deployment. It never acts as a pass/fail oracle or source of current AWS truth.

At the start of an authorized run, create a record with a SHA-256 fingerprint of the **actual build inputs** (include relevant untracked changes explicitly; a Git commit alone is not enough for a dirty tree), revision, and independently observed metadata:

```bash
python3 .agents/skills/boundary-live-verification/scripts/dev_state.py run start \
  --profile my-dev --revision "$REVISION" --source-sha256 "$SOURCE_SHA256" \
  --test lifecycle-smoke --image-digest "$ECR_DIGEST" \
  --lambda-code-sha256 "$LAMBDA_CODE_SHA256" --task-definition-arn "$TASK_DEF_ARN" \
  --cli-sha256 "$CLI_SHA256"
# Prints a run UUID; copy it into the test record and cleanup notes.
```

Immediately after task creation, save cleanup identifiers even if the test might fail later:

```bash
python3 .agents/skills/boundary-live-verification/scripts/dev_state.py run update \
  --profile my-dev --run-id "$RUN_ID" \
  --task-arn "$TASK_ARN" --investigation-id "$INVESTIGATION_ID"
```

Finish it even on failure (`--result blocked|failed|passed`, `--cleanup completed|pending|not-required`, `--session-evidence verified|missing|unverified|not-required`, `--s3-evidence ...`). Use `run show --profile my-dev --run-id "$RUN_ID"` or `run list --profile my-dev` to review. A pending cleanup result must include task/investigation IDs when available. The tool refuses a passed result with missing evidence or pending cleanup. Do not enter sensitive log bodies or audit artifacts into the ledger.

## Inventory before reuse or deployment

1. Verify AWS caller identity, explicitly selected Region and account guard; read-only ECS cluster/base and per-investigation task definitions, ECR image manifest/digest and platform, Lambda function package/hash/status, EFS, audit bucket/log groups, IAM identity/grants and OIDC providers. Compare with local account/network/regional state ownership and effective `.env`/tfvars values without dumping secrets. Check whether the regional stack and account root share an unresolved IAM handoff; never run automatic import/adoption. Local Terraform state is sensitive; inspect only the needed addresses/outputs safely.
2. Inspect `deploy/account/Makefile`, `deploy/network/Makefile`, `deploy/regional/Makefile`, variables and backend definitions. Do **not** run regional `show-env` or `lambda` (targeted auto-approve). In the regional Makefile, `.env` exports `TF_VAR_abac_tag_key` and `TF_VAR_enable_kube_proxy` with fallbacks; these may override `terraform.tfvars`. The dev profile does not override these variables and cannot validate their effective values by itself. Confirm effective values during review.
3. If the existing account deployment matches every required component, **reuse it only if artifact provenance is established**. `:latest` is mutable: an ECR tag digest, a registered task definition, and a locally built image are three separate facts. A newly launched task may pull a different digest from an older task, and a running task will not update. Prefer a unique source-fingerprint tag plus digest-pinned `container_image`; for Lambda Zip compare built artifact SHA-256 (AWS `CodeSha256` is base64 of raw SHA-256) after apply. When a proof is unavailable, mark it unverified and redeploy with reviewed provenance rather than assuming equality.
   Run the optional **read-only** metadata matcher once expected values are obtained from the approved build, not from the current AWS environment itself:

   ```bash
   python3 .agents/skills/boundary-live-verification/scripts/preflight.py \
     --profile my-dev --expect-image-digest "$BUILD_DIGEST" \
     --expect-architecture X86_64 --expect-lambda-code-sha256 "$BUILD_ZIP_SHA256_BASE64"
   ```

   Omit expectations for unrelated surfaces and describe them as unchecked. Exit 0 means *only* that requested metadata checks match; exit 2 means mismatch/unverified/blocked. The script deliberately rejects a mutable task-definition image tag, even if the tag currently resolves to that digest. It does not compare Terraform plans, confirm registry manifest architecture, inspect Lambda image packages, or prove task runtime/audit behavior. Those require independent review and tests.
4. Determine CLI config source from [current config code](../../../../internal/config/config.go). Use isolated `XDG_CONFIG_HOME`/`XDG_CACHE_HOME` under the contributor's private local directory for live-dev runs so the workstation's staging configuration/tokens are not reused. Avoid inherited `ROSA_BOUNDARY_*` and legacy env overrides. Run CLI `configure --environment dev` with the contributor's base URL/realm/client ID **explicitly for non-default OIDC**. Login as the approved SRE; verify all discovered account IDs, region and resources before mutating commands.

## Fresh bootstrap / mismatch repair

For a genuinely new account, request account ID and approved budget/network/identity inputs, then plan and review **account IAM**, **network**, image publication, **regional** in that order. Account and network have separate local states from regional. A pre-existing manually managed network can be reused after VPC/subnet/NAT review; do not let Terraform create a duplicate. Use root `make build-amd64`/`build-arm64` as required, inspect image architecture and verify ECR push digest, then configure the regional image and use its `make init`, `make validate`, `make plan`, and (after approval) `make apply`. Verify the plan's actual changes and AWS account guard; do not assume a reused, clean plan proves the deployed image matches source. Publish no image until the user approves the destination/revision. In personal dev, Terraform is local; staging uses the Git/HCP workflow and is outside this skill.

For a mismatch, propose *only* the affected layer(s), with source fingerprint, destination account/region, image architecture/digest, and Lambda package mode. Updating CLI locally does not require AWS apply. Lambda Zip changes require a reviewed regional plan/apply (the `apply` target builds dependencies), not a direct Lambda update. A container or task-definition change requires a new investigation task for runtime evidence. Re-read AWS after each deployment step and capture the observed digest/hash, revision and state; resolve errors before test execution.

## Audit and cleanup

Use the [investigation workflow](../../../../docs/runbooks/investigation-workflow.md) for approved CLI command syntax. The task timeout minimum is deployment-specific; use a bounded positive timeout. Audit reads require a separate authorized AWS identity in the **same account/Region**; CLI SRE credentials are not an audit-reader. Identify the actual session log stream and container log stream for the task/time window, and verify the expected harmless marker object under its task-scoped S3 prefix. Avoid printing sensitive transcript content. `--wait` confirms STOPPED only; check audit sync warnings and object existence. After evidence collection, close and verify no running tasks or leaked access points/task definitions from the test. Do not delete WORM audit objects or EFS data as routine cleanup. Retain the task/investigation IDs and mark cleanup pending if an earlier step fails.

## Handoff from change verification

Use this compact contract (planning-only calls must not create tasks):

```text
revision/source fingerprint: ...
changed boundaries: CLI | image | Lambda | account | network | regional | audit | identity
local checks and limits: ...
required live assertions and negative cases: ...
required image architecture/credentials/target cluster: ...
deployment layers needed / provenance gaps: ...
audit evidence required: ...
approval status (deployment and test separately): ...
```

Do not hand off a vague "run e2e" without target, approvals, and measurable evidence. Record blocked checks rather than substituting another account, Keycloak provider, or cluster.

---
type: testing-guide
title: Boundary Infrastructure Verification (Terraform Tests)
description: Explains Boundary's Terraform test strategy — mock-provider-based .tftest.hcl suites under deploy/account and deploy/regional that validate IAM ownership, content storage, replication topology, ECR/Lambda wiring, and input-variable guards without touching real AWS — plus the one Python-based replication-topology check that uses a different mechanism.
tags: [terraform, testing, iam, infrastructure, mock-provider, tftest, replication, bedrock]
verified:
  - by: openwiki/0.7.1
    at: 2026-11-12T16:02:44.301Z
sources:
  - id: openwiki-source-7afccf6bb50a66b861c2b750
    resource: repo://deploy/account/Makefile
  - id: openwiki-source-e0e8c15f232fd81f46f03e41
    resource: repo://deploy/account/modules/shared-iam/iam.tf
  - id: openwiki-source-65e02007ebea688b767a848b
    resource: repo://deploy/account/modules/shared-iam/lambda-create-investigation.tf
  - id: openwiki-source-f4745022f20c2f39d1db313b
    resource: repo://deploy/account/modules/shared-iam/lambda-reap-investigations.tf
  - id: openwiki-source-ca5deb97ae20b796aad13c09
    resource: repo://deploy/account/modules/shared-iam/lambda-reap-tasks.tf
  - id: openwiki-source-13bc46f3694506473af729bc
    resource: repo://deploy/account/tests/baseline.tftest.hcl
  - id: openwiki-source-88ce5728cbec2814062ae8aa
    resource: repo://deploy/account/tests/content-publishing.tftest.hcl
  - id: openwiki-source-6064e356e2f17b6ca9a00336
    resource: repo://deploy/account/tests/ecr-lambda.tftest.hcl
  - id: openwiki-source-e63bbacd264bc409c45ddf07
    resource: repo://deploy/account/tests/shared-iam.tftest.hcl
  - id: openwiki-source-45c9b8ed543efe3e46e09b07
    resource: repo://deploy/account/tests/test_replication_topology.py
  - id: openwiki-source-b1c5e619d9ef5b51db452442
    resource: repo://deploy/regional/Makefile
  - id: openwiki-source-92cccd8107e9e4386a317d7a
    resource: repo://deploy/regional/tests/claude_default_model.tftest.hcl
  - id: openwiki-source-e331ce49d4745096eb9b7376
    resource: repo://deploy/regional/tests/content-storage.tftest.hcl
  - id: openwiki-source-d47764bc2ef3fe0e490a1747
    resource: repo://deploy/regional/tests/ecr-lambda-destination.tftest.hcl
  - id: openwiki-source-1599d372a558b44029d5589b
    resource: repo://deploy/regional/tests/iam-ownership.tftest.hcl
generated: { by: "openwiki/0.7.1", at: "2026-11-12T16:02:44.301Z" }
---

# Boundary Infrastructure Verification (Terraform Tests)

Boundary's two Terraform roots — `deploy/account` (one state per AWS account) and `deploy/regional` (one state per deployed Region) — each ship a `tests/` directory of [native Terraform test](https://developer.hashicorp.com/terraform/language/tests) suites (`*.tftest.hcl`). Every suite uses `mock_provider "aws"` (and, where the module uses it, `mock_provider "archive"`) so `terraform test` can run `plan` and `apply` against ephemeral test state without AWS credentials, real API calls, or any live infrastructure. These suites are the authoritative check on IAM identity/policy ownership, content-bucket and replication wiring, ECR/Lambda destination behavior, and the input-variable guards that gate Bedrock model selection and cross-Region trust — they are not a substitute for a deployed-environment verification of real AWS enforcement.

## Why mocked Terraform tests exist

Both roots read from and grant permissions on resources that either don't exist until apply time (ARNs, bucket names) or are deliberately looked up from another workspace's state (shared IAM identities owned by `deploy/account`, consumed by every `deploy/regional` workspace — see [HCP Terraform workspaces](../infrastructure/hcp-terraform-workspaces.md) for the workspace/state topology and [Regional runtime](../infrastructure/regional-runtime.md) for what the regional root deploys). Terraform's mocked test mode lets each suite assert on the *rendered configuration* — resource names, IAM policy JSON, attachment targets, output values — while supplying deterministic mock ARNs/IDs in place of real AWS responses. This proves Terraform computes the intended shape; it does not prove AWS will accept or enforce that shape, and the suites say so explicitly in their own header comments (for example, `deploy/regional/tests/content-storage.tftest.hcl`'s opening comment: mocked applies "prove nothing about AWS enforcement, real alias/aws/s3 key ARNs or actual replication behaviour").

## Account-level suites (`deploy/account/tests`)

Four `.tftest.hcl` suites cover the account root and its `modules/shared-iam` submodule, plus one Python test that uses an entirely different mechanism.

| Suite | What it covers |
| --- | --- |
| `baseline.tftest.hcl` | The account singleton contract: one shared identity set and `regional_iam_contract` output instead of regional identity copies, the Bedrock budget/notification configuration, OIDC provider create/reference/adoption modes, custom role-name-prefix validation (including the exact 36-character boundary that keeps generated IAM role names at 64 characters), model-agreement preservation, rejection of wildcard Bedrock service-trust regions and of silently dropping the legacy trust region, the metrics-read identity wiring, content-identity defaults, and a source-level `fileset`/`regexall` assertion that the account root contains no `aws_iam_role_policy` resources and no regional-only ARNs, while `modules/shared-iam` contains **exactly five** `aws_iam_role_policy_attachment` resources. |
| `shared-iam.tftest.hcl` | The `modules/shared-iam` submodule directly (`module { source = "./modules/shared-iam" }`): identity trust policies, resource tags, the five common managed-policy attachments, explicit multi-Region Bedrock invocation-logging trust, and the metrics-read role's opt-in behavior and fail-closed caller-allowlist validation (rejecting wildcards, account-root callers, repeated callers, unbounded or too-short sessions, and whitespace). |
| `content-publishing.tftest.hcl` | The three content-publisher GitHub Actions OIDC identities (exact-subject trust, no wildcard repository/branch/audience, no injected subjects, no pull-request refs as branches), content-replication identity independence from audit replication, custom-prefix propagation, and the stable output contract. |
| `ecr-lambda.tftest.hcl` | The account-owned source ECR repository for the create-investigation Lambda image: opt-in creation, immutability/retention settings, source-owned and filtered replication to Regional destinations, rejection of replicating into the source Region or the wrong primary Region, and migration-input consistency checks (`legacy_workspace_input_preserves_existing_replication_before_meta_apply`, `conflicting_migration_inputs_are_rejected`). |

`deploy/account/tests/test_replication_topology.py` is a **different test mechanism**, not a `.tftest.hcl` suite: it is a standalone Python `unittest` module that reads `hcp-terraform/rosa-boundary/main.tf` as text, slices out its `locals` block up to the `module "rosa_boundary"` block, writes that slice into a temporary module, and shells out to `terraform console` to evaluate `jsonencode(local.replication_topology)`. It asserts the existing ECR-only topology and inactive S3 destination are preserved, that a populated content-replication handoff keeps the same destination key, that every HCP Terraform workspace variable block receives `local.replication_topology.<stage>` under a single `replication` key (and that the old `lambda_ecr_replication_regions`/`content_replication_destinations` keys are gone from the generator), that the corresponding `moved` blocks exist in `moved.tf` so Terraform treats the old variable as renamed rather than deleted, and that `deploy/account/variables.tf` and `deploy/regional/variables.tf` declare the `replication` variable with an identical type. Because it drives `terraform console` against a HCL fragment rather than running `terraform test`, it is invoked separately (for example `python3 -m pytest deploy/account/tests/test_replication_topology.py`), not via `make --directory=deploy/account test`.

## Regional-level suites (`deploy/regional/tests`)

Four `.tftest.hcl` suites cover the regional root. All of them mock the same core AWS data/resources (`aws_kms_alias`, `aws_s3_bucket`, `aws_partition`, `aws_caller_identity`, `aws_region`, `aws_iam_role`, `aws_iam_openid_connect_provider`, and — where the module creates them — `aws_lambda_function`, `aws_cloudwatch_event_rule`, `aws_ecs_cluster`, `aws_efs_file_system`, `aws_efs_access_point`, `aws_kms_key`, `aws_cloudwatch_log_group`) and override `aws_s3_bucket.content`'s ARN/ID so the shared `aws_s3_bucket` mock doesn't collide the content bucket with the audit bucket under test.

### `iam-ownership.tftest.hcl`: the ownership invariant

This suite's `mock_provider "aws"` block mocks `aws_kms_alias`, `aws_lambda_function`, `aws_cloudwatch_event_rule`, `aws_s3_bucket`, `aws_ecs_cluster`, `aws_efs_file_system`, `aws_efs_access_point`, `aws_kms_key`, `aws_cloudwatch_log_group`, `aws_partition`, `aws_caller_identity`, `aws_region`, `aws_iam_role`, and `aws_iam_openid_connect_provider`, alongside `mock_provider "archive" {}`; an `override_resource` block gives `aws_s3_bucket.content` a distinct test ARN/ID so it doesn't inherit the shared audit-bucket mock's ARN. This current setup still matches what the suite exercises.

The invariant it asserts is **regional/account IAM ownership separation**: the regional root must create zero `aws_iam_role` or `aws_iam_openid_connect_provider` resources, zero `aws_iam_role_policy_attachment` resources, and no `aws_iam_role_policies_exclusive`/`aws_iam_role_policy_attachments_exclusive` reconciliation anywhere in its `.tf` files (checked with a source-level `fileset`/`regexall` scan, plus a check that `account-handoff.tf` contains no `from = aws_iam_role_policy.` moved blocks) — all shared identities and managed attachments live in the account workspace's `modules/shared-iam`, and the regional root only *looks them up* via `data.aws_iam_role`/`data.aws_iam_openid_connect_provider` and attaches inline grants to them. A companion assertion confirms every `aws_iam_role_policy` in the regional root attaches to one of those looked-up `data.aws_iam_role` identities (task, execution, sre_shared, lambda_invoker, create_investigation_lambda, reap_tasks_lambda, reap_investigations_lambda, bedrock_invocation_logging, s3_replication), never to a locally created role. Further runs confirm the thirteen legacy inline policy names and their exact JSON scopes are unchanged in the legacy Region, that a second Region (`us-west-2`) renders the **same identities but distinct, suffixed policy names** and Region/account-scoped ARNs instead of copying the legacy Region's grants, that the designated "legacy" owner Region is whatever `legacy_policy_region` is set to rather than a hardcoded `us-east-1`, and that the investigation reaper's EFS mount/write/root-access grant — in both the Lambda's inline policy and the EFS file-system policy — is conditioned on its own dedicated `aws_efs_access_point.reaper`, never a bare file-system-wide grant. A separate pair of runs shows the optional account-owned metrics-read grant is opt-in, never looks up the account role when disabled, and is rejected at variable-evaluation time (before any role lookup) if the calling Region doesn't match `legacy_policy_region`. These are configuration-shape checks under mocking — they prove Terraform renders ownership-correct, non-colliding grants, not that a live AWS account enforces them or that cross-workspace state lookups succeed against real account state.

### `claude_default_model.tftest.hcl`: the model/agreement consistency guard

This suite verifies the `claude_default_model` ↔ `bedrock_model_agreements` consistency guard implemented as an input-variable validation in `deploy/regional/variables.tf`: `claude_default_model` must be a known Bedrock inference-profile ID — a key in `local.claude_inference_profile_foundation_models` — that resolves to a foundation-model ID present in `bedrock_model_agreements`. A bare foundation-model ID (not an inference-profile ID) is rejected even if that foundation model is itself approved.

Because this validation is evaluated during `plan`, the suite still has to satisfy every other precondition the module checks before Terraform reaches it: `mock_provider "aws"` mocks `aws_kms_alias`, `aws_s3_bucket`, `aws_iam_role`, and `aws_iam_openid_connect_provider` so IAM ARNs read via data sources resolve during planning; an `override_data` block gives `data.aws_partition.current` a real `aws` partition so interpolated IAM policy ARNs are valid strings under mocking; and two more `override_data` pairs put both test subnets in the same VPC with distinct availability-zone IDs (satisfying the Bedrock-endpoint precondition that subnets span one AZ each in one VPC) and give each subnet's route table a default route (satisfying the `subnet_outbound_routing` precondition). With those preconditions satisfied, each `run` block's `plan` succeeds or fails purely on the `claude_default_model` validation under test: `approved_sonnet5_profile_succeeds` sets `claude_default_model = "us.anthropic.claude-sonnet-5"` against `bedrock_model_agreements = { "anthropic.claude-sonnet-5" = "offer-test" }` and expects no failures; `bare_foundation_model_rejected` sets `claude_default_model = "anthropic.claude-sonnet-5"` (the bare foundation-model ID, not an inference-profile ID) against the same agreement map and expects `var.claude_default_model` to fail; `unapproved_foundation_model_fails` keeps the valid inference-profile ID but points `bedrock_model_agreements` at a different foundation model (`anthropic.claude-opus-5`), so the profile's resolved foundation model is absent from the agreement map and `var.claude_default_model` fails again.

### `content-storage.tftest.hcl`

The largest regional suite (36 `run` blocks) covers the per-Region published-content bucket: the bucket and the task's read grant exist unconditionally in every Region without opt-in, while publisher and replication grants stay absent until role ARNs/destinations are supplied; bucket protections (encryption, versioning, public-access block); publisher/runtime grants kept minimal; non-legacy-Region policy names carrying the Region suffix (mirroring the `iam-ownership` suite's naming contract); replication rules and their IAM grant; two destinations keeping replication-rule priorities unique across Regions; and a long list of `content_prefixes` input-validation rejections — empty, non-directory, overlapping, duplicate, reserved-bootstrap, wildcard (bare `*` and prefix-spanning), IAM-policy-variable syntax, whitespace, and colon-containing prefixes — plus rejections of path-qualified publisher/replication role ARNs, publishing/replication grants placed on the wrong role (task or audit), cross-Region replica key mismatches, and replicating a destination back into its own source Region. A final block of runs exercises the content-replica side: a replica accepts a shared, populated topology without needing its own source-side grants, an unpopulated destination leaves content inactive, and a replica still validates bucket metadata, key Region, and rejects publisher handoff.

### `ecr-lambda-destination.tftest.hcl`

Covers the regional root's **destination** ECR repository for the create-investigation Lambda image (the counterpart to the account root's **source** repository tested by `ecr-lambda.tftest.hcl`): the destination repository and lifecycle policy are opt-in and absent by default; when configured, the destination mirrors the source repository's immutability, `force_delete`, `AES256` encryption, scan-on-push, and 25-image lifecycle retention without switching the running Lambda over to it, and provisions a `quay` ECR pull-through cache rule so the rendered image URI resolves through `rosa-boundary-quay`; and configuring a destination Region equal to the account's own source Region is rejected (`source_region_cannot_duplicate_account_repository`, asserted via `expect_failures` on the destination repository resource itself).

## Running the suites

The account Makefile exposes its suites through `make --directory=deploy/account test`, which runs `terraform test`. The regional root's `Makefile` defines `init`, `fmt`, `validate`, `plan`, and `apply` but **no `test` target**, so `deploy/regional/tests/*.tftest.hcl` must be run with `terraform test` directly from `deploy/regional` (or wrapped in CI tooling outside the Makefile) — do not assume a `make test` invocation exists there, and do not mistake `make validate` for exercising the test files. `deploy/account/tests/test_replication_topology.py` is outside both Makefiles' `test` targets entirely and must be selected explicitly with a Python test runner, as described above.

## What these suites do and do not prove

Every suite here runs against Terraform's in-memory mocked state, never a deployed AWS account. They prove that the two roots render the intended resource names, IAM policy JSON, attachment targets, trust conditions, and input-variable rejections — including resource-name collisions avoided across Regions, exclusive ownership of shared IAM identities kept in the account workspace, and Bedrock model/Region guards enforced before `apply`. They do not prove that AWS accepts those policies, that cross-workspace `data.aws_iam_role`/`data.aws_iam_openid_connect_provider` lookups succeed against real account state, that S3/ECR replication actually copies objects, or that a live `terraform apply` succeeds end to end. Use an approved deployed-environment verification (plan/apply against a real HCP Terraform workspace — see [HCP Terraform workspaces](../infrastructure/hcp-terraform-workspaces.md)) for those claims, and treat this page's suites as the fast, credential-free guard against configuration regressions in ownership, scoping, and input validation. [Trusted Actions testing and CI](trusted-actions-testing.md) documents the separate, independently-moduled component's own unit/integration test strategy, which this page does not cover.

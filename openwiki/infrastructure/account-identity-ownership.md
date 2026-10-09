---
type: infrastructure-ownership
title: Account-level IAM identity and budget ownership
description: Explains how the deploy/account Terraform root and its shared-iam module own ROSA Boundary's IAM role identities, trust policies, OIDC providers, common managed-policy attachments, and the account-wide Bedrock budget/model agreements, and how these were migrated from the former regional-owned identities.
tags: [terraform, iam, aws, bedrock, identity, migration, account-root]
verified:
  - by: openwiki/0.7.1
    at: 2026-10-09T17:04:25.482Z
sources:
  - id: openwiki-source-aae9d35abe4e9dea115f5663
    resource: repo://deploy/account/bedrock-budget.tf
  - id: openwiki-source-7182e154441e0f90fda05986
    resource: repo://deploy/account/bedrock-model-agreements.tf
  - id: openwiki-source-4f2f75f7a0f4728ad23e5678
    resource: repo://deploy/account/imports.tf
  - id: openwiki-source-7abd92951c465f5a76e176f4
    resource: repo://deploy/account/main.tf
  - id: openwiki-source-6b03d2d17a5b9eb3f358798b
    resource: repo://deploy/account/modules/shared-iam/bedrock-logging.tf
  - id: openwiki-source-e0e8c15f232fd81f46f03e41
    resource: repo://deploy/account/modules/shared-iam/iam.tf
  - id: openwiki-source-65e02007ebea688b767a848b
    resource: repo://deploy/account/modules/shared-iam/lambda-create-investigation.tf
  - id: openwiki-source-d25a030029a9183fad61b582
    resource: repo://deploy/account/modules/shared-iam/lambda-invoker.tf
  - id: openwiki-source-ca5deb97ae20b796aad13c09
    resource: repo://deploy/account/modules/shared-iam/lambda-reap-tasks.tf
  - id: openwiki-source-4fc80bc41a09c6cab048d0ca
    resource: repo://deploy/account/modules/shared-iam/main.tf
  - id: openwiki-source-c2905a327012a93813a2dd05
    resource: repo://deploy/account/modules/shared-iam/oidc.tf
  - id: openwiki-source-ee86c0d48b646d4bc6813442
    resource: repo://deploy/account/outputs.tf
  - id: openwiki-source-45393b666c4d8ce854ed025b
    resource: repo://deploy/account/README.md
  - id: openwiki-source-13bc46f3694506473af729bc
    resource: repo://deploy/account/tests/baseline.tftest.hcl
  - id: openwiki-source-e63bbacd264bc409c45ddf07
    resource: repo://deploy/account/tests/shared-iam.tftest.hcl
  - id: openwiki-source-03f3d05fc1af60a151214ce7
    resource: repo://deploy/account/variables.tf
  - id: openwiki-source-461b24bea8fa463d1763c8c2
    resource: repo://deploy/regional/account-handoff.tf
  - id: openwiki-source-6697a0d2171b442a1f541cf8
    resource: repo://deploy/regional/account-iam.tf
  - id: openwiki-source-81722021d767635aca673ab8
    resource: repo://hcp-terraform/rosa-boundary/main.tf
generated: { by: "openwiki/0.7.1", at: "2026-10-09T17:04:25.482Z" }
---

# Account-level IAM identity and budget ownership

`deploy/account` is a separate Terraform root, with its own state, that owns
ROSA Boundary's **account-global** resources: IAM role identities and trust
policies, OIDC providers, the two sets of common AWS-managed policy
attachments, the account-wide Bedrock monthly budget, and the approved Bedrock
model agreements. [`deploy/regional`](../infrastructure/regional-runtime.md)
keeps the regional inline permission grants on those same roles plus all
ECS/EFS/S3/KMS/Lambda/logging resources and resource policies. See
[Identity and Access](../architecture/identity-and-access.md) for how the
runtime (SRE OIDC login, ECS tasks, Lambdas) actually consumes these
identities at request time, and [Regional Runtime](../infrastructure/regional-runtime.md)
for the data-source/inline-policy side of the split.

Account identity creation has no dependency on regional resource ARNs,
temporary ARNs, remote state, or any regional resource existing first; the
reverse direction (regional roots looking up roles/providers by name) is the
only coupling between the two roots.

## Ownership split

| Owner | Resources |
| --- | --- |
| Account | Execution, task, shared SRE, invoker, create-investigation Lambda, reaper Lambda, Bedrock logging, and optional S3-replication role **identities and trust policies** |
| Account | ECS execution managed-policy attachment and the two Lambda `AWSLambdaBasicExecutionRole` attachments |
| Account | OIDC providers (primary/stage/prod Keycloak), the Bedrock monthly budget, and approved Bedrock model agreements |
| Regional | Execution Secrets Manager, task audit/Bedrock/Exec/logging/KMS, SRE ABAC/lifecycle, invoker, Lambda lifecycle, Bedrock log-delivery, and optional replication **inline policies** |
| Regional | ECS/EFS/S3/KMS/Lambda/logging resources, regional resource policies, and invocation-logging configuration |

Because IAM identities are account-global, splitting ownership by Terraform
root does **not** make the roles regional or isolate permissions per region:
each shared role receives the **union** of every consuming region's inline
grants. Each regional inline policy keeps its own explicit resource scope and
ABAC conditions, and every `(role, policy-name)` pair, and every
`(role, managed-policy ARN)` attachment, has exactly one Terraform owner.
Neither root configures `inline_policy`, `managed_policy_arns`, or the
`*_exclusive` IAM resources on these shared roles — doing so would wipe out
grants owned by the other root/region. Introducing distinct, non-shared roles
would be a separate isolation decision, not a byproduct of this ownership
split.

## `deploy/account` layout

- `main.tf` — provider/version pinning (`hashicorp/aws ~> 6.0`, Terraform
  `>= 1.15, < 2.0`, matching `deploy/regional`), the account-wide
  `provider "aws"` block guarded by `allowed_account_ids`, and the
  `module "shared_iam"` call.
- `oidc.tf` — the three `aws_iam_openid_connect_provider` singletons
  (`keycloak`, optional `stage_keycloak`, optional `prod_keycloak`), each
  retaining its original URL, client ID, thumbprint, and `Name` tag.
- `bedrock-budget.tf` — the account-wide Bedrock budget (see below).
- `bedrock-model-agreements.tf` — the approved model-agreement manifest (see
  below).
- `imports.tf` — declarative `import` blocks used only during handoff (see
  below).
- `outputs.tf` — `shared_roles` (name/ARN for every role, consumed by regional
  roots via data lookups), `regional_iam_contract`
  (`account_role_name_prefix` + `legacy_policy_region`, the two values every
  regional root must copy), `oidc_provider_arn`, and `bedrock_budget_name`.
- `modules/shared-iam/` — the actual identity resources, described next.

### `modules/shared-iam` module

- `main.tf` — provider/version block, `data "aws_caller_identity"` /
  `data "aws_partition"`, and `local.common_tags` (`Project`, `Stage`,
  `Region = var.legacy_role_tag_region`, `ManagedBy = "Terraform"`).
- `iam.tf` — `aws_iam_role.execution` (ECS task-execution trust) with its
  `AmazonECSTaskExecutionRolePolicy` attachment, `aws_iam_role.task`, and the
  optional `aws_iam_role.s3_replication` (trusts `s3.amazonaws.com`).
- `oidc.tf` — `local.*_oidc_provider_domain`, derived by splitting each
  provider ARN on `oidc-provider/`, and `aws_iam_role.sre_shared`: a single
  ABAC role with one `AssumeRoleWithWebIdentity` + `sts:TagSession` trust
  statement per configured Keycloak issuer (primary always present, stage and
  prod conditional on their issuer URLs), each matching `aud` against its own
  OIDC client ID and optionally enforcing a UUID allowlist
  (`aws:RequestTag/uuid`) and/or a required OIDC group/role
  (`aws:RequestTag/roles`). Preconditions fail the plan if
  `enable_uuid_allowlist` is set with an empty `allowed_uuids`, or if
  `enable_oidc_group_enforcement` is set with an empty `required_oidc_role`.
- `lambda-invoker.tf` — `aws_iam_role.lambda_invoker`, trust policy identical
  in shape to `sre_shared` (same per-issuer statements) but with a fixed
  `max_session_duration = 3600`; SREs assume it via
  `AssumeRoleWithWebIdentity` to get SigV4 credentials for calling the
  create-investigation Lambda function URL, which performs its own
  application-level OIDC validation as a second layer.
- `lambda-create-investigation.tf` / `lambda-reap-tasks.tf` — the two Lambda
  execution roles (`lambda.amazonaws.com` trust) plus their
  `AWSLambdaBasicExecutionRole` attachments, owned once here even though
  regional Terraform adds each Lambda's operational inline policy.
- `bedrock-logging.tf` — `aws_iam_role.bedrock_invocation_logging`, trusted by
  `bedrock.amazonaws.com` with `aws:SourceAccount` pinned to the caller
  account and `aws:SourceArn` restricted (via `ArnLike`) to
  `arn:<partition>:bedrock:<region>:<account>:*` for every region in
  `var.bedrock_logging_source_regions`. A single-region list is JSON-encoded
  as a scalar rather than a one-element list, to avoid an unwanted diff when
  the original trust policy used IAM's scalar form.
- `variables.tf` / `outputs.tf` — module inputs and the `roles` output map
  consumed by the root's `shared_roles` output.

Every inline-grant file (execution Secrets Manager, task audit/Bedrock/Exec/
logging/KMS, SRE ABAC/lifecycle, invoker, Lambda lifecycle, Bedrock
log-delivery, replication) lives in `deploy/regional`, not in this module;
`deploy/account/tests/baseline.tftest.hcl` asserts no `aws_iam_role_policy`
resource exists anywhere under the account root.

## Bedrock budget and model agreements

`bedrock-budget.tf` defines a single `aws_budgets_budget.bedrock`: an
account-wide **cost-visibility singleton**. Its `cost_filter` matches the
`Amazon Bedrock` service across the whole AWS account/region, so it tracks
**all** Bedrock spend, not only charges generated by ROSA Boundary. It emits
`ACTUAL` threshold notifications at 50/80/100% of
`var.bedrock_monthly_budget_usd` to `var.bedrock_budget_notification_email`;
these notifications are informational only and never throttle or block
inference.

`bedrock-model-agreements.tf` manages `aws_bedrock_foundation_model_agreement`
entries from `var.bedrock_model_agreements`, an explicit `model_id -> offer_id`
map that must be reviewed and pinned in configuration. At plan time, a
`data "aws_bedrock_foundation_model_agreement_offers"` lookup retrieves the
current offers for each model, and a precondition fails the plan if the
approved `offer_id` is no longer among them (forcing re-review before
applying). The actual `offer_token` used to accept the agreement is resolved
from that same lookup and then set to `ignore_changes = [offer_token]`,
because AWS can rotate the token value without changing the approved offer
ID. Management happens once, against the original regional Bedrock API
endpoint preserved in `var.aws_region`; per AWS's model-access documentation,
activating a model in one region typically makes the entitlement usable in
other supported regions, but this does **not** by itself guarantee regional
model availability or grant any IAM invocation permission — both remain
separate, regional concerns.

Regional Terraform (`deploy/regional`) receives the same
`bedrock_model_agreements` manifest and uses it only to **validate** the
configured default model (`claude_default_model`) against the approved
manifest; it never creates, modifies, or revokes agreements itself. See
`deploy/regional/tests/claude_default_model.tftest.hcl` for that validation
behavior.

## Naming, tagging, and quota contract

- **`role_name_prefix` / `account_role_name_prefix`**: the account root's
  `role_name_prefix` (default `${project}-${stage}`) must equal every
  regional root's `account_role_name_prefix`, since regional roots resolve
  role names by string concatenation (`data "aws_iam_role"` lookups), not by
  remote-state reference. `deploy/account/outputs.tf` republishes this value
  via `regional_iam_contract.account_role_name_prefix` for consuming regions
  to copy.
- **`legacy_policy_region`**: exactly one region keeps unsuffixed inline
  policy names (e.g. `s3-audit-access`); every other region appends
  `-${aws_region}` to its policy names on the same shared roles
  (`deploy/regional/account-iam.tf` computes
  `local.regional_policy_suffix`). This is a cross-workspace naming contract,
  not a per-region choice — every regional workspace must agree on the same
  `legacy_policy_region` value, and it is also exposed via
  `regional_iam_contract.legacy_policy_region`.
- **10,240-character inline-policy quota**: AWS limits the aggregate size of
  a role's inline policies to 10,240 characters (excluding whitespace).
  Region-qualified policy names avoid name collisions when adding more
  regions but do not raise this per-role quota; before onboarding another
  region onto the shared roles, check the aggregate size budget.
- **`legacy_role_tag_region`**: preserves the shared roles' original `Region`
  tag (`local.common_tags.Region` in `modules/shared-iam/main.tf`), even
  though the roles themselves are account-global. It also serves as the
  default source region for Bedrock logging trust (see below) when
  `bedrock_logging_source_regions` is left empty.
- **`bedrock_budget_tag_region`**: separately preserves the Bedrock budget's
  original `Region` tag (`deploy/account/main.tf` `local.common_tags`); it
  has no default and must be copied from the existing deployment's active
  value, like the budget limit and notification email.
- **`bedrock_logging_source_regions`**: an explicit allowlist of regions
  permitted in the Bedrock delivery role's `aws:SourceArn` trust condition.
  An empty list retains only `legacy_role_tag_region`, preserving the
  original single-region trust; a variable validation rejects wildcards and
  requires the legacy region to remain included whenever other regions are
  added, so the restriction can only be deliberately widened, never dropped
  or replaced with `*`.

## Migration / handoff mechanics

These resources used to be created per-region inside `deploy/regional`. For
existing deployments, ownership moves to `deploy/account` through a
state-transfer procedure (not a destroy/recreate):

1. **Freeze** applies in both roots and inventory existing names, trust JSON,
   tags, OIDC settings, and budget/model values, including which regional
   inline policies must stay in regional state.
2. **Release from regional state.** `deploy/regional/account-handoff.tf`
   contains `removed { lifecycle { destroy = false } }` blocks for every
   shared-identity resource: `aws_iam_role.s3_replication`,
   `aws_iam_role.execution`/`aws_iam_role_policy_attachment.execution_managed`,
   `aws_iam_role.task`, the three `aws_iam_openid_connect_provider` resources,
   `aws_iam_role.sre_shared`, `aws_iam_role.lambda_invoker`,
   `aws_iam_role.create_investigation_lambda`/its basic-execution
   attachment, `aws_iam_role.reap_tasks_lambda`/its basic-execution
   attachment, `aws_iam_role.bedrock_invocation_logging`,
   `aws_budgets_budget.bedrock`, and
   `aws_bedrock_foundation_model_agreement.approved`. `destroy = false` tells
   Terraform to drop these addresses from regional state **without** issuing
   any AWS delete calls. Regional inline policies are never listed here and
   must remain at their original regional addresses, still attached to the
   same roles.
3. **Import into account state.** `deploy/account/imports.tf` declares
   `import` blocks, gated by `var.adopt_existing_resources`, that adopt the
   same live objects by their natural AWS identifiers: role names for
   `aws_iam_role.*`, `role/managed-policy-arn` for the two
   `aws_iam_role_policy_attachment` resources, the OIDC provider ARN
   (`arn:<partition>:iam::<account>:oidc-provider/<issuer-host-and-path>`)
   for each `aws_iam_openid_connect_provider`, and `account:name`
   (`${aws_account_id}:${project}-${stage}-bedrock-monthly`) for
   `aws_budgets_budget.bedrock`. `bedrock-model-agreements.tf` has its own
   `import` block, also gated by `adopt_existing_resources`, that imports
   each `aws_bedrock_foundation_model_agreement.approved[model_id]` by model
   ID. No regional inline policy is ever imported into account state.
4. Apply the account plan and verify it performs **only** imports — no
   replacement, trust/name/tag drift, budget modification, or agreement
   cancellation — then set `adopt_existing_resources = false`, confirm clean
   plans in both roots, and unfreeze. A failed import leaves the live AWS
   object untouched, so the freeze should persist until adoption succeeds;
   a partially failed import must not be "fixed" by letting Terraform
   recreate the resource.

Plain Terraform `moved` blocks are not used across states (they only work
within a single state); the `removed`-then-`import` pair is the only
supported mechanism for this cross-state ownership transfer. If multiple
existing regional states already share one of these objects (one budget or
provider reused by several regions, for example), it must be released from
every one of those states before the single `import` in account state, since
two states must never both manage the same object. For a brand-new
deployment, no handoff is needed: `adopt_existing_resources` stays `false`,
and the account root is simply applied before the first regional root.

## Account-level test suites

Both suites use `mock_provider "aws"` with mocked data sources
(`aws_partition`, `aws_caller_identity`, and, for the root suite,
`aws_bedrock_foundation_model_agreement_offers`); neither suite makes live
AWS calls, and assertions check Terraform-plan/apply output, not real AWS
state.

- **`deploy/account/tests/baseline.tftest.hcl`** exercises the root module.
  Representative runs:
  - `account_singletons_and_shared_contract_without_regional_resources`
    confirms all eight shared roles exist exactly once
    (`length(output.shared_roles) == 8`), that `regional_iam_contract`
    exposes the expected prefix/legacy-region pair, that the budget keeps its
    name/limit/notifications/`Region` tag, and that the OIDC providers remain
    singletons with their original URL/client ID/tags. It also runs
    source-level regexp assertions (via `file()`/`fileset()`) proving the
    account root never defines `aws_iam_role_policy`, never references
    regional remote-state/resource-ARN variables, never configures
    `inline_policy`/`managed_policy_arns`/`*_exclusive` resources inside
    `modules/shared-iam`, defines exactly three
    `aws_iam_role_policy_attachment` resources, and never references any
    regional resource type (`aws_ecs_cluster`, `aws_efs_file_system`,
    `aws_s3_bucket`, `aws_kms_key`, `aws_cloudwatch_log_group`,
    `aws_lambda_function`) anywhere under the account root.
  - `optional_oidc_singletons` / `custom_shared_prefix` /
    `invalid_prefix_rejected` / `longest_valid_prefix` /
    `too_long_prefix_rejected` cover the optional stage/prod OIDC providers
    and the `role_name_prefix` validation boundaries (1–36 IAM-safe
    characters).
  - `model_activation_preserves_manifest` checks that the approved offer
    resolves to the mocked offer token while preserving the model ID.
  - `wildcard_service_trust_region_rejected` and
    `legacy_bedrock_trust_cannot_be_silently_dropped` assert the
    `bedrock_logging_source_regions` validation rejects `"*"` and rejects
    dropping the legacy region from a non-empty list.

- **`deploy/account/tests/shared-iam.tftest.hcl`** exercises
  `modules/shared-iam` directly (`module { source = "./modules/shared-iam" }`)
  across all three OIDC issuers at once (primary, stage, prod configured
  simultaneously). Representative runs:
  - `legacy_identity_trust_tags_and_common_attachments` asserts all eight
    legacy role names survive unchanged, that `sre_shared` and
    `lambda_invoker` share an identical three-statement trust policy shape
    (one `Federated` principal per configured issuer, each with its own
    `aud` condition and the same UUID/group conditions) but differ in
    `max_session_duration` (7200 vs. the fixed 3600), that
    execution/task/Lambda roles keep their AWS-service trust, that the
    Bedrock logging role's `SourceAccount`/`SourceArn` condition matches the
    single configured source region, that the two managed-policy
    attachments point at the right roles/ARNs, and that every role carries
    the expected `Region`/`Project`/`Stage`/`ManagedBy`/custom tags plus a
    role-specific `Name` tag.
  - `explicit_multi_region_bedrock_trust` confirms that listing two source
    regions produces an `ArnLike` condition with both ARNs (the list form,
    not the scalar form).
  - `empty_uuid_allowlist_fails_closed` confirms the `sre_shared` role's
    precondition fails the plan (`expect_failures`) when
    `enable_uuid_allowlist = true` but `allowed_uuids = []`.

## HCP Terraform workspace

A matching HCP Terraform workspace, `rosa-boundary-stage-account`
(`working_directory = "deploy/account"`), is registered alongside
`rosa-boundary-stage-regional` and the other `rosa-boundary` workspaces in
`hcp-terraform/rosa-boundary/main.tf`. It is pinned with
`auto_apply = false` and `auto_apply_run_trigger = false` — kept on manual
apply deliberately while the team validates that post-adoption plans stay
clean — and carries the staging values for all the contract variables
described above (`role_name_prefix`, `legacy_policy_region`,
`legacy_role_tag_region`, `bedrock_budget_tag_region`,
`bedrock_model_agreements`, OIDC issuer/thumbprint/client settings, and
`adopt_existing_resources = false` once the one-time import completed). See
[HCP Terraform Workspaces](../infrastructure/hcp-terraform-workspaces.md) for
how this workspace fits into the broader workspace graph (network, AWS
credentials, account, and regional workspaces and their apply ordering/gates).

## Invariants and failure modes

- Account identity creation never depends on regional resource ARNs or
  remote state; regional roots depend on account identities existing (by
  name/issuer URL), not the reverse.
- Destroying regional consumers and their inline policies must happen before
  destroying account roles; splitting ownership does not create an automatic
  cross-workspace dependency graph, so the account workspace's destroy plan
  must be coordinated manually with every consuming region.
- Removing one region's grants (or one region's workspace) must never affect
  another region's policies or the common attachments — each is isolated by
  distinct Terraform addresses/state, not by any runtime scoping.
- The account workspace can produce a plan before adoption completes, but
  that create-mode plan must never be applied against already-existing,
  regional-owned identities, budget, or model agreements — only the reviewed
  `adopt_existing_resources = true` import plan may touch them.

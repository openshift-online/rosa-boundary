# Account infrastructure

One Terraform state per AWS account owns Boundary's shared IAM identities:
roles, trust policies, OIDC providers and common AWS-managed policy attachments.
The account-wide Bedrock monthly budget and model agreements also belong here.
This baseline adds no audit-reader role and does not manage organization access.

[`../regional`](../regional/README.md) owns ECS, EFS, S3, KMS, CloudWatch Logs,
Lambda functions, resource policies, and the **regional inline permission grants**
on the account roles. Regional deployments look up roles by name and OIDC
providers by issuer URL, without remote-state access. Account identity creation
does not require regional resource ARNs, temporary ARNs, or regional resources
to exist.

| Owner | Resources |
| --- | --- |
| Account | Execution, task, shared SRE, invoker, create-investigation Lambda, reaper Lambda, Bedrock logging and optional S3 replication role identities/trust |
| Account | ECS execution managed-policy attachment and the two Lambda basic-execution attachments |
| Account | OIDC providers, Bedrock budget and approved model agreements |
| Regional | Execution Secrets Manager, task audit/Bedrock/Exec/logging/KMS, SRE ABAC/lifecycle, invoker, Lambda lifecycle, Bedrock log delivery and optional replication inline policies |
| Regional | ECS/EFS/S3/KMS/Lambda/logging resources, regional resource policies and invocation logging configuration |

## Ownership and multi-region permissions

IAM identities are account-global. Terraform ownership of regional grants does
not make IAM roles regional or isolate permissions by region: shared roles receive
the **union** of all regional grants. Each regional policy retains explicit
resource scopes and existing ABAC conditions. Distinct roles would be a separate
trust/isolation decision, not a requirement of this ownership split.

Each inline policy and each `(role, managed-policy ARN)` attachment has exactly
one Terraform owner. Only the account root manages common AWS-managed
attachments. Do not configure exclusive inline/managed policy reconciliation,
`inline_policy`, or `managed_policy_arns` on shared roles: that would remove
regional grants. Regional inline policy names must be unique within each role;
one designated legacy region retains existing names and additional regions use
region-qualified names. Coordinate that naming contract across all deployments
using the same roles.

Before expanding to more regions, check the shared roles' aggregate inline
policy size: AWS limits it to **10,240 characters per role**, excluding whitespace.
Region-qualified names avoid overwrites but do not bypass this quota. A later
move to region-owned managed policies must preserve scopes and account for
attachment quotas; it is not part of this ownership migration. See
[IAM quotas](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html).

## Inputs and local commands

Use Terraform `>= 1.15, < 2.0` and public-registry `hashicorp/aws ~> 6.0`, matching
the regional root. Copy `terraform.tfvars.example` and supply the target account,
provider endpoint region, original issuer URLs/audiences/thumbprints, budget
limit/email and shared identity/trust settings. Preserve role prefixes, session
duration, UUID allowlist and OIDC group enforcement. Preserve the regional ABAC
key and keep it consistent with the issuer's principal-tag mapping in every
region; do not rely on defaults if an existing deployment uses different values.

- Account `role_name_prefix` defaults to `${project}-${stage}`. Each regional
  `account_role_name_prefix` must resolve to that same shared prefix.
- Account `legacy_role_tag_region` retains the original roles' Region tag.
- Regional `legacy_policy_region` must be set to the same designated original
  region in **every** consuming workspace. That region retains names such as
  `s3-audit-access`; other regions append `-${aws_region}`. It is an ownership
  contract, not something each region may independently set to itself.
- Account `bedrock_logging_source_regions` explicitly approves regions in the
  Bedrock delivery role's SourceArn trust condition. An empty list retains only
  `legacy_role_tag_region`, preserving original trust. Add a region deliberately
  before enabling its logging; do not replace the region restriction with `*`.
- Account `enable_s3_replication_role` creates the shared replication identity
  when any regional stack needs it; replication grants remain regional.

Preserve `tags`, provider `default_tags` and `ignored_tag_keys`, including the
original roles' Region tag even though their identities are account-global.
`bedrock_budget_tag_region` preserves the budget's original Region tag, not the
provider endpoint. Budget limit, notification email and tag region have no
defaults: copy the existing active values rather than silently choosing new ones.

```bash
make init
make fmt
make validate
make test               # Mock providers; no live AWS calls
make plan
make apply
```

`plan` and `apply` optionally source the repository-root `.env` (override with
`ENV_FILE`); use explicit `TF_VAR_*` values or a tfvars file. `TF_ARGS` passes
additional flags. State/backend configuration and HCP workspace wiring are
outside this baseline. Never reuse the regional backend/state.

## Existing deployment handoff

1. Freeze applies in both roots, back up both states, and inventory existing
   identities, common attachments and account singletons. Check actual names,
   trust JSON, role tags, OIDC audiences/thumbprints and budget/model settings.
   Separately inventory the regional policies that **remain in regional state**.
2. Configure the account with the exact existing role prefix, trust settings and
   tags. Configure the regional role lookup and designated legacy policy region
   to preserve all existing policy names. Enable the optional account replication
   identity if the existing deployment uses S3 replication.
3. Plan the regional root: `account-handoff.tf` must forget only IAM roles,
   common AWS-managed attachments, OIDC providers, budget and existing model
   agreements, **not destroy them**. Inline policies must stay at their original
   regional addresses, attached to the same roles with unchanged documents/names.
   Apply that reviewed handoff under the freeze. Existing identities allow the
   data lookups to succeed before account adoption.
4. Set account `adopt_existing_resources = true`. Plan optional declarative
   identity/attachment/singleton imports. Verify imports only: no replacement,
   trust/name/tag changes, budget modification, or agreement cancellation. No
   regional inline policy is imported into account state. Apply the reviewed plan.
5. Disable `adopt_existing_resources`, confirm clean plans in both roots, and
   unfreeze. A failed import leaves the AWS object intact; keep the freeze and
   finish adoption. Do not recreate a resource whose import failed.

Role import IDs are role names, attachments use `role/managed-policy-arn`, OIDC
uses provider ARN, and Budgets uses `account:name`. `removed` blocks forget the
whole address (including counted instances), with `destroy = false`. No `moved`
blocks are used across states. Keep release declarations until every relevant
old regional state has released ownership. This migrates from the original
regional state; the superseded account-owned per-region implementation was not
deployed and does not require a reverse migration.

If old states already share an OIDC provider, attachment, role or budget, release
it from every old state and import once. Never let multiple states manage the
same object. Multiple distinct existing identities or budgets require an explicit
inventory/consolidation plan; this baseline preserves the original deployment,
not an automatic merge of independent installations.

## New account bootstrap and teardown

Leave `adopt_existing_resources = false`. Apply account identities and common
attachments first. Then apply regional infrastructure and regional policies,
which reference the actual resource ARNs from that root. No placeholder EFS/KMS
IDs or follow-up account permission reconciliation are needed. Do not start
investigations until the regional permissions and infrastructure are ready.

Destroy regional consumers and their policies before destroying account roles.
Splitting state ownership does **not** create a cross-workspace lifecycle graph:
account role deletion must be coordinated with every consuming region. Removing
one region's grants must not remove another region's policies or common
attachments. Review a destroy plan with the same care as deployment.

HCP workspace registration, variable redistribution and live migration validation
remain pending. The staging meta-workspace is configured to disable regional
auto-apply and auto-apply on run triggers, but the gate must be verified in HCP
after reconciliation, including any queued runs. This scaffold does not change
regional ownership of shared identities, the Bedrock budget or model agreements,
or authorize applying the account root against existing staging resources.
Mocked tests do not prove live state-transfer safety.

## Bedrock model agreement scope

`bedrock-model-agreements.tf` owns account-wide model activation once. Keep
`aws_region` equal to the original agreement management endpoint during migration
and copy the full model/approved-offer map. Imports retain each model ID and the
existing regional API identity; original offer validation and
`ignore_changes = [offer_token]` remain unchanged. Never cancel or recreate
agreements as part of this handoff. The AWS
[model access guide](https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html)
explains that activation in one region makes the subscription usable in other
supported regions. This does not guarantee regional model availability or IAM
invocation permission. Regional roots require the same approved manifest for
default-model validation, but do not create or revoke agreements.

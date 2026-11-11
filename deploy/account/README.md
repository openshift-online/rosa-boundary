# Account infrastructure

One Terraform state per AWS account owns Boundary's shared IAM identities:
roles, trust policies, OIDC providers and common AWS-managed policy attachments.
The account-wide Bedrock monthly budget and model agreements also belong here.
This baseline adds no audit-reader role and does not manage organization access.

## Staging Lambda image repository

`enable_lambda_ecr_source` (off by default) manages the ordinary, private
`rosa-boundary/create-investigation-lambda` ECR repository in the account
provider Region. The staging account workspace enables it in `us-east-1` and
requires manual approval before applying plans. `us-east-1` is the Git-managed workspace's
`aws_region`, not an independent Lambda source-region variable: changing it also requires
coordinated app-interface ECR registration and Konflux release-destination and
credential changes. The repository uses AES256 encryption, immutable tags,
scan-on-push and a 25-tagged-image retention policy; `force_delete` is disabled.
Same-account publication relies on IAM permissions of the generated ECR
credential's role; no cross-account repository policy is configured.

`replication` (null by default) configures a single
registry-wide, prefix-filtered ECR replication rule from the source repository
to the listed Regions in the same account. Stage the `us-west-2` destination
repository first; only after that workspace applies, set the account workspace
`replication.destinations` to include `us-west-2` in a separate PR. Staging workspaces require manual
applies; approve them in dependency order rather than assuming ordering within
a single meta-workspace change.
The filter is a **prefix**, not an exact repository-name match. ECR replication
configuration is a whole-registry singleton: before merging an enabling change,
confirm its plan does not replace unrelated rules. If other rules already exist,
import the existing configuration into this account state and model all rules
together instead of overwriting them. This configuration does not manage the
regional Lambda image URI or destination ECR repositories. The existing Quay
pull-through-cache rule and Lambda image URI remain in the regional root.
For a new account or repository, check for an existing repository in the
account/Region (import instead of creating a duplicate), verify account and
Region, and confirm the credential role's push scope **before enabling** this
resource. Review and explicitly approve the account's AWS resource plan before
applying; keep automatic applies disabled (see
[`docs/staging-deployment.md`](../../docs/staging-deployment.md)); the meta-workspace
speculative plan only shows the variable change. A Terraform plan does not
prove an image push.

[`../regional`](../regional/README.md) owns ECS, EFS, S3, KMS, CloudWatch Logs,
Lambda functions, resource policies, and the **regional inline permission grants**
on the account roles. Regional deployments look up roles by name and OIDC
providers by issuer URL, without remote-state access. Account identity creation
does not require regional resource ARNs, temporary ARNs, or regional resources
to exist.

| Owner | Resources |
| --- | --- |
| Account | Execution, task, shared SRE, invoker, create-investigation Lambda, reaper Lambda, Bedrock logging, optional S3 replication and optional metrics-read role identities/trust |
| Account | Optional GitHub Actions OIDC provider, content publisher role identities/trust and the dedicated content replication role identity |
| Account | ECS execution managed-policy attachment and the two Lambda basic-execution attachments |
| Account | OIDC providers, Bedrock budget and approved model agreements |
| Regional | Execution Secrets Manager, task audit/Bedrock/Exec/logging/KMS, SRE ABAC/lifecycle, invoker, Lambda lifecycle, Bedrock log delivery, optional replication and optional metrics-read inline policies |
| Regional | ECS/EFS/S3/KMS/Lambda/logging resources, regional resource policies and invocation logging configuration |

## Shared replication topology and content handoff

For HCP-managed deployments, `replication_topology` in
[`hcp-terraform/rosa-boundary/main.tf`](../../hcp-terraform/rosa-boundary/main.tf)
is the shared source of primary and replica Regions for ECR and published-content
S3. Each environment's `primary_region` supplies the account `aws_region`, the
primary regional `aws_region`, and the replica's Lambda ECR source Region.
The same environment object is passed as `replication` to the account and all
regional roots. Its `destinations` map keys select ECR replica Regions; optional
`content` metadata enables S3 for those same destinations. There is no independent
S3 Region list. Local deployments must pass that same object to both roots.
The former `content_replication_destinations` input is removed. The account
root temporarily accepts `lambda_ecr_replication_regions` as a migration fallback:
PR plans still see existing HCP inputs until the meta-workspace applies the
rename. When both inputs are present, their destination Regions must match.
Remove the fallback only after both account workspaces use `replication`; do not
approve deletion of the live ECR replication rule as part of this input rename.

A replica's `content = null` deliberately leaves S3 replication **inactive**;
it does not disable the existing ECR replication destination. Bootstrap and apply
the destination regional bucket first, then collect its `content_bucket_arn`,
`content_bucket_kms_key_arn`, `content_bucket_region`, and `content_prefixes`
outputs. In a separately reviewed PR replace that replica's null handoff with:

```hcl
content = {
  bucket_arn       = "<destination content_bucket_arn output>"
  kms_key_arn      = "<destination content_bucket_kms_key_arn output>"
  content_prefixes = { /* exact destination content_prefixes output */ }
}
```

The map key must match `content_bucket_region`; the exported prefix map must
match the source's map exactly. Do not construct a key ARN from `alias/aws/s3`,
a bucket name, or an assumed key ID. The primary regional root derives S3 rules
from this map; replica roots receive the same object but never own source
replication grants or rules, and must not get publisher grants. Also supply the account output
`content_replication_role_arn` to the primary before enabling; this topology
change does not create that grant or supply invented resource identities.

Both environments currently retain null content handoffs, so this change does
not activate S3 replication or change ECR's requested destination list. This is
a one-way output handoff via reviewed Git configuration, not remote-state access
or account ownership of regional buckets/keys. Keep workspace apply gates
unchanged, review downstream resource plans, and apply in dependency order.
Changing the primary Region also changes the account provider endpoint used
for model agreements: treat that as a migration, not a replication-only toggle.

Offline topology/handoff regression checks (no providers or credentials):

```bash
python3 -m unittest discover -s deploy/account/tests -p 'test_replication_topology.py' -v
```

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
- Account `enable_metrics_read_role` creates the optional identity an external
  metrics collector assumes; `metrics_read_trusted_principal_arns` is its trust
  allowlist and `metrics_read_session_duration` bounds its sessions. The role's
  permissions are the regional `enable_metrics_read_grant` inline policy, so the
  two must be enabled in that order - see below.
- Account `bedrock_logging_source_regions` explicitly approves regions in the
  Bedrock delivery role's SourceArn trust condition. An empty list retains only
  `legacy_role_tag_region`, preserving original trust. Add a region deliberately
  before enabling its logging; do not replace the region restriction with `*`.
- Account `enable_s3_replication_role` creates the shared replication identity
  when any regional stack needs it; replication grants remain regional.
- Every account creates or resolves the GitHub Actions OIDC provider and creates
  one publisher identity per source repository. Configure these with
  `create_github_actions_oidc_provider`, `content_publisher_sources` and
  `content_publisher_session_duration`. The dedicated content replication
  identity is also always created, independently of the audit replication flag.

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

`plan` and `apply` optionally source the trusted repository-root `.env`, as the
regional Makefile does; do not use an untrusted file there. Use explicit
`TF_VAR_*` values or a tfvars file. For additional Terraform flags, set
`TF_CLI_ARGS` or a subcommand-specific variable such as `TF_CLI_ARGS_plan`;
the Makefile does not interpolate flags into shell commands. State/backend
configuration and HCP workspace wiring are outside this baseline. Never reuse
the regional backend/state.

### Optional metrics-read role: sequencing and trust

Both halves are off by default and must be enabled in two separate, reviewed
applies. The regional root resolves the role **by name**, so enabling both at
once is unsafe: workspaces are not guaranteed to run in dependency order within
one meta-workspace change, and the regional lookup fails with
`NoSuchEntity` if it runs before the account apply.

1. Merge with both flags off. This is a no-op in every workspace.
2. Account workspace: set `enable_metrics_read_role = true` and
   `metrics_read_trusted_principal_arns`. Let it apply.
3. The **one** regional workspace whose `aws_region` equals `legacy_policy_region`:
   set `enable_metrics_read_grant = true`. Any other region fails the plan,
   because the grant is account-global and a second owner would only duplicate
   it. Note the coupling this creates: the capability lives wherever the
   designated legacy policy region lives, so decommissioning that workspace
   means re-homing this grant along with the other legacy-named policies.

Between steps 2 and 3 the role exists and is assumable but grants nothing. That
interim is the intended fail-safe: a caller gets `AccessDenied` on the metric
calls, not broader access. To reverse, disable the regional grant first, then
the account identity.

`metrics_read_trusted_principal_arns` must be complete caller ARNs -
`arn:aws:iam::<caller-account-id>:role/<caller-role>`, or an STS
`assumed-role/<role>/<session>` session ARN. Account roots, service principals,
partial names and wildcards are rejected by variable validation. Do not rely on
IAM to catch a wildcard: it rejects a partial wildcard such as `role/*`, but it
**accepts** a bare `*` as an anonymous principal, which would leave the role
assumable by anyone in the partition. The variable validation is the control
that prevents that. Prefer the plain role ARN: a session
ARN pins trust to one session name and stops matching if the caller renames its
sessions. Note that IAM stores role principals by unique ID, so deleting and
recreating a trusted caller role breaks trust until the policy is re-applied.

Supply the caller ARNs through a workspace **variable set**, not by inlining
them in the Git-managed meta-workspace definition, when the caller's account and
role name should not be published in this repository.

### Content publishing identities: provider modes, subjects and sequencing

Every deployment of this account root creates the three configured publisher
identities and creates or resolves the GitHub Actions OIDC provider. There is
no publisher enablement flag. This applies to development, staging and
production account plans; review provider ownership in each account before
applying. A dedicated content replication identity is always created.
It is **not** the audit replication
role created by `enable_s3_replication_role`. These identities carry no content
permissions: the prefix-scoped bucket and key grants belong to the regional
root, in a later change. Until those land, a role is assumable but holds no
content access from this configuration — the same intended fail-safe as the
metrics reader. That is a
statement about what this state declares, not a guarantee that no resource
policy elsewhere in the account names the role; verify the account if that
matters.

Role names and the published contract, which downstream regional and publishing
work consumes, are stable:

| Source key | Repository | Default branch | Role name |
| --- | --- | --- | --- |
| `ops-sop` | `openshift/ops-sop` | `master` | `<prefix>-publisher-ops-sop` |
| `managed-notifications` | `openshift/managed-notifications` | `master` | `<prefix>-publisher-managed-notifications` |
| `rosa-claude-plugins` | `openshift-online/rosa-claude-plugins` | `main` | `<prefix>-publisher-rosa-claude-plugins` |
| — | — | — | `<prefix>-content-replication-role` |

Publisher source keys allow up to 21 characters, and every generated IAM role
name must fit 64 characters. With the default sources, the longest suffix is
`-publisher-managed-notifications` (32 characters), so `role_name_prefix` must
be at most 32 characters. Longer prefixes require shorter custom source keys;
validation rejects combinations that exceed the IAM limit.

Outputs: `content_publisher_roles` (name, ARN, repository, branch and exact
subject per key), `content_publisher_role_arns`, `content_replication_role_arn`
and `github_actions_oidc_provider_arn`. The last is populated whether this state
created the provider or referenced an existing one, so a consumer never has to
know which. `shared_roles` is unchanged.

Each publisher trusts exactly one subject,
`repo:<owner>/<repo>:ref:refs/heads/<default-branch>`, with audience
`sts.amazonaws.com`, using `StringEquals` and a scalar value. The audience is a
literal and is not configurable. This is a repository/branch restriction, not a
merge-event restriction: scheduled, manually dispatched and `pull_request_target`
workflows can also match. Publishing workflows must not execute untrusted PR
code; review their triggers and permissions separately.

Two different things keep that narrow, and it is worth not conflating them:

- **Syntax validation** on `content_publisher_sources` rejects wildcards,
  colons, full refs and empty values. That is what stops any input becoming a
  pull-request, merge-ref or environment subject, because the subject is built
  from a fixed `repo:<repository>:ref:refs/heads/<branch>` template and no
  value can smuggle in its own `:` segment. It does **not** restrict which
  owner, repository or branch you configure: pointing a publisher at a fork or
  a different branch is possible, as a deliberate and reviewable configuration
  change. Introducing GitHub environment subjects, by contrast, would require a
  trust-policy change, not just configuration.
- **The configured sources** are what actually pin trust to the three agreed
  repositories and their default branches. The shipped defaults are those
  three, and the account tests assert the complete rendered subject set, so an
  unconfigured repository or branch is excluded by the rendered policy rather
  than by input validation.

On operators: `StringEquals` compares the subject literally, so a `*` in a
configured value would match no real token — inert, not broad. Rejecting `*` at
the input is therefore defence in depth: it keeps a stored value from becoming
a live wildcard if the condition operator were ever changed to `StringLike`,
where `*` and `?` are metacharacters. `StringLike` with a value containing no
metacharacter behaves like `StringEquals`; the hazard is the combination, not
either alone. Keep `StringEquals`.

Separate identities per repository are deliberate: one shared publisher would
let a compromised workflow in one repository write another's content once
grants exist.

The OIDC provider has three modes, because an account may already have one.
AWS permits one provider per issuer URL per account, so none of these can
silently create a duplicate; the wrong choice fails loudly without destroying
anything.

| Mode | Settings | Meaning |
| --- | --- | --- |
| Create | `create_github_actions_oidc_provider = true` (default) | This state creates and owns the provider. Fails with `EntityAlreadyExists` if one exists. |
| Reference | `create_github_actions_oidc_provider = false` | The provider is looked up by issuer URL and not managed here. Fails the plan with `NoSuchEntity` if none exists. |
| Adopt | `create_github_actions_oidc_provider = true` and `adopt_existing_resources = true` | The existing provider is imported into this state, as the handoff procedure below does for other singletons. |

No thumbprint is pinned for this issuer. The argument is optional and computed
on the AWS provider this root uses, and AWS maintains the trust chain for
`token.actions.githubusercontent.com`, so a pinned fingerprint would be a
rotation liability rather than a control. That is a property of this
configuration only: it does **not** predict that referencing or importing a
provider in a particular account produces an empty plan. **Before applying,
inventory that account's existing OIDC providers, choose the mode, and review
the resulting plan.** The Git-managed Boundary workspaces require manual
applies (`auto_apply = false` and `auto_apply_run_trigger = false` in
`hcp-terraform/rosa-boundary/main.tf`). Explicitly approve each account plan
before applying; a merge alone does not create these identities.

Enable in this order, matching the content design's apply order: account
identities, then regional content buckets and scoped grants, then source
replication configuration, then the first publisher runs. Reverse it to
withdraw: remove the regional grants before deleting the identities here, or
the role delete conflicts with its attached policy. Removing a publisher source
from the map destroys its role. The dedicated replication identity has no
enablement flag; deleting it requires an explicit account configuration change.

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

The staging account workspace now owns the imported shared identities and
account-wide resources and requires manual approval of applies. The handoff procedure
above is historical for staging; do not run it again against the current state.
For a new deployment with existing resources still in regional state, keep both
workspaces gated until the reviewed release/import is complete. Workspace
registration does not transfer ownership; mocked tests do not prove live
state-transfer safety.

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

---
type: infrastructure
title: Regional AWS runtime infrastructure
description: Describes the Terraform-owned regional ECS, EFS, audit storage, Lambda, encryption, and Bedrock resources in deploy/regional, the inline IAM grants it attaches to account-owned identities via data-source lookups, and the regional_policy_suffix mechanism that lets multiple regions share those roles safely.
tags: [terraform, aws, ecs, efs, iam, bedrock, s3, lambda]
verified:
  - by: openwiki/0.7.1
    at: 2026-10-09T17:04:25.482Z
sources:
  - id: openwiki-source-7182e154441e0f90fda05986
    resource: repo://deploy/account/bedrock-model-agreements.tf
  - id: openwiki-source-461b24bea8fa463d1763c8c2
    resource: repo://deploy/regional/account-handoff.tf
  - id: openwiki-source-6697a0d2171b442a1f541cf8
    resource: repo://deploy/regional/account-iam.tf
  - id: openwiki-source-af67bd84d6fb827de35fd527
    resource: repo://deploy/regional/bedrock-endpoint.tf
  - id: openwiki-source-43a5f7fe8e3da821d41a4dba
    resource: repo://deploy/regional/bedrock-large-payloads.tf
  - id: openwiki-source-86eaa81471e45a1fc5290cf1
    resource: repo://deploy/regional/bedrock-logging.tf
  - id: openwiki-source-f1bd1e0a9201f149b775a09c
    resource: repo://deploy/regional/ecs.tf
  - id: openwiki-source-e1ea6906f2471c7921ff32ce
    resource: repo://deploy/regional/efs.tf
  - id: openwiki-source-84177eee21b0f3eb77df526a
    resource: repo://deploy/regional/iam.tf
  - id: openwiki-source-d176128a85129af793772942
    resource: repo://deploy/regional/lambda-create-investigation.tf
  - id: openwiki-source-a7f1ddde1efa89d5bfad2d5c
    resource: repo://deploy/regional/lambda-reap-tasks.tf
  - id: openwiki-source-a467cf2af07b3f58e60a50ab
    resource: repo://deploy/regional/main.tf
  - id: openwiki-source-dcec1f4680246d4606ff71f8
    resource: repo://deploy/regional/s3.tf
  - id: openwiki-source-92cccd8107e9e4386a317d7a
    resource: repo://deploy/regional/tests/claude_default_model.tftest.hcl
  - id: openwiki-source-1599d372a558b44029d5589b
    resource: repo://deploy/regional/tests/iam-ownership.tftest.hcl
  - id: openwiki-source-a055ff9a3fcbd2c0a0fc4ee2
    resource: repo://deploy/regional/variables.tf
  - id: openwiki-source-6e447421bb9d1456afb165d9
    resource: repo://lambda/reap-tasks/handler.py
generated: { by: "openwiki/0.7.1", at: "2026-10-09T17:04:25.482Z" }
---

# Regional AWS runtime infrastructure

`deploy/regional/` defines the AWS resources that host investigations in a
single account/Region. Terraform takes the account, region, VPC, subnet,
container-image, and identity-contract inputs; the provider restricts
deployment to the configured 12-digit account ID (`aws_account_id`).
Configuration includes checks for at least two task subnets (`subnet_ids`
validation) and usable default routes (the `subnet_outbound_routing` check),
because Fargate needs outbound access to ECR. The directory Makefile sources
the repository `.env`, exposes Terraform targets, and builds create-investigation
Lambda dependencies before apply.

`deploy/regional` does **not** own IAM role or OIDC-provider identities: a
separate `deploy/account` Terraform root owns those, along with the
account-wide Bedrock budget and approved model agreements. See
[Account-level IAM identity and budget ownership](account-identity-ownership.md)
for that split and its migration history.

## IAM: data-sourced account roles and regional inline grants

`deploy/regional/account-iam.tf` looks up the execution, task, sre-shared,
lambda-invoker, create-investigation-lambda, reap-tasks-lambda,
bedrock-invocation-logging, and (when replication is enabled) s3-replication
roles via `data.aws_iam_role`, by name, under a shared
`${account_role_name_prefix}-<role>` convention. It also looks up the primary,
stage, and prod Keycloak OIDC providers via `data.aws_iam_openid_connect_provider`.
Regional Terraform owns **no** `aws_iam_role`, `aws_iam_role_policy_attachment`,
or `aws_iam_openid_connect_provider` resource; `deploy/regional/account-handoff.tf`
records `removed` blocks (with `destroy = false`) for the identities and
common attachments that used to live in this state, so applying the current
configuration never deletes the account-owned roles. `deploy/regional/iam.tf`
only attaches `aws_iam_role_policy` inline grants to these data-sourced role
IDs — audit S3 read/write, Bedrock invocation/profile-resolution access, ECS
Exec SSM messaging, ECS Exec session logging, KMS for session encryption, the
SRE shared role's OIDC/ABAC ECS/EFS/SSM/KMS permissions, Lambda invocation and
ECS/EFS/PassRole/SSM management for the two Lambdas, Bedrock log delivery, and
optional S3 cross-account replication. See
[Identity and Access](../architecture/identity-and-access.md) for how these
roles are consumed at request time.

Because IAM identities are account-global and a single role can receive
inline grants from more than one regional stack, every `aws_iam_role_policy`
name in `iam.tf` is suffixed through `local.regional_policy_suffix`: one
designated `legacy_policy_region` (matched against `var.aws_region`) keeps the
original, unsuffixed policy name on each shared role, while every other
region appends `-${aws_region}` to its own grants. This lets additional
regions attach their own scoped grants to the same shared roles without
colliding with — or silently overwriting — the legacy region's inline
policies; each `(role, policy name)` pair still has exactly one Terraform
owner.

## ECS, EFS, and task roles

The regional stack creates an ECS cluster with Container Insights and ECS
Exec logging/encryption configuration, CloudWatch log groups, a Fargate
security group, and a task definition. The task definition references the
data-sourced execution and task role ARNs, runs the `rosa-boundary`
container, mounts the baseline EFS home through an EFS access point, and
overlays empty task-scoped volumes at `/home/sre/.config/ocm` and
`/home/sre/.kube`. An optional `kube-proxy` sidecar consumes a cluster
kubeconfig secret and exposes its proxy only on localhost; the main container
waits for its health check when enabled.

EFS is encrypted and mounted through dedicated per-subnet mount targets. The
baseline access point presents UID/GID 1000 and `/home/sre`; the filesystem
policy grants the data-sourced task role `ClientMount`/`ClientWrite`/
`ClientRootAccess` only when accessed via a mount target with a non-null
access point ARN, effectively requiring the task role to mount through an
access point. At investigation creation, Lambda creates a separate access
point rooted at `/<cluster-id>/<investigation-id>` and rewrites the
per-investigation task definition to use it.

## Audit and session records

The investigation audit bucket is versioned, uses S3 Object Lock compliance
retention, blocks public access, encrypts objects with AES-256, and denies
non-TLS requests. An optional cross-account replication configuration grants
the data-sourced `s3-replication` role bucket/object permissions, requires
the destination account ID, and transfers object ownership to the
destination account. Container shutdown syncs the SRE home to this bucket;
task-scoped credential paths are excluded by the runtime script.

ECS Exec sessions use a rotating KMS key. The ECS cluster sends session
output to a dedicated encrypted CloudWatch log group; container stdout uses
its own log group. Bedrock invocation payload logging has separate resources
and retention: CloudWatch receives enabled text payload delivery and a
dedicated S3 bucket receives large payloads. This logging configuration is
account/Region-wide rather than limited to Boundary tasks, so access to those
logs and objects has broader sensitivity implications than container logs.

## Lambda deployment, the reaper, and task timeout

The create-investigation Lambda can be packaged as ZIP (the default) or as a
container image; both modes receive the same `local.lambda_env_vars`
environment configuration (Keycloak settings, the data-sourced task/execution/
sre-shared/lambda-invoker role ARNs, ECS/EFS/S3 identifiers, and timeout
bounds). Image mode requires a repository and an immutable tag, enforced by
`lifecycle.precondition` blocks. Its AWS-IAM-authorized Function URL is
configured separately from the CLI's direct SDK invocation path.

A scheduled reaper Lambda (`lambda/reap-tasks/handler.py`) is packaged from
its single handler file; EventBridge invokes it at the configured
`reaper_schedule_minutes` rate to find and stop ECS tasks whose `deadline` tag
has expired. Its IAM policy
(`aws_iam_role_policy.reap_tasks_lambda_ecs`, `deploy/regional/iam.tf`) scopes
`ecs:ListTasks` to the regional cluster via a condition, and scopes
`ecs:DescribeTasks`/`ecs:StopTask` to task ARNs under that cluster (`StopTask`
additionally requires a non-empty `deadline` resource tag). The policy also
grants `ssm:DescribeSessions`, which cannot be scoped to a specific SSM
resource ARN and so is granted account/Region-wide like the Bedrock logging
role's write-model-invocations caveat. The reaper calls `DescribeSessions`
before stopping an expired task, to check whether an ECS Exec session is
still active on it; on an error retrieving session state it fails closed,
skipping the task rather than stopping a session mid-use. See
[Investigation Lifecycle](../workflows/investigation-lifecycle.md) for how
this check fits into task teardown.

## Bedrock access and approved models

Fargate tasks use a private Bedrock Runtime interface endpoint
(`aws_vpc_endpoint.bedrock_runtime`) with private DNS, task-only HTTPS
ingress, and `lifecycle.precondition` checks requiring every endpoint subnet
to belong to the configured VPC and exactly one subnet per Availability Zone.
The endpoint policy grants inference calls to the data-sourced task role.

`deploy/regional` no longer creates Bedrock model agreements: that resource
(`aws_bedrock_foundation_model_agreement.approved`) moved to
`deploy/account/bedrock-model-agreements.tf`, and
`deploy/regional/account-handoff.tf` records its `removed` block so regional
applies never attempt to delete it. Regionally, `var.bedrock_model_agreements`
(`deploy/regional/variables.tf`) is now a read-only reference to that
account-owned approved-agreement manifest — a map of foundation model ID to
approved offer ID, supplied with the same value in both roots — used purely
to validate configuration, not to create or own any agreement. Task IAM
grants no Marketplace subscription permission, so an unapproved model returns
403 at invocation time rather than failing earlier.

The default Claude inference profile (`var.claude_default_model`) is checked
against a pinned profile-to-foundation-model mapping
(`local.claude_inference_profile_foundation_models` in
`deploy/regional/main.tf`) and, when `bedrock_model_agreements` is non-empty,
against that approved agreement set; the profile ID is never inferred by
stripping a prefix from the foundation model ID. Terraform tests
(`deploy/regional/tests/claude_default_model.tftest.hcl`) use a mocked AWS
provider — including mocked `data.aws_iam_role` and
`data.aws_iam_openid_connect_provider` responses, since IAM identities are now
read via data sources rather than created as resources — to accept an
approved profile and reject a bare foundation-model ID or a profile whose
foundation model is not approved.

## Terraform test coverage

Besides the model-validation tests above,
`deploy/regional/tests/iam-ownership.tftest.hcl` mocks `data.aws_iam_role` and
`data.aws_iam_openid_connect_provider` (plus the other AWS resources the
module touches) to `apply` the module without live AWS access, and asserts
that:

- all thirteen inline policy names remain in their original, legacy
  (unsuffixed) form when `aws_region == legacy_policy_region`, and that no
  `.tf` file in the module declares an `aws_iam_role`,
  `aws_iam_role_policy_attachment`, or `aws_iam_openid_connect_provider`
  resource, nor an `*_exclusive` IAM reconciliation resource, nor a
  `removed { from = aws_iam_role_policy... }` block — i.e. regional state owns
  no identities and never reconciles or releases its own grants;
- every `aws_iam_role_policy` resource's `role` attribute equals the `id` of
  its corresponding `data.aws_iam_role` lookup, so grants attach only to
  looked-up shared account roles;
- the reaper's policy conditions render exactly as configured: `ListTasks`
  scoped by `ecs:cluster`, `DescribeTasks`/`StopTask` scoped to the cluster's
  task ARN pattern, `StopTask` gated on a present `deadline` tag, and an
  unscoped `ssm:DescribeSessions` grant;
- switching `aws_region` away from `legacy_policy_region` renders every
  inline policy name with the `-${aws_region}` suffix and region-specific
  ARNs, so a second region never collides with or silently reuses the legacy
  region's grants; and
- a custom `account_role_name_prefix` is honored by every `data.aws_iam_role`
  lookup, and disabling replication (`audit_replication_bucket_arn = ""`)
  adds no `s3_replication` data source or policy.

See [Verification](../testing/verification.md) for how these `.tftest.hcl`
suites fit into the broader test strategy.

## Evidence-backed claims

- Regional Terraform guards the target account, subnet count, outbound routes, and Bedrock endpoint subnet/VPC/AZ shape. [provider and routing checks](repo://deploy/regional/main.tf#L1-L69) · [subnet input validation](repo://deploy/regional/variables.tf#L185-L193) · [Bedrock endpoint preconditions](repo://deploy/regional/bedrock-endpoint.tf#L60-L69)
- The Fargate task definition mounts persistent EFS home plus empty task-scoped credential overlays, with an optional kube-proxy sidecar whose health gates the main container. [task volumes and container configuration](repo://deploy/regional/ecs.tf#L61-L159) · [sidecar](repo://deploy/regional/ecs.tf#L175-L224)
- EFS is encrypted and its filesystem policy allows the task role to mount via an access point; the baseline access point uses the `sre` UID/GID. [filesystem and mount targets](repo://deploy/regional/efs.tf#L1-L42) · [access point and policy](repo://deploy/regional/efs.tf#L44-L97)
- The audit bucket enables versioning and compliance-mode Object Lock, blocks public access, encrypts with AES-256, and denies non-TLS requests; replication is optional and account-scoped. [audit bucket controls](repo://deploy/regional/s3.tf#L1-L73) · [replication](repo://deploy/regional/s3.tf#L75-L120)
- Create-investigation Lambda ZIP and container-image modes share environment configuration, while image mode requires an image repository and tag; a separate EventBridge schedule invokes the deadline reaper. [Lambda package modes](repo://deploy/regional/lambda-create-investigation.tf#L85-L185) · [reaper schedule](repo://deploy/regional/lambda-reap-tasks.tf#L110-L133)
- The reaper Lambda's IAM policy grants an unscoped `ssm:DescribeSessions` permission, alongside cluster/tag-scoped ECS list/describe/stop grants, so it can detect active ECS Exec sessions before stopping an expired task. [reaper IAM policy](repo://deploy/regional/iam.tf#L262-L294) · [session check in the handler](repo://lambda/reap-tasks/handler.py#L29-L46)
- Regional Terraform no longer creates Bedrock model agreements: `var.bedrock_model_agreements` is a read-only validation input checked against the account-owned manifest, while `deploy/account/bedrock-model-agreements.tf` owns the actual `aws_bedrock_foundation_model_agreement` resources and offer lookups. [regional validation input and default-model consistency guard](repo://deploy/regional/variables.tf#L31-L66) · [pinned profile-to-model mapping](repo://deploy/regional/main.tf#L83-L94) · [account-owned agreements](repo://deploy/account/bedrock-model-agreements.tf#L1-L39) · [Terraform tests](repo://deploy/regional/tests/claude_default_model.tftest.hcl#L1-L115)
- Bedrock Runtime uses a private interface endpoint and invocation payload logging sends text to encrypted CloudWatch storage and larger payloads to a separate S3 bucket. [runtime endpoint](repo://deploy/regional/bedrock-endpoint.tf#L1-L72) · [invocation logging](repo://deploy/regional/bedrock-logging.tf#L1-L85) · [large-payload bucket](repo://deploy/regional/bedrock-large-payloads.tf#L1-L87)
- Execution, task, sre-shared, lambda-invoker, create-investigation-lambda, reap-tasks-lambda, bedrock-invocation-logging, and optional s3-replication roles are looked up by name via `data.aws_iam_role` rather than owned as regional resources, and `deploy/regional/iam.tf` attaches only inline policy grants to them. [data-source role lookups](repo://deploy/regional/account-iam.tf#L1-L35) · [regional-handoff removed blocks](repo://deploy/regional/account-handoff.tf#L1-L30) · [inline grants attach to looked-up roles](repo://deploy/regional/iam.tf#L1-L45)
- A `regional_policy_suffix` keeps one designated `legacy_policy_region`'s inline-policy names unsuffixed while every other region appends `-${aws_region}`, letting multiple regional stacks grant inline policies on the same shared account roles without name collisions. [suffix mechanism](repo://deploy/regional/account-iam.tf#L1-L8) · [Terraform test coverage](repo://deploy/regional/tests/iam-ownership.tftest.hcl#L77-L218)
- `deploy/regional/tests/iam-ownership.tftest.hcl` mocks `data.aws_iam_role`/`data.aws_iam_openid_connect_provider` and other AWS resources to verify, without live AWS access, that regional policies render against the correct looked-up roles and that the reaper's ECS/SSM grant conditions are preserved. [mocked provider and role/OIDC data](repo://deploy/regional/tests/iam-ownership.tftest.hcl#L1-L39) · [role-attachment and reaper-condition assertions](repo://deploy/regional/tests/iam-ownership.tftest.hcl#L100-L171)

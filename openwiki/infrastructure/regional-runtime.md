---
type: infrastructure
title: Boundary Regional Runtime Infrastructure
description: Describes regional ECS, EFS, Lambda, audit/content S3, and Bedrock resources, their shared account-IAM ownership contract, and the constraints for safely running multiple regional states.
tags: [terraform, aws, ecs, efs, iam, bedrock, s3]
sources:
  - id: openwiki-source-7182e154441e0f90fda05986
    resource: repo://deploy/account/bedrock-model-agreements.tf
  - id: openwiki-source-7abd92951c465f5a76e176f4
    resource: repo://deploy/account/main.tf
  - id: openwiki-source-6b03d2d17a5b9eb3f358798b
    resource: repo://deploy/account/modules/shared-iam/bedrock-logging.tf
  - id: openwiki-source-509075f8404cde427a1990b6
    resource: repo://deploy/account/modules/shared-iam/content-publishing.tf
  - id: openwiki-source-e0e8c15f232fd81f46f03e41
    resource: repo://deploy/account/modules/shared-iam/iam.tf
  - id: openwiki-source-f4745022f20c2f39d1db313b
    resource: repo://deploy/account/modules/shared-iam/lambda-reap-investigations.tf
  - id: openwiki-source-ee86c0d48b646d4bc6813442
    resource: repo://deploy/account/outputs.tf
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
  - id: openwiki-source-59e04e9f85ec6ba973e74aab
    resource: repo://deploy/regional/iam-content.tf
  - id: openwiki-source-84177eee21b0f3eb77df526a
    resource: repo://deploy/regional/iam.tf
  - id: openwiki-source-d176128a85129af793772942
    resource: repo://deploy/regional/lambda-create-investigation.tf
  - id: openwiki-source-81b84da9542934c33f2e42d7
    resource: repo://deploy/regional/lambda-reap-investigations.tf
  - id: openwiki-source-a7f1ddde1efa89d5bfad2d5c
    resource: repo://deploy/regional/lambda-reap-tasks.tf
  - id: openwiki-source-a467cf2af07b3f58e60a50ab
    resource: repo://deploy/regional/main.tf
  - id: openwiki-source-662794d8125035472cb54f09
    resource: repo://deploy/regional/s3-content.tf
  - id: openwiki-source-dcec1f4680246d4606ff71f8
    resource: repo://deploy/regional/s3.tf
  - id: openwiki-source-92cccd8107e9e4386a317d7a
    resource: repo://deploy/regional/tests/claude_default_model.tftest.hcl
  - id: openwiki-source-e331ce49d4745096eb9b7376
    resource: repo://deploy/regional/tests/content-storage.tftest.hcl
  - id: openwiki-source-1599d372a558b44029d5589b
    resource: repo://deploy/regional/tests/iam-ownership.tftest.hcl
  - id: openwiki-source-a055ff9a3fcbd2c0a0fc4ee2
    resource: repo://deploy/regional/variables.tf
  - id: openwiki-source-81722021d767635aca673ab8
    resource: repo://hcp-terraform/rosa-boundary/main.tf
  - id: openwiki-source-d796a031add13f67891a2f24
    resource: repo://lambda/reap-investigations/handler.py
generated: { by: "openwiki/0.7.1", at: "2026-11-12T16:02:44.301Z" }
verified:
  - by: openwiki/0.7.1
    at: 2026-11-12T16:02:44.301Z
---

# Boundary Regional Runtime Infrastructure

`deploy/regional/` defines the AWS resources that host investigations. Terraform takes the account, region, VPC, subnet, container-image, and identity inputs; the provider restricts deployment to the configured 12-digit account ID. Configuration includes checks for at least two task subnets and usable default routes, because Fargate needs outbound access to ECR. The directory Makefile sources the repository `.env` for **local dev**, exposes Terraform targets, and builds create-investigation Lambda dependencies before local apply; HCP staging uses Git-managed variables and remote execution instead.

## ECS, EFS, and task roles

The regional stack creates an ECS cluster with Container Insights and ECS Exec logging/encryption configuration, CloudWatch log groups, a Fargate security group, and a task definition. The task definition runs the `rosa-boundary` container, mounts the baseline EFS home through an EFS access point, and overlays empty task-scoped volumes at `/home/sre/.config/ocm` and `/home/sre/.kube`. An optional `kube-proxy` sidecar consumes a cluster kubeconfig secret and exposes its proxy only on localhost; the main container waits for its health check when enabled.

EFS is encrypted and mounted through dedicated per-subnet mount targets. The baseline access point presents UID/GID 1000 and `/home/sre`; the filesystem policy's `EnforceAccessViaAccessPoint` statement requires the task role to mount via an access point. At investigation creation, Lambda creates a separate access point rooted at `/<cluster-id>/<investigation-id>` and rewrites the per-investigation task definition to use it.

The filesystem policy carries a second statement, `AllowReaperViaDedicatedAccessPoint`, granting the reap-investigations Lambda role `ClientMount`/`ClientWrite`/`ClientRootAccess` scoped by `elasticfilesystem:AccessPointArn` to a single dedicated access point (`aws_efs_access_point.reaper`), rooted at `/` with UID/GID 0 for full filesystem reach. This grant is separate from the task role's access-point-scoped statement and is deliberately not extended to the dynamically created per-investigation access points. Removing *other* investigations' access points is instead handled by a distinct `DeleteAccessPoint` permission on the reap-investigations Lambda role, scoped to resources carrying the `ManagedBy=rosa-boundary-lambda` tag so the role cannot delete unrelated access points.

IAM separates the ECS execution role from the task role. The execution role supports image pulls/logging and secret retrieval; the task role carries runtime permissions for audit S3 writes, Bedrock, ECS Exec messaging, session logging, KMS, and EFS access. See [identity and access](../architecture/identity-and-access.md) for trust and task-level controls.

## Account/regional ownership and multi-region contract

The **account** root (`deploy/account/`, backed by the `deploy/account/modules/shared-iam` module) owns shared IAM role identities, their trust policies, OIDC providers, and common AWS-managed policy attachments — for example the execution role's `AmazonECSTaskExecutionRolePolicy` attachment and both the basic-execution and `AWSLambdaVPCAccessExecutionRole` attachments on the investigation-reaper role. The account root never defines inline policies or `aws_iam_role_policy_attachment`/exclusive-assignment resources itself for those roles; it exposes them as a `shared_roles` output plus a `regional_iam_contract` output (`account_role_name_prefix`, `legacy_policy_region`) for regional consumption.

The **regional** root (`deploy/regional/`) owns all inline permission grants on those shared roles. `deploy/regional/account-iam.tf` resolves each role by name (and each OIDC provider by issuer URL) through `data` lookups rather than remote state, and computes a `regional_policy_suffix` local from the region and the contract's `legacy_policy_region`; `deploy/regional/iam.tf` then attaches one `aws_iam_role_policy` per grant, named with that suffix. Because identity creation never needs a regional resource ARN, the account root can be applied independently of any region. `deploy/regional/iam-content.tf` follows exactly this same split for published content: the account root's `shared-iam` module creates the publisher and content-replication role identities (`content_publisher_role_arns`, `content_replication_role_arn` outputs) and regional state attaches every inline grant on them, named with the same `regional_policy_suffix`, by resolving each role name from its supplied ARN rather than by remote state.

Every regional root must use the same `account_role_name_prefix` and the same single `legacy_policy_region` from the account root's `regional_iam_contract` output. Only that legacy region keeps unsuffixed inline-policy names; all other regions append `-${aws_region}`. The staging definitions designate `us-east-1` as the legacy owner and `us-west-2` as an additional consumer. A west workspace must not choose itself as another legacy owner, because that would overwrite east's inline policies on the same roles.

Regional policy ownership does **not** make IAM roles regional: the shared identity receives the union of grants from all consuming regions. Keep each inline policy and each `(role, managed-policy ARN)` attachment under exactly one state owner; exclusive policy reconciliation would remove another region's grants. The regional `account-handoff.tf` declarations release listed legacy account-owned objects with `destroy = false`, while inline policies remain in regional state. This configuration is not evidence that a particular live state transfer or apply succeeded. Coordinate teardown across all consumers before deleting account roles; see [HCP workspace integration](hcp-terraform-workspaces.md) for the six-workspace staging topology and apply gates.

Trusted Actions runs its own separate AWS footprint under `components/trusted-actions/terraform/{global,regional}`, outside this Boundary account/regional split; see [Trusted Actions deployment](trusted-actions-deployment.md) for that infrastructure.

## Published content storage

Alongside the audit bucket, every regional deployment unconditionally creates a second bucket, `<account>-<project>-<stage>-<region>-content`, for SRE content that Boundary tasks read at runtime (SOPs, Claude plugins, managed notifications). It is deliberately a separate bucket from the write-once audit bucket in `s3.tf`: published content is mutable and replaceable, so it has versioning (for recoverability, not immutability), no Object Lock, and a lifecycle rule that expires only noncurrent versions and abandoned multipart uploads — current objects are never expired. Public access is fully blocked and a bucket policy denies non-TLS requests, uploads that request any encryption other than `aws:kms`, uploads naming any KMS key other than the resolved regional key, and any SSE-C (customer-key) upload, since none of the task role, a publisher role, or the replication role could read an SSE-C object back.

The bucket uses SSE-KMS with the Region's AWS-managed `alias/aws/s3` key rather than a customer-managed key: `deploy/regional` creates no KMS key and edits no key policy. Because that key's ARN cannot be known statically, `aws_s3_object.key_bootstrap` writes a single reserved, never-read object at `_bootstrap/key-init` with an explicit `aws:kms` request to guarantee the key exists, and `data.aws_kms_alias.content_s3` then reads its real ARN for every grant and bucket-policy statement that follows. The bootstrap key sits outside every published prefix so a publisher's `aws s3 sync --delete` can never remove it, and `content_prefixes` validation independently rejects any published prefix that is an ancestor of `_bootstrap/`. S3 Bucket Keys are deliberately not enabled, because enabling them would move the KMS encryption context from the object ARN to the bucket ARN and require `kms:Decrypt` in the AWS-managed replica key's policy — a policy this design cannot edit.

`content_prefixes` (default: `ops-sop/`, `rosa-claude-plugins/`, `managed-notifications/`) is the single source of truth for both the publisher grants and the runtime subdirectory layout; its values must be distinct, non-overlapping, directory-style (`/`-terminated) paths so one publisher's prefix can never list, read, write, or delete another's content. `deploy/regional/iam-content.tf` grants three kinds of access on top of this bucket, all owned by regional state even though the underlying roles are account-owned identities resolved by name (the same ownership split used elsewhere — see below):

- **Task read grant** (`aws_iam_role_policy.task_content`, unconditional, name `s3-content-read[-<region>]`): the shared task role gets `s3:ListBucket` (prefix-conditioned), `s3:GetObject`, and `kms:Decrypt` scoped to this Region's own bucket and key only — never another Region's replica, and never the `_bootstrap/` object.
- **Publisher grants** (`aws_iam_role_policy.content_publisher`, one per `content_publisher_role_arns` entry, name `content-publish-<key>[-<region>]`): rendered only where an account-supplied publisher role ARN is present, which should be only the publishing source Region. Each publisher gets `s3:ListBucket` scoped to its own prefix, `s3:PutObject`/`s3:DeleteObject`/`s3:AbortMultipartUpload` scoped to its own prefix only, and `kms:GenerateDataKey`/`kms:Decrypt` on the regional key. There is deliberately no `s3:GetObject` (`aws s3 sync` only reads the listing, never the destination object), no tagging action, and no `kms:Encrypt` (PutObject and CreateMultipartUpload use GenerateDataKey, not Encrypt).
- **Replication grant** (`aws_iam_role_policy.content_replication`, at most one, name `content-replication[-<region>]`): rendered only when `content_replication_role_arn` is set and `replication` has at least one populated content destination from this Region. It grants exactly the AWS-documented minimal SSE-KMS replication action set (source reads, `s3:ReplicateObject`/`s3:ReplicateDelete`, source `kms:Decrypt`, destination `kms:Encrypt`) and deliberately omits `kms:GenerateDataKey`, because the bucket policy already makes a plaintext or foreign-key object impossible to create. This identity is distinct from the audit replication role in `s3.tf` and must never be reused for audit data.

Replication reuses the same generic `replication` topology object shared with `deploy/account`: only `var.replication.primary_region` activates source-side content rules and grants (a `lifecycle.precondition` on `aws_iam_role_policy.content_publisher` explicitly blocks publisher grants outside the primary region), and `aws_s3_bucket_replication_configuration.content` is created only in that Region, with one rule per `(destination, prefix)` pair, a stride of `length(content_prefixes)` so priorities stay unique as destinations are added, prefix-only filters (required for valid delete-marker replication), delete-marker replication enabled, and the SSE-KMS replication opt-in that S3 requires before it will replicate encrypted objects at all. Supplying only `content_replication_role_arn`, or only publisher ARNs, does not by itself enable replication or publishing; each requires its own populated input. Destination bucket ARNs, replica key ARNs, and replica `content_prefixes` must exactly match the convention and the source's own map — `lifecycle.precondition` blocks reject a destination bucket name outside `<account>-<project>-<stage>-<region>-content`, a replica key outside the destination Region, a destination whose `content_prefixes` disagrees with the source map, or a destination equal to the workspace's own Region. Destination metadata must arrive as plain Terraform input values (copied from the destination Region's own `content_bucket_arn`/`content_bucket_kms_key_arn`/`content_prefixes` outputs) rather than through `terraform_remote_state`, keeping the two regional states decoupled.

Outputs expose `content_bucket_name`, `content_bucket_arn`, `content_bucket_region`, `content_bucket_kms_key_arn`, `content_prefixes`, and `content_replication_rule_ids` (empty in a replica, when `replication` is null, or before destinations are populated) so an operator can wire up a second Region's replication inputs without inventing bucket or key metadata.

## Audit and session records

The investigation audit bucket is versioned, uses S3 Object Lock compliance retention, blocks public access, encrypts objects with AES-256, and denies non-TLS requests. An optional cross-account replication configuration requires the destination account ID and transfers ownership to the destination account. Container shutdown syncs the SRE home to this bucket; task-scoped credential paths are excluded by the runtime script.

ECS Exec sessions use a rotating KMS key. The ECS cluster sends session output to a dedicated encrypted CloudWatch log group; container stdout uses its own log group. Bedrock invocation payload logging has separate resources and retention: CloudWatch receives enabled text payload delivery and a dedicated S3 bucket receives large payloads. This logging configuration is account/Region-wide rather than limited to Boundary tasks, so access to those logs and objects has broader sensitivity implications than container logs.

## Lambda deployment and task timeout

The regional stack ships three Lambda functions: create-investigation, reap-tasks, and reap-investigations.

The create-investigation Lambda can be packaged as ZIP (the default) or as a container image; both modes receive the same runtime configuration. Image mode requires a repository and an immutable tag; staging sets image mode for remote execution. Its AWS-IAM-authorized Function URL is configured separately from the CLI's direct SDK invocation path. The reap-tasks Lambda is packaged from its single handler file and gets scoped ECS list/describe/stop permissions; EventBridge invokes it at a configurable schedule (Terraform variable `reaper_schedule_minutes`, default 15 minutes) to stop expired tasks **without an active Exec session**.

The reap-investigations Lambda runs on its own schedule (Terraform variable `investigation_reaper_schedule_hours`, default every 8 hours) to reclaim investigation directories, access points, and matching task definitions. Eligibility requires no matching RUNNING task and an access-point creation age strictly greater than the configured grace period (Terraform default 168 hours), or a missing `CreatedAt` tag treated as legacy state. It is not a timer starting when the last task stops. The handler rechecks running tasks before cleanup and requires a successful final S3 backup before deleting an existing directory; see [investigation lifecycle](../workflows/investigation-lifecycle.md#investigation-level-garbage-collection-reap-investigations).

Regional Terraform gives this function its own log group, security group, and inline grants on the account-owned reaper role:

- **ECS:** `ListTasks`/`DescribeTasks` are conditioned on the regional cluster ARN; `ListTaskDefinitions` and `DeregisterTaskDefinition` are configured with wildcard resources. Family matching is performed by the handler, not by a family-specific IAM condition.
- **EFS:** `DescribeAccessPoints` targets the regional filesystem. `DeleteAccessPoint` targets access-point ARNs in the current account/Region and requires `ManagedBy=rosa-boundary-lambda`. The separate `ClientMount`/`ClientWrite`/`ClientRootAccess` grant targets the filesystem and requires the dedicated reaper access point, not an investigation access point.
- **S3:** `PutObject`/`PutObjectAcl` target `{cluster}/{investigation}/reaper-final-backup/*` in the audit bucket; `ListBucket` is prefix-conditioned for that backup layout.

The function mounts `aws_efs_access_point.reaper` directly at `/mnt/efs` through `file_system_config`. That access point uses UID/GID 0 and root `/`; the filesystem policy independently authorizes it. VPC configuration uses the supplied subnets and an outbound-only `reaper_lambda` security group; EventBridge invocation does not require inbound network access. The common VPC execution managed-policy attachment is owned once by account state, not recreated by every region.

## Bedrock access and approved models

Fargate tasks use a private Bedrock Runtime interface endpoint with private DNS, task-only HTTPS ingress, and one subnet per availability zone in the configured VPC. The endpoint policy grants inference calls to the task role. Task IAM does not grant Marketplace subscription; **account Terraform** owns model agreements from an explicit model-to-offer map. Regional Terraform validates the default Claude inference profile against a pinned profile-to-foundation-model mapping and the approved agreement input; it is not inferred by stripping a prefix. Terraform tests use a mocked AWS provider to accept an approved profile and reject a bare foundation-model ID or a profile whose foundation model is not approved.

The account-owned Bedrock logging role has a separate regional service-trust contract. `bedrock_logging_source_regions` enumerates permitted `SourceArn` regions while retaining `SourceAccount`; an empty account input falls back to the legacy role-tag region, not a wildcard. Staging explicitly approves east and west. Each regional root still owns its own invocation-logging configuration, CloudWatch/KMS destination, large-payload bucket, and delivery grant. Allowing west in trust is a prerequisite for west logging, not proof that payload delivery works there.

## Focused verification

The mocked regional IAM tests assert that identities and managed attachments are absent from regional ownership, grants use looked-up account roles, a second region uses non-colliding policy names, and EFS reaper grants retain their dedicated-access-point conditions. `deploy/regional/tests/content-storage.tftest.hcl` separately asserts that the content bucket and task read grant exist unconditionally, that publisher and replication grants stay absent until their respective inputs are populated, that publisher and runtime IAM statements carry only the minimal actions a real call path needs (no `s3:GetObject`/tagging/`kms:Encrypt` on publisher grants, no `kms:GenerateDataKey` on the replication grant), that the `_bootstrap/key-init` object and policy denials (`DenyUploadsWithAnotherEncryptionAlgorithm`, `DenyUploadsWithAnotherKMSKey`, `DenyCustomerProvidedKeyUploads`) render as expected, and that replication rule priorities and policy-name suffixes behave correctly across regions. Account tests verify shared trust/attachments and the explicit multi-region Bedrock trust list. These tests validate rendered configuration, not live role adoption, IAM authorization, or delivery. See [testing and verification](../testing/verification.md) for suite selection and [audit operations](../operations/audit-and-logging.md) for deployed evidence.

## Evidence-backed claims

- Regional Terraform guards the target account, subnet count, outbound routes, and Bedrock endpoint subnet/VPC/AZ shape. [provider and routing checks](repo://deploy/regional/main.tf#L1-L69) · [Bedrock endpoint preconditions](repo://deploy/regional/bedrock-endpoint.tf#L30-L69)
- The Fargate task definition mounts persistent EFS home plus empty task-scoped credential overlays, with an optional kube-proxy sidecar whose health gates the main container. [task volumes and container configuration](repo://deploy/regional/ecs.tf#L61-L159) · [sidecar](repo://deploy/regional/ecs.tf#L175-L224)
- EFS is encrypted and its filesystem policy allows the task role to mount via an access point; the baseline access point uses the `sre` UID/GID. [filesystem and mount targets](repo://deploy/regional/efs.tf#L1-L42) · [access point and policy](repo://deploy/regional/efs.tf#L44-L75)
- The EFS filesystem policy's `AllowReaperViaDedicatedAccessPoint` statement grants the reap-investigations Lambda role `ClientMount`/`ClientWrite`/`ClientRootAccess` scoped to its own dedicated `aws_efs_access_point.reaper`, distinct from both the task role's access-point-scoped grant and the reap-investigations role's separate tag-scoped `DeleteAccessPoint` permission used to remove other investigations' access points. [dedicated reaper statement](repo://deploy/regional/efs.tf#L103-L126) · [reaper access point](repo://deploy/regional/lambda-reap-investigations.tf#L120-L143) · [tag-scoped DeleteAccessPoint](repo://deploy/regional/lambda-reap-investigations.tf#L59-L70)
- The audit bucket enables versioning and compliance-mode Object Lock, blocks public access, encrypts with AES-256, and denies non-TLS requests; replication is optional and account-scoped. [audit bucket controls](repo://deploy/regional/s3.tf#L1-L73) · [replication](repo://deploy/regional/s3.tf#L75-L120)
- Create-investigation Lambda ZIP and container-image modes share environment configuration, while image mode requires an image repository and tag; a separate EventBridge schedule invokes the task-deadline reaper. [Lambda package modes](repo://deploy/regional/lambda-create-investigation.tf#L11-L140) · [reaper schedule](repo://deploy/regional/lambda-reap-tasks.tf#L42-L66) · [reap-tasks schedule default](repo://deploy/regional/variables.tf#L402-L422)
- The investigation reaper uses an account-owned role and basic/VPC managed attachments, with regional logging and ECS/EFS/S3 inline grants; access-point deletion and filesystem mounting have different conditions. [regional grants](repo://deploy/regional/lambda-reap-investigations.tf#L1-L117) · [shared identity and attachments](repo://deploy/account/modules/shared-iam/lambda-reap-investigations.tf#L1-L19)
- The reaper mounts its dedicated root access point at `/mnt/efs`, runs independently, and backs up existing directory data before ordered cleanup. Eligibility is creation-age-based with an idle legacy exception for missing `CreatedAt`. [function and schedule](repo://deploy/regional/lambda-reap-investigations.tf#L174-L239) · [schedule and grace-period variables](repo://deploy/regional/variables.tf#L402-L422) · [staleness](repo://lambda/reap-investigations/handler.py#L252-L321) · [backup-before-delete](repo://lambda/reap-investigations/handler.py#L662-L712)
- Account state owns shared role identities and managed-policy attachments; regional state resolves them by name and owns every inline grant, suffixed per region. [shared role identities](repo://deploy/account/modules/shared-iam/iam.tf#L1-L22) · [reaper identity and attachments](repo://deploy/account/modules/shared-iam/lambda-reap-investigations.tf#L1-L19) · [account contract output](repo://deploy/account/outputs.tf#L1-L12) · [regional lookup and suffix](repo://deploy/regional/account-iam.tf#L1-L8) · [regional inline grant example](repo://deploy/regional/iam.tf#L79-L90) · [ownership and suffix tests](repo://deploy/regional/tests/iam-ownership.tftest.hcl#L98-L121) · [additional-region tests](repo://deploy/regional/tests/iam-ownership.tftest.hcl#L193-L233)
- Account-managed Bedrock logging trust permits only approved source regions in the same account; regional destinations and grants remain separate. [account input fallback](repo://deploy/account/main.tf#L42-L49) · [service trust](repo://deploy/account/modules/shared-iam/bedrock-logging.tf#L1-L28) · [staging region list](repo://hcp-terraform/rosa-boundary/main.tf#L209-L215)
- Account Terraform manages Bedrock model agreement offers by ID, while regional validation requires the configured default inference profile to map to an approved foundation model; Terraform tests reject invalid profile/agreement combinations. [account agreements](repo://deploy/account/bedrock-model-agreements.tf#L1-L40) · [default model validation](repo://deploy/regional/variables.tf#L37-L65) · [Terraform tests](repo://deploy/regional/tests/claude_default_model.tftest.hcl#L78-L115)
- Bedrock Runtime uses a private interface endpoint and invocation payload logging sends text to encrypted CloudWatch storage and larger payloads to a separate S3 bucket. [runtime endpoint](repo://deploy/regional/bedrock-endpoint.tf#L1-L69) · [invocation logging](repo://deploy/regional/bedrock-logging.tf#L1-L85) · [large-payload bucket](repo://deploy/regional/bedrock-large-payloads.tf#L1-L86)
- Every regional deployment unconditionally creates a published-content bucket, separate from the write-once audit bucket, with versioning, no Object Lock, a lifecycle rule that expires only noncurrent versions/abandoned multipart uploads, full public-access blocking, and a bucket policy that denies non-TLS access, non-`aws:kms` uploads, uploads naming a foreign KMS key, and any SSE-C upload. [bucket resources and lifecycle](repo://deploy/regional/s3-content.tf#L62-L237) · [bucket protections test](repo://deploy/regional/tests/content-storage.tftest.hcl#L147-L254)
- The content bucket uses the Region's AWS-managed `alias/aws/s3` key rather than a customer-managed key; a reserved `_bootstrap/key-init` object guarantees the key exists before `data.aws_kms_alias.content_s3` resolves its real ARN for every downstream grant and policy statement, and S3 Bucket Keys are deliberately left disabled. [bootstrap and alias read](repo://deploy/regional/s3-content.tf#L214-L245) · [no-CMK test](repo://deploy/regional/tests/content-storage.tftest.hcl#L192-L216)
- `content_prefixes` is the single source of truth for publisher grants and the runtime subdirectory layout; its values must be distinct, non-overlapping, directory-style paths, and none may be a prefix of the reserved `_bootstrap/` key. [prefix validations](repo://deploy/regional/variables.tf#L456-L511)
- Regional IAM grants unconditional read-only access to the shared task role scoped to the local bucket/key, publisher grants scoped to one prefix each (rendered only where a publisher role ARN is supplied), and a replication grant on a dedicated content-replication identity (rendered only once a replication destination's content metadata is populated); none of these three grants shares an identity with the audit replication role. [task read grant](repo://deploy/regional/iam-content.tf#L144-L186) · [publisher grants](repo://deploy/regional/iam-content.tf#L67-L142) · [replication grant](repo://deploy/regional/iam-content.tf#L188-L265) · [unconditional-creation and opt-in tests](repo://deploy/regional/tests/content-storage.tftest.hcl#L98-L145)
- Content replication reuses the shared `replication` topology object, activates source-side rules and grants only in `replication.primary_region`, renders one rule per destination/prefix pair with a prefix-count priority stride, and rejects a destination bucket name, replica key region, or `content_prefixes` map that disagrees with the source's own conventions; destination metadata must arrive as plain input values, never `terraform_remote_state`. [replication rules and preconditions](repo://deploy/regional/s3-content.tf#L247-L335) · [replication test](repo://deploy/regional/tests/content-storage.tftest.hcl#L499-L631)
- The account root's `shared-iam` module owns the content publisher and content-replication role identities; regional state resolves each by its supplied ARN and owns every inline grant on them, suffixed per region exactly like the other shared-role grants. [regional role-name resolution](repo://deploy/regional/iam-content.tf#L28-L65) · [account-owned identities](repo://deploy/account/modules/shared-iam/content-publishing.tf#L1-L40)

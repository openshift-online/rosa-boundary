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
  - id: openwiki-source-53ded000b5419d48efde6aba
    resource: repo://lambda/reap-investigations/close_finalization.py
  - id: openwiki-source-d796a031add13f67891a2f24
    resource: repo://lambda/reap-investigations/handler.py
  - id: openwiki-source-6e447421bb9d1456afb165d9
    resource: repo://lambda/reap-tasks/handler.py
generated: { by: "pi", at: "2026-11-25T19:00:35.491Z" }
verified:
  - by: openwiki/0.9.0
    at: 2026-11-25T19:00:35.491Z
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

Regional policy ownership does **not** make IAM roles regional: the shared identity receives the union of grants from all consuming regions. Keep each inline policy and each `(role, managed-policy ARN)` attachment under exactly one state owner; exclusive policy reconciliation would remove another region's grants. `deploy/regional/account-handoff.tf` is a one-way migration record: each `removed` block (with `lifecycle { destroy = false }`) names an object that used to live in regional state and now belongs to account state — every shared IAM role (`execution`, `task`, `sre_shared`, `lambda_invoker`, the Lambda roles, `bedrock_invocation_logging`), every Keycloak OIDC provider, the S3 replication role, and the Bedrock-specific singletons `aws_budgets_budget.bedrock` and `aws_bedrock_foundation_model_agreement.approved`. Inline policies are deliberately never listed here and remain in regional state. This file is a historical handoff manifest, not evidence that a particular live state transfer or apply succeeded. Coordinate teardown across all consumers before deleting account roles; see [HCP workspace integration](hcp-terraform-workspaces.md) for the six-workspace staging topology and apply gates.

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

ZIP and image creation functions share configuration. Image mode derives a regional ECR URI and requires a lowercase 40-character SHA tag; reap-tasks has its own EventBridge schedule.

The EFS policy grants the reaper root access through its dedicated access point and explicitly denies the workload role use of that point.

Regional IAM distinguishes deletion of unsealed managed access points from deletion of points marked as reaper-managed.

The account owns the reaper identity and execution attachments; the region owns its log group, VPC configuration and ECS, EFS and audit storage grants.

The investigation reaper mounts EFS at /mnt/efs and schedules discovery every eight hours by default. Expiry and idle discovery feed verified closure; normal close retains the directory and stale reclamation requires separate permission to reclaim.

The task and investigation reapers use separate roles and schedules: one enforces task age limits and the other finalizes workspace closure.

## Bedrock access and approved models

Fargate tasks reach Bedrock Runtime only through a private interface VPC endpoint (`aws_vpc_endpoint.bedrock_runtime`): private DNS is enabled so the standard `bedrock-runtime` hostname resolves to an ENI in each task subnet, ingress is restricted to HTTPS from the `fargate` security group only, and a `lifecycle.precondition` pair rejects any configuration whose endpoint subnets fall outside `var.vpc_id` or that does not supply exactly one subnet per Availability Zone. The endpoint policy grants only the task role `bedrock:InvokeModel`/`InvokeModelWithResponseStream` on inference-profile and foundation-model resources, plus a narrow second statement authorizing the fixed `project/default` Bedrock resource the OpenAI-compatible Responses path requires — no other principal, project, account, or Region is opened. Task IAM does not grant Marketplace subscription; **account Terraform** owns model agreements from an explicit model-to-offer map (`deploy/account/bedrock-model-agreements.tf`), and `account-handoff.tf`'s `removed` blocks confirm the model-agreement and Bedrock-budget resources were migrated out of regional state entirely. Regional Terraform validates the default Claude inference profile against a pinned profile-to-foundation-model mapping (`local.claude_inference_profile_foundation_models` in `main.tf`) and the approved-agreement input; it is not inferred by stripping a prefix. `tests/claude_default_model.tftest.hcl` uses a mocked AWS provider and `command = plan` runs to check this end-to-end: one run asserts the shared default profile (`us.anthropic.claude-sonnet-5-5`) both satisfies validation and reaches the task definition's `ANTHROPIC_MODEL` environment variable, sibling runs show that a profile whose resolved foundation model is missing from `bedrock_model_agreements` fails (`expect_failures`), that region-appropriate profiles (`us.`/`eu.`/`global.`) succeed, and a later block confirms a bare foundation-model ID (not an inference-profile key) is rejected outright.

Bedrock invocation-payload logging and large-payload storage are two distinct resources with two distinct concerns, not one generic "Bedrock bucket": `bedrock-logging.tf` owns a dedicated KMS key (scoped by `kms:EncryptionContext:aws:logs:arn` to exactly this Region's Bedrock log group), the CloudWatch log group itself, and the `aws_bedrock_model_invocation_logging_configuration` resource that turns text-payload delivery on; `bedrock-large-payloads.tf` separately owns the S3 bucket, its own encryption/ownership/lifecycle configuration, and a bucket policy that only lets the `bedrock.amazonaws.com` service principal (scoped by `aws:SourceAccount`/`aws:SourceArn`) write under its `large-data/AWSLogs/<account>/BedrockModelInvocationLogs/` prefix — CloudWatch carries payload bodies up to 100 KB and S3 receives anything larger. The account-owned Bedrock logging role additionally has a separate regional service-trust contract: `bedrock_logging_source_regions` enumerates permitted `SourceArn` regions while retaining `SourceAccount`; an empty account input falls back to the legacy role-tag region, not a wildcard. Staging explicitly approves east and west. Each regional root still owns its own invocation-logging configuration, CloudWatch/KMS destination, large-payload bucket, and delivery grant. Allowing west in trust is a prerequisite for west logging, not proof that payload delivery works there.

## Focused verification

The mocked regional IAM tests assert that identities and managed attachments are absent from regional ownership, grants use looked-up account roles, a second region uses non-colliding policy names, and EFS reaper grants retain their dedicated-access-point conditions. `deploy/regional/tests/content-storage.tftest.hcl` separately asserts that the content bucket and task read grant exist unconditionally, that publisher and replication grants stay absent until their respective inputs are populated, that publisher and runtime IAM statements carry only the minimal actions a real call path needs (no `s3:GetObject`/tagging/`kms:Encrypt` on publisher grants, no `kms:GenerateDataKey` on the replication grant), that the `_bootstrap/key-init` object and policy denials (`DenyUploadsWithAnotherEncryptionAlgorithm`, `DenyUploadsWithAnotherKMSKey`, `DenyCustomerProvidedKeyUploads`) render as expected, and that replication rule priorities and policy-name suffixes behave correctly across regions. Account tests verify shared trust/attachments and the explicit multi-region Bedrock trust list. These tests validate rendered configuration, not live role adoption, IAM authorization, or delivery. See [testing and verification](../testing/verification.md) for suite selection and [audit operations](../operations/audit-and-logging.md) for deployed evidence.

## Further reading

See [system overview](../architecture/system-overview.md) for the distinction between task shutdown synchronization and independent close verification.

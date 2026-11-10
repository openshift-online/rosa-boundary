# ROSA Boundary Regional Infrastructure

Terraform configuration for deploying ROSA Boundary container infrastructure on AWS Fargate, including S3 audit storage with WORM compliance and EFS persistent storage, consuming account-owned IAM roles with Bedrock access.

## Ordinary Lambda ECR destination repository

`lambda_ecr_destination_source_region` is empty by default. Set it to the
account root's Lambda publication Region only in a *different* Region to create
`rosa-boundary/create-investigation-lambda` with the same immutable-tag,
encryption, scanning and 25-tag retention settings as the source. In staging,
only the `us-west-2` regional workspace enables it; `us-east-1` continues to
use the account-owned source repository. The account root owns filtered,
registry-wide image replication, not this state. New source-region pushes after
replication is enabled can verify delivery; older images require a separate
backfill if they will be needed at the destination. Neither repository
provisioning nor replication changes the running Lambda's existing Quay-cache
image URI. Promote a new URI only after an approved SHA exists in every Region.

## Account identities and regional grants

Deploy [`../account`](../account/README.md) before a new regional deployment.
This root now consumes existing IAM roles by name and OIDC providers by issuer
URL; it no longer owns role/trust definitions or the Bedrock monthly budget.
It **does own regional inline policies** on those shared roles, referencing the
actual resources created here. Configure `account_role_name_prefix` to match
the shared account identity prefix (empty retains the legacy `project-stage`
prefix). Coordinate the legacy policy region with all other regional stacks:
set `legacy_policy_region` to that same original region in every workspace.
Existing names are retained only there; other regions use qualified policy names
to avoid overwriting another region's grants. Shared roles receive the union of
regional permissions; this state split does not enforce regional isolation.
Budget and IAM trust/thumbprint inputs remain
accepted for compatibility, but account state controls those settings.
For existing states, follow the account README's non-destructive `removed` plus
optional import handoff before resuming normal applies. Model agreements are
account-owned; the regional approved manifest still validates the default model.
Only identities/common attachments/account singletons transfer ownership;
existing regional inline policy addresses stay here. Account creation needs no
regional ARNs or placeholder resource IDs. Tear down all regional consumers and
policies before deleting shared account roles; there is no cross-state lifecycle
graph. Older examples below that describe role creation must use the account root.

## Prerequisites

- **Terraform** — HCP workspace runtime pinned to 1.16.0; configuration compatible with `>= 1.15, < 2.0`
- **AWS CLI** configured with appropriate credentials (local development only)
- **VPC** with at least 2 subnets (for high availability)
- **Container image** pushed to a container registry (ECR, Docker Hub, etc.)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      AWS Account                        │
│                                                         │
│  ┌────────────┐    ┌──────────────┐   ┌─────────────┐ │
│  │ ECS Cluster│───>│ Fargate Task │<──│ ECS Exec    │ │
│  └────────────┘    └──────┬───────┘   │ (SSM)       │ │
│                           │            └─────────────┘ │
│                           │                             │
│            ┌──────────────┼──────────────┐              │
│            │              │              │              │
│            ▼              ▼              ▼              │
│      ┌─────────┐    ┌─────────┐   ┌──────────┐        │
│      │   EFS   │    │   S3    │   │ Bedrock  │        │
│      │/home/sre│    │ Audit   │   │(Claude)  │        │
│      └─────────┘    └─────────┘   └──────────┘        │
│      (persistent)   (WORM mode)    (AI)                │
└─────────────────────────────────────────────────────────┘
```

## Resources Created

- **S3 Bucket**: WORM-compliant audit bucket for investigation artifacts
- **EFS Filesystem**: Encrypted persistent storage for `/home/sre`
- **ECS Cluster**: Fargate cluster with Container Insights
- **ECS Task Definition**: Complete task definition with EFS mount
- **IAM Roles**: Looked up from account-owned execution/task roles, not created here
- **IAM permission grants**: Regional inline policies on shared account roles; common AWS-managed attachments remain account-owned
- **Security Groups**: For Fargate tasks and EFS mount targets
- **Bedrock Runtime interface endpoint**: Private DNS and an HTTPS-only security group restricted to the Fargate task security group; one endpoint ENI per task AZ
- **CloudWatch Log Group**: For container logs
- **Bedrock cost budget**: Account-owned monthly spend alerts (not created here)
- **Content bucket**: Regional published-content bucket, separate from the audit bucket

### Bedrock cost alerts

The budget amount and notification email are configured in `deploy/account`.
Copy existing active values when transferring ownership; regional compatibility
variables no longer control the budget. The alert thresholds and **actual**
monthly spend setting are defined in `deploy/account/bedrock-budget.tf`. The
Service filter includes all Amazon Bedrock spend in the account, not only ROSA
Boundary tasks or a single Region. Billing and alert evaluation can lag usage;
these alerts do not stop or cap inference spending.

### Bedrock Runtime private networking

The regional stack creates `com.amazonaws.${region}.bedrock-runtime` in
`subnet_ids`, with private DNS and one endpoint ENI per task AZ. Tasks using the
standard `bedrock-runtime.<region>.amazonaws.com` hostname route Bedrock Runtime
traffic through the VPC endpoint instead of NAT. Its dedicated security group
allows inbound TCP 443 only from `aws_security_group.fargate`. Other AWS APIs
continue to use their existing network paths.

The endpoint policy limits inference calls over this endpoint to the Boundary
task role, but does **not** restrict calls to the model-agreement manifest:
its inference-profile and foundation-model resource patterns are broad. The
task role's invocation policy is also broad (`iam.tf`). Account-level
agreements enable models, not a per-task model allowlist; see the
[model-agreement guide](../../docs/configuration/bedrock-model-agreements.md)
for the limits of relying on an absent subscription to deny an invocation.

### Bedrock model invocation logging

The regional stack enables text model invocation logging to a dedicated KMS-encrypted
CloudWatch Logs group (`/aws/bedrock/<project>-<stage>/model-invocations`) with
`retention_days` retention. Bedrock assumes a separate write-only role scoped to
its log stream. The setting is **account/Region-wide**, not restricted to
ROSA Boundary; coordinate with other Bedrock users before deployment. Logs may
contain prompts and responses (up to 100 KB inline) and must be read only by
authorized audit operators. The separate private S3 bucket
`<account>-<project>-<stage>-<region>-bedrock-invocations` receives larger
text payloads under `large-data/`, with SSE-S3, TLS-only access, Bedrock-only
write permissions, and `retention_days` lifecycle expiration. This is **not**
the investigation S3 audit escrow. Image, embedding, and video logging remain
disabled. Do not copy logged bodies into terminal transcripts; large-payload
delivery has not been validated with an oversized invocation.

#### Accepted access and encryption controls

For this deployment we accept storing unredacted model inputs and outputs in
the Bedrock audit destinations, subject to these controls:

- Reading invocation records requires privileged CloudWatch Logs permissions
  outside ordinary ROSA Boundary/Backplane task access. The Boundary task role
  and the OIDC-assumed SRE role in this stack do not grant read access to the
  Bedrock invocation log group. Bedrock's delivery role has only log-stream
  creation and event-write permissions. Account administrators or other roles
  granted CloudWatch Logs read permissions can still read the records; review
  their effective IAM access before staging rollout.
- CloudWatch invocation logs are encrypted at rest by the dedicated
  Terraform-managed customer-managed AWS KMS key in `bedrock-logging.tf`. We
  are retaining this key rather than switching to the AWS-managed CloudWatch
  Logs key. KMS permissions alone are not the log read-access boundary.
- Oversized text bodies in the separate private S3 bucket use AWS-managed
  SSE-S3 encryption, not that KMS key. S3 read access is governed separately
  by IAM and the bucket policy; block-public-access and the scoped Bedrock
  delivery *write* grant do not by themselves restrict privileged reads.

These controls limit access and protect storage at rest; they do **not** redact
prompts or responses, guarantee that sensitive data is absent, or scope the
account/Region-wide Bedrock configuration to Boundary callers. Review the
speculative HCP Terraform plan and the account's effective log/S3 readers
before the ownership-release apply; confirm the staging regional workspace's
manual-apply gate is active in HCP Terraform. For subsequent changes, review
speculative plans before merge and verify readers after apply; a merged PR
does not prove that its HCP run completed successfully.

## Published content storage

Every regional deployment creates
`<account>-<project>-<stage>-<region>-content`, a bucket for SRE content
published from its source repositories, along with key bootstrap and the shared
task role's regional read grant. There is no bucket enablement flag. This
applies to development, staging and production plans; review and approve each
plan before applying. It is deliberately separate from the audit bucket:
audit data is write-once evidence under Object Lock, published content is
mutable and read by every task. Publisher grants are created only for supplied
publisher role ARNs; replication is created only when destinations are supplied.

Protections: versioning, all four public-access-block flags, a TLS-only deny,
and `force_destroy = false` so destroying a populated bucket fails loudly. There
is **no** Object Lock — this is replaceable content, not evidence — and **no**
lifecycle rule that expires current objects; cleanup is limited to noncurrent
versions and abandoned multipart uploads.

### Encryption and the AWS-managed key

Default encryption is SSE-KMS with the Region's **AWS-managed** `alias/aws/s3`
key. No customer-managed key is created and no AWS-managed key policy is
edited. S3 Bucket Keys are deliberately not enabled: they would move the KMS
encryption context from the object ARN to the bucket ARN and would require
`kms:Decrypt` for the replication principal in the replica key's *key policy*,
which cannot be authored for an AWS-managed key.

AWS creates `aws/s3` on first use in an account and Region, so it may already
exist here or may not; either way its ARN is account- and Region-specific and
must never be guessed. The first apply writes one empty object at
`_bootstrap/key-init`, which makes an SSE-KMS request and so **guarantees the
key is available**, then reads whatever ARN is actually in place and publishes
it as `content_bucket_kms_key_arn`. The bootstrap establishes availability; it
is not evidence that the key was absent beforehand. That object is key
initialisation only: it is outside every published and replicated prefix,
nothing reads it, and no grant covers it, so a publisher's
`aws s3 sync --delete` can never remove it.

### Publishing

Publishing jobs should pass `--sse aws:kms`:

```bash
aws s3 sync ./content "s3://${CONTENT_BUCKET}/ops-sop/" --delete --sse aws:kms
```

Two mechanisms together make "no unencrypted or SSE-S3 object exists here" an
enforced invariant, which in turn lets the replication role omit
`kms:GenerateDataKey`:

- the bucket policy denies any upload that **asks for** an algorithm other than
  `aws:kms`; and
- bucket default encryption (`aws:kms`) encrypts any upload that asks for
  nothing.

The deny is guarded with `Null = "false"` so it applies only to requests that
actually supplied the `x-amz-server-side-encryption` header. That guard is
required for correctness, not leniency: AWS accepts that request header on
`PutObject`, `CopyObject`, `POST Object` and `CreateMultipartUpload` but **not**
on `UploadPart`, and a negated IAM condition operator evaluates to true when its
key is absent. An unguarded `StringNotEquals` would therefore deny every
`UploadPart` — which is authorised as `s3:PutObject` — and break multipart
uploads for exactly the large files the publisher grant's multipart permissions
exist to serve.

Server-side encryption with customer-provided keys (SSE-C) is denied outright
by a second statement: it uses a different request header, so the guard above
does not cover it, and an SSE-C object could be read by neither the task role
nor the replication role.

A real multipart upload has not been executed against a deployed bucket; that
check is listed under deferred activation verification below.

### Replication

The source Region owns exactly one replication configuration, with one rule per
destination and prefix, unique priorities, prefix-only filters, delete-marker
replication and the SSE-KMS opt-in S3 requires. Replication is same-account and
cross-Region, which AWS supports with an AWS-managed key; the restriction that
requires a customer-managed key applies only to cross-**account** replication.

Destination identifiers are plain inputs, never another Region's remote state,
so there is no cross-state cycle. Activating replication is a staged handoff and
no value may be invented:

1. Apply the destination Region with no `content_replication_destinations`.
   Its bucket, key bootstrap and task read grant are always included.
2. Read its `content_bucket_arn` and `content_bucket_kms_key_arn` outputs.
3. Supply those two real values in the source Region's
   `content_replication_destinations`, along with
   `content_replication_role_arn` from the account root.
4. Apply the source Region, which creates the rules.

Point publishers at the source only once the rules exist. S3 live replication
covers only objects written after a rule is created; to seed a newly added
destination with content that already exists, run **S3 Batch Replication** as an
operator action — Terraform does not backfill.

### Grants

Three regional inline policies, all on roles the account root owns, all carrying
the regional policy suffix:

| Policy | Role | Scope |
|---|---|---|
| `content-publish-<key>` | `<prefix>-publisher-<key>` | List, upload, delete and abort multipart in **one** prefix; `kms:GenerateDataKey` and `kms:Decrypt` on the regional key |
| `s3-content-read` | shared task role | List and get the published prefixes of the **local** bucket; `kms:Decrypt` |
| `content-replication` | `<prefix>-content-replication-role` | Source version reads, destination replicate/delete, source `kms:Decrypt` and destination `kms:Encrypt` |

The publisher grant has no `s3:GetObject`: `aws s3 sync` decides what to upload
from the listing's size and last-modified time and never reads the destination
object. `kms:Decrypt` is present because multipart `UploadPart` and
`CompleteMultipartUpload` require it. Each regional runtime grant is read-only
and names only its own bucket. The task role itself is shared across Regions:
its effective permissions are the union of all attached regional grants. This
is not a per-Region task-identity isolation boundary.

### Prefix values, source keys and local paths

A map **key** (`ops-sop`, `rosa-claude-plugins`, `managed-notifications`)
selects the account-owned publisher identity and names the IAM policy. Account
publishers are unconditional; regional grants remain opt-in. The map **value**
is the S3 prefix, and with its trailing slash removed it is also the
content-relative local path a consumer should materialise it at. Defaults
currently match their keys, but custom keys and nested prefixes need not:
`handbook = "ops-sop/v2/"` must map to `ops-sop/v2`, not `handbook`.
This storage change exports that contract; it does not implement the consumer.

Prefix values are constrained to `/`-terminated segments of `[A-Za-z0-9._-]`.
That is an allowlist, not a denylist of known-bad characters: these values are
interpolated into IAM `Resource` ARNs and `StringLike` conditions, where **both
`*` and `?` are wildcards**, and into policy text where `${...}` is a policy
variable. Permitting `?` alone would allow `?bootstrap/`, whose rendered
pattern matches the reserved `_bootstrap/` object. The same grammar excludes
whitespace and `:` so a value stays safe inside the space-delimited
`KEY:PREFIX` handoff a content consumer parses. Nested paths such as
`ops-sop/v2/` remain configurable.

### Deferred activation verification

These require an authorised deployment and have **not** been performed:

- a real `aws s3 sync --sse aws:kms` upload, including a file large enough to
  trigger `CreateMultipartUpload` / `UploadPart` / `CompleteMultipartUpload`,
  to confirm the bucket policy admits every multipart phase;
- resolution of the real regional `alias/aws/s3` key ARNs;
- actual replication of an object and of a delete marker to the replica Region,
  and the replication role's effective KMS permissions there.

## Execution Modes

### HCP Terraform (Remote Execution)

HCP Terraform executes Terraform directly in `deploy/regional` as the working
directory. Key differences from local execution:

- HCP Terraform **does not** automatically source the repository-root `.env`.
- HCP Terraform **does not** run the regional `Makefile` or its `build-lambda` target.
- All deployment values must be supplied through HCP Terraform workspace
  variables or approved variable sets — not hardcoded into generic resources.
- The `rosa-boundary-stage-regional` workspace variables are declared in
  [`../../hcp-terraform/rosa-boundary/main.tf`](../../hcp-terraform/rosa-boundary/main.tf),
  which is the source of truth. Update that file through a PR; do not edit
  workspace variables directly in the HCP Terraform UI, API, or MCP tools.
- The `Makefile` and `.env` workflow remain a local-development convenience,
  not a dependency of the Terraform root module.

#### Required HCP Terraform Workspace Variables

| Variable | Type | Description |
|----------|------|-------------|
| `aws_account_id` | string | 12-digit AWS account ID (provider deployment guard) |
| `aws_region` | string | AWS region for all resources |
| `stage` | string | Environment stage (`dev`, `stage`, `prod`) |
| `legacy_policy_region` | string | Match the account workspace's designated original region for legacy inline policy names |
| `vpc_id` | string | VPC ID where Fargate tasks run |
| `subnet_ids` | list(string) | Private subnet IDs (minimum 2 for HA) |
| `container_image` | string | Container image URI |
| `keycloak_issuer_url` | string | Keycloak OIDC issuer URL |
| `keycloak_thumbprint` | string (sensitive) | SHA1 thumbprint of Keycloak TLS certificate |
| `required_groups` | list(string) | Groups allowed to create/join investigations |

#### Optional Variables with Defaults

| Variable | Default | Notes |
|----------|---------|-------|
| `account_role_name_prefix` | `""` | Shared role prefix from the account workspace; staging sets it explicitly. |
| `abac_tag_key` | `"uuid"` | ECS task tag key for ABAC isolation. The correct value depends on the OIDC provider's principal-tag claim mapping. |
| `enable_metrics_read_grant` | `false` | Attaches the CloudWatch read grant to the account-owned metrics-read role. Enable **only** in the `legacy_policy_region` workspace, and **only after** the account workspace has applied `enable_metrics_read_role`; this root resolves that role by name and fails with `NoSuchEntity` otherwise. A non-owning region fails the plan on a precondition. See the [account README](../account/README.md). |

The staging regional workspace is configured in the Git-managed meta-workspace.
Do not apply its ownership-release plan until the non-destructive removals and
the account import inventory have both been reviewed under the verified gate.

### Local Development

> **Run all `make` commands from the project root**, not from this directory.
> The `deploy/regional/Makefile` sources `.env` from the project root and builds
> Lambda dependencies before applying — running `terraform` directly skips both.

### 1. Setup Infrastructure

```bash
# Copy the example configuration (from project root)
cp deploy/regional/terraform.tfvars.example deploy/regional/terraform.tfvars

# Edit with your VPC ID, subnets, and container image
vi deploy/regional/terraform.tfvars

# Initialize and apply Terraform (from project root)
make -C deploy/regional init
make -C deploy/regional plan
make -C deploy/regional apply
```

### 2. Push Container Image to ECR

```bash
# Create ECR repository (if not exists)
aws ecr create-repository --repository-name rosa-boundary

# Login to ECR
aws ecr get-login-password --region us-east-2 | \
  podman login --username AWS --password-stdin YOUR_ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com

# Tag and push image
podman tag rosa-boundary:latest-amd64 YOUR_ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com/rosa-boundary:latest
podman push YOUR_ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com/rosa-boundary:latest

# Update terraform.tfvars with ECR image URI and re-apply
make apply
```

### 3. Investigation Lifecycle Management

The `examples/` directory contains scripts for the complete investigation lifecycle:

```bash
cd examples/

# Create investigation workspace (EFS access point + task definition)
./create_investigation.sh rosa-prod-abc INV-12345 4.18

# Launch a Fargate task for the investigation
./launch_task.sh rosa-boundary-dev-rosa-prod-abc-INC-12345-TIMESTAMP

# Connect to the running task
./join_task.sh <task-id>

# Stop the task (triggers S3 sync)
./stop_task.sh <task-id>

# Close investigation (cleanup task definition + access point)
./close_investigation.sh rosa-boundary-dev-rosa-prod-abc-INV-12345-TIMESTAMP fsap-xxx
```

See [Investigation Lifecycle](#investigation-lifecycle) below for detailed examples.

## Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `aws_account_id` | string | **required** | 12-digit AWS account ID (provider deployment guard) |
| `aws_region` | string | **required** | AWS region for all resources |
| `project` | string | `"rosa-boundary"` | Project name for resource naming |
| `stage` | string | `"dev"` | Environment stage (dev, stage, prod) |
| `retention_days` | number | `90` | S3 object lock retention period (1-3650 days) |
| `retention_days` | number | `90` | Retention period for S3 and CloudWatch Logs (see [valid values](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html#SttingLogRetention)) |
| `container_image` | string | **required** | Container image URI |
| `claude_default_model` | string | `"us.anthropic.claude-sonnet-5"` | Bedrock inference profile Claude Code uses by default (`ANTHROPIC_MODEL`); Terraform checks the explicit mapping to a foundation model in `bedrock_model_agreements` when that map is nonempty. This does not enforce invocation access or check live availability |
| `container_cpu` | number | See `variables.tf` | Fargate CPU units (see [task size](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#task_size)) |
| `container_memory` | number | See `variables.tf` | Fargate memory in MB (see [task size](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#task_size)) |
| `vpc_id` | string | **required** | VPC ID for Fargate tasks |
| `subnet_ids` | list(string) | **required** | Subnet IDs (minimum 2 for HA) |
| `log_retention_days` | number | `7` | CloudWatch log retention period |
| `tags` | map(string) | `{}` | Additional tags for resources |
| `content_prefixes` | map(string) | three agreed prefixes | Published prefixes keyed by source key; values must be distinct and non-overlapping |
| `content_publisher_role_arns` | map(string) | `{}` | Publisher role ARNs from the account root; supply only in the publishing source Region |
| `content_replication_role_arn` | string | `""` | Account-owned content replication identity; required when destinations are set |
| `content_replication_destinations` | list(object) | `[]` | Replica Regions, each with the destination bucket ARN and that Region's resolved `aws/s3` key ARN |
| `content_noncurrent_version_days` | number | `30` | Expiry for superseded content versions; independent of `retention_days` |
| `content_bucket_force_destroy` | bool | `false` | Allow destroying a populated content bucket |

## Outputs

| Output | Description |
|--------|-------------|
| `bucket_name` | S3 audit bucket name |
| `bucket_arn` | S3 audit bucket ARN |
| `ecs_cluster_name` | ECS cluster name |
| `ecs_cluster_arn` | ECS cluster ARN |
| `task_definition_arn` | ECS task definition ARN |
| `task_definition_family` | ECS task definition family name |
| `task_role_arn` | ECS task IAM role ARN |
| `execution_role_arn` | ECS execution IAM role ARN |
| `efs_filesystem_id` | EFS filesystem ID |
| `efs_access_point_id` | EFS access point ID |
| `security_group_id` | Fargate security group ID |
| `efs_security_group_id` | EFS security group ID |
| `cloudwatch_log_group` | CloudWatch log group name |
| `content_bucket_name` | Published-content bucket name (empty when disabled) |
| `content_bucket_arn` | Published-content bucket ARN; a replica Region supplies this to the source Region |
| `content_bucket_region` | Region the content bucket lives in |
| `content_bucket_kms_key_arn` | Resolved AWS-managed `alias/aws/s3` key ARN; a replica Region supplies this to the source Region |
| `content_prefixes` | Published content prefixes keyed by source key |
| `content_replication_rule_ids` | Replication rule IDs this source Region owns (empty until activated) |

## Credential Volumes

The Terraform base task definition and Lambda-generated per-investigation task
definitions overlay `/home/sre/.config/ocm` and `/home/sre/.kube` with empty,
task-scoped Fargate volumes. These volumes have no persistent storage
configuration, use the default encrypted Fargate ephemeral storage, are not
mounted into the kube-proxy sidecar, and are destroyed with the task.

The legacy lifecycle scripts under `examples/` do not create these overlays and
are not a supported path for `credentials configure`.

## Investigation Lifecycle

The infrastructure uses a per-investigation isolation model with EFS access points and dedicated task definitions.

### Workflow Overview

```
1. create_investigation.sh  → Creates EFS access point + task definition with locked OC version
2. launch_task.sh           → Launches Fargate task for the investigation
3. join_task.sh        → Connects to running task via ECS Exec
4. stop_task.sh        → Stops task (triggers S3 sync to unique path)
5. close_investigation.sh   → Cleanup: deletes task definition + access point
```

### Path Structure

- **EFS**: `/$cluster_id/$investigation_id/` → Mounted to `/home/sre` in container
- **S3**: `s3://bucket/$cluster_id/$investigation_id/$date/$task_id/`

**Example:**
- EFS: `/rosa-prod-abc/INV-12345/` (shared across all tasks for this investigation)
- S3: `s3://bucket/rosa-prod-abc/INC-12345/20251215/d0910f05.../` (unique per task)

### Step 1: Create Investigation Workspace

```bash
cd examples/

# Syntax: ./create_investigation.sh <cluster-id> <investigation-id> [oc-version]
./create_investigation.sh rosa-prod-abc INV-12345 4.18
```

**Output:**
- EFS Access Point: `fsap-xxx` with path `/$cluster_id/$investigation_id/`
- Task Definition: `rosa-boundary-dev-$cluster_id-$investigation_id-TIMESTAMP`
- OC Version: Locked to specified version in task definition

**Save the output values** (task family name and access point ID) for later steps.

### Step 2: Launch Task

```bash
# Use task family name from create_investigation.sh output
./launch_task.sh rosa-boundary-dev-rosa-prod-abc-INC-12345-20251215-171625
```

**Automatic configuration:**
- Mounts investigation-specific EFS path to `/home/sre`
- Sets environment variables: `CLUSTER_ID`, `INVESTIGATION_ID`, `OC_VERSION`, `S3_AUDIT_BUCKET`
- Enables ECS Exec for interactive access

### Step 3: Connect to Task

```bash
# Use task ID from launch_task.sh output
./join_task.sh d0910f05129944e3a3b03f4b453bf18c
```

**Inside the container (as sre user):**
```bash
whoami                    # sre
pwd                       # /home/sre
claude --version          # 2.0.69
oc version --client       # 4.18.x (locked to investigation)
echo $CLUSTER_ID          # rosa-prod-abc
echo $INVESTIGATION_ID    # INV-12345

# Do your investigation work
# All files in /home/sre persist to EFS
```

### Step 4: Stop Task (Triggers S3 Sync)

```bash
./stop_task.sh d0910f05129944e3a3b03f4b453bf18c "Investigation complete"
```

**What happens:**
1. Container receives SIGTERM signal
2. Entrypoint auto-generates S3 path: `s3://bucket/$cluster/$investigation/$date/$taskid/`
3. Syncs `/home/sre` to S3 with WORM compliance, excluding `.config/ocm/*` and `.kube/*`
4. Container exits gracefully

**S3 Path Example:**
```
s3://641875867446-rosa-boundary-dev-us-east-2/rosa-prod-abc/INC-12345/20251215/d0910f05.../
```

### Step 5: Close Investigation (Cleanup)

```bash
# Use task family and access point ID from create_investigation.sh output
./close_investigation.sh rosa-boundary-dev-rosa-prod-abc-INV-12345-TIMESTAMP fsap-xxx
```

**Cleanup actions:**
1. Checks for running tasks (must stop all first)
2. Deregisters all task definition revisions
3. Deletes EFS access point (prompts for confirmation)

**Note:** EFS data remains on the filesystem but is no longer accessible. S3 data is retained per WORM policy.

---

## SSM Session Logging

All ECS Exec sessions are automatically streamed to CloudWatch Logs in real-time with KMS encryption.

### Session Log Structure

```
CloudWatch Log Group: /ecs/rosa-boundary-dev/ssm-sessions
  Log Streams: ecs-execute-command-<SESSION_ID>
    - Real-time command I/O capture
    - Session metadata in log events
```

### What's Logged

- **All commands typed** by the user
- **All command output** (stdout/stderr)
- **Session metadata**: Start time, end time, user identity, task ID
- **Encrypted with KMS** in transit and at rest

### Separate from Container Audit

SSM session logs capture real-time terminal activity, while container audit sync captures final state:

| Location | Content | When Captured |
|----------|---------|---------------|
| `/ecs/.../ssm-sessions` (CloudWatch) | Terminal I/O transcript | Real-time streaming during session |
| `$cluster/$investigation/$date/$taskid/` (S3) | `/home/sre` directory | On container exit |

### Viewing Session Logs

```bash
# List recent log streams
aws logs describe-log-streams \
  --log-group-name "/ecs/rosa-boundary-dev/ssm-sessions" \
  --order-by LastEventTime --descending \
  --max-items 10

# View session logs (real-time streaming)
aws logs tail "/ecs/rosa-boundary-dev/ssm-sessions" --follow

# Get logs for specific session
aws logs get-log-events \
  --log-group-name "/ecs/rosa-boundary-dev/ssm-sessions" \
  --log-stream-name "ecs-execute-command-<SESSION_ID>"

# Filter logs by time range
aws logs filter-log-events \
  --log-group-name "/ecs/rosa-boundary-dev/ssm-sessions" \
  --start-time $(date -d '1 hour ago' +%s)000
```

### Privacy Note

Session logs contain complete terminal output including any credentials or sensitive data typed during the session. Review logs before sharing.

---

## Environment Variables

### Automatically Set (by lifecycle scripts)

- `CLUSTER_ID` - ROSA cluster identifier
- `INVESTIGATION_ID` - Investigation tracking ID
- `OC_VERSION` - OpenShift CLI version (locked per investigation)
- `S3_AUDIT_BUCKET` - S3 bucket name for audit logs
- `CLAUDE_CODE_USE_BEDROCK=1` - Enable Claude Code via Bedrock

### Auto-Detected at Runtime

- `AWS_REGION` - Detected from ECS task metadata

### Optional Manual Overrides

- `S3_AUDIT_ESCROW` - Override auto-generated S3 path

## S3 Bucket WORM Compliance

The S3 bucket is configured with **Object Lock in Compliance mode**:

- **Retention period**: Configurable via `retention_days` variable
- **Mode**: COMPLIANCE (cannot be deleted before retention expires)
- **Versioning**: Required and enabled
- **Encryption**: AES256 server-side encryption
- **Public access**: Blocked

**Important**: Once an object is written, it cannot be deleted or modified until the retention period expires, even by the root account.

## EFS Persistent Storage

The EFS filesystem provides persistent storage for `/home/sre`:

- **Encryption**: At rest encryption enabled
- **Performance**: General Purpose mode with bursting throughput
- **Access Point**: Configured for sre user (uid=1000, gid=1000)
- **Lifecycle**: Transitions to Infrequent Access after 30 days
- **Mount path**: `/home/sre` in the container

Claude Code configuration and investigation artifacts persist across task restarts when using the same EFS filesystem.

## IAM Permissions

The account root owns the following role identities and common AWS-managed
attachments. This regional root owns the inline permission grants referencing
its resources. Grants from other regions on the same roles are additive, not
isolated; no root may exclusively reconcile policies on these shared roles.

### Task Execution Role

Used by ECS to pull images and write logs:

- `AmazonECSTaskExecutionRolePolicy` (AWS managed, account-owned attachment)
- Secrets Manager read access (regional inline policy, for future token injection)

### Task Role

Used by the container at runtime:

- **S3**: Write access to the audit bucket
- **Bedrock**: InvokeModel, InvokeModelWithResponseStream, ListInferenceProfiles, GetInferenceProfile (source-region, same-account inference profiles)
- **SSM**: ECS Exec permissions for interactive access

## Connecting to Running Tasks

### Via join_task.sh (Recommended)

```bash
cd examples/
./join_task.sh <task-id>
```

Automatically connects as the `sre` user via ECS Exec.

### Manual Connection

```bash
# List running tasks
aws ecs list-tasks --cluster rosa-boundary-dev --desired-status RUNNING

# Connect as sre user
aws ecs execute-command \
  --cluster rosa-boundary-dev \
  --task <task-id> \
  --container rosa-boundary \
  --interactive \
  --command '/usr/bin/su - sre'

# Or connect as root first
aws ecs execute-command \
  --cluster rosa-boundary-dev \
  --task <task-id> \
  --container rosa-boundary \
  --interactive \
  --command '/bin/bash'
```

### Viewing Logs

```bash
# Via AWS CLI
aws logs tail /ecs/rosa-boundary-dev --follow

# Via CloudWatch Console
# Navigate to CloudWatch > Log groups > /ecs/rosa-boundary-dev
```

## Cost Considerations

Estimated monthly costs (us-east-1, on-demand pricing):

- **Fargate**: ~$30-50/month (512 CPU, 1024 MB, running 24/7)
- **EFS**: ~$5-10/month (assuming 10 GB storage)
- **S3**: Variable based on storage and retention
- **CloudWatch Logs**: ~$0.50-2/month (7 day retention)
- **Bedrock**: Pay per API call (varies by model and usage)

**Note**: Actual costs depend on usage patterns. Consider using Fargate Spot for non-production environments.

## Cleanup

To destroy all resources:

```bash
# Empty the S3 bucket first (WORM compliance prevents Terraform from deleting objects)
aws s3 rm s3://$(cd deploy/regional && terraform output -raw bucket_name) --recursive

# Then destroy infrastructure (from deploy/regional/)
make destroy
```

**Warning**: Objects in compliance mode cannot be deleted until retention expires. You may need to wait or contact AWS support to delete the bucket.

## Troubleshooting

### Task fails to start

- Check CloudWatch logs: `/ecs/rosa-boundary-dev`
- Verify container image is accessible
- Ensure security groups allow outbound traffic

### EFS mount fails

- Verify mount targets are in the same subnets as Fargate tasks
- Check security group allows NFS (port 2049) from Fargate SG
- Ensure EFS mount targets are available (check AWS console)

### Bedrock access denied

- In a **new** investigation task after the regional base task definition is
  updated, check `AWS_REGION` and `ANTHROPIC_MODEL` and try a harmless prompt
  with plain `claude`. Lambda copies the base definition's environment into
  each new investigation task definition; already-running tasks and existing
  per-investigation definitions do not pick up new defaults automatically.
- Confirm the model is supported in the Bedrock Region and that the configured
  inference profile resolves to the intended foundation model. The default
  profile-to-foundation-model mapping is in `main.tf`.
- With an operator identity authorized for the Bedrock control plane, use
  `get-foundation-model-availability` to check agreement, authorization,
  entitlement, and Region status; the Boundary task role itself only has the
  runtime and profile permissions in `iam.tf`. For an Anthropic model, also
  confirm the account/organization first-time-use form is complete. Check the
  Terraform-managed agreements for the **account**, not just the manifest.
- A `GetInferenceProfile` access denial indicates missing task-role profile
  lookup permission; an invocation denial may instead indicate model
  availability/subscription or runtime authorization. A missing subscription
  usually prevents an unenabled third-party model from working because the task
  role cannot subscribe, but it is **not** a model deny-list: an existing
  account-wide agreement, models without Marketplace subscriptions, or AWS's
  temporary first-invocation behavior can change the outcome. For strict
  denial, use Bedrock invocation IAM/SCP restrictions.

### S3 sync fails

- Verify task role has S3 write permissions
- Check bucket name in `S3_AUDIT_ESCROW` environment variable
- Review container logs for AWS SDK errors

## Security Best Practices

1. **Use private subnets**: Run Fargate tasks in private subnets with NAT gateway
2. **Rotate credentials**: Use IAM roles instead of access keys
3. **Enable CloudTrail**: Monitor all S3 and Bedrock API calls
4. **Restrict Bedrock access**: Limit to specific model IDs if needed
5. **Use Secrets Manager**: Store OpenShift tokens in Secrets Manager (not S3)

## License

See parent repository LICENSE file.

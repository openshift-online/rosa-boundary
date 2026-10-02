# Auditing and Logging

This document describes what rosa-boundary audits, where audit data lives, and how to access it.

**Note**: This document should be considered accurate as of the last modified date in git.

---

## S3 Home Directory Escrow

**What**: Eligible files under `/home/sre` — for example shell history, downloaded files, and notes. Task-scoped OCM configuration and kubeconfig mounts (`.config/ocm/*` and `.kube/*`) are explicitly excluded; neither they nor symlink targets are escrowed.

**When**: The entrypoint attempts a sync on handled signals (SIGTERM, SIGINT, SIGHUP) and normal command completion when an audit destination is configured. It uses a `SYNC_TIMEOUT` guard (default 300s), but failures are not fatal, forced termination can bypass it, and the task definition sets a 120s container stop timeout. Do not assume a complete final snapshot; see [known lifecycle gaps](architecture/investigations-and-tasks.md#known-gaps).

**Where**: S3 bucket `{account_id}-{project}-{stage}-{region}`, path:

s3://{bucket}/{cluster_id}/{investigation_id}/{YYYYMMDD}/{task_id}/

**Protections**:
- WORM compliance — S3 Object Lock in `COMPLIANCE` mode (`retention_days`, default 90). Protected object versions cannot be deleted during retention, even by root; new versions of the same key can still be written.
- The task-role policy grants `s3:PutObject` on objects and `s3:ListBucket` on the bucket, but not `s3:GetObject` or `s3:DeleteObject`.
- No symlink following — `--no-follow-symlinks` prevents exfiltration of files outside `/home/sre`.
- Optional cross-account replication to a separate audit account (`audit_replication_bucket_arn`).
- TLS-only bucket policy; SSE-S3 encryption.

**How to access**:

```bash
# Set the bucket name from your deployed stack's bucket_name Terraform output,
# or use the naming convention (verify the account and Region first).
BUCKET="${ACCOUNT_ID}-${PROJECT}-${STAGE}-${AWS_REGION}"

# List investigations for a cluster
aws s3 ls "s3://${BUCKET}/${CLUSTER_ID}/" --recursive

# Download a specific task's home directory
aws s3 cp "s3://${BUCKET}/${CLUSTER_ID}/${INVESTIGATION_ID}/${DATE}/${TASK_ID}/" ./audit/ --recursive

# AWS Console → S3 → {account_id}-{project}-{stage}-{region}
```

Requires `s3:GetObject` and `s3:ListBucket` on the audit bucket (the task-role policy does not grant GetObject). Cross-account replicas, if configured, are accessed in the audit account.

---

## ECS Exec Session Logs

**What**: ECS Exec session transcript delivery, including commands and output visible in the session. It is not a guaranteed record of every keystroke: terminal echo can be disabled (for example, during credential injection), and log delivery can fail. Do not use this as the sole audit source.

**Where**: CloudWatch log group `/ecs/{project}-{stage}/ssm-sessions` (e.g., `/ecs/rosa-boundary-dev/ssm-sessions`). KMS-encrypted at rest with a dedicated key (`alias/{project}-{stage}-exec-session`). Retention: `retention_days` (default 90).

**How to access**:

```bash
LOG_GROUP="/ecs/rosa-boundary-dev/ssm-sessions"

# Tail live sessions
aws logs tail "${LOG_GROUP}" --follow

# Search sessions by time range
aws logs filter-log-events \
  --log-group-name "${LOG_GROUP}" \
  --start-time $(date -d '2 hours ago' +%s000) \
  --filter-pattern "some-command"

# AWS Console → CloudWatch → Log groups → /ecs/{project}-{stage}/ssm-sessions
```

Requires `logs:FilterLogEvents` and `kms:Decrypt` on the exec-session KMS key (`alias/{project}-{stage}-exec-session`).

---

## Container Logs

**What**: Container stdout/stderr — entrypoint and workload output. Interactive ECS Exec session output is delivered through the separate session logging path, not necessarily the container log stream.

**Where**: CloudWatch log group `/ecs/{project}-{stage}` (e.g., `/ecs/rosa-boundary-dev`), stream prefix `rosa-boundary`. The kube-proxy sidecar logs to the same group under prefix `kube-proxy`. Retention: `log_retention_days` (default 7).

**How to access**:

```bash
LOG_GROUP="/ecs/rosa-boundary-dev"

# Tail container output
aws logs tail "${LOG_GROUP}" --follow

# Filter by stream prefix (rosa-boundary or kube-proxy)
aws logs filter-log-events \
  --log-group-name "${LOG_GROUP}" \
  --log-stream-name-prefix "rosa-boundary"

# AWS Console → CloudWatch → Log groups → /ecs/{project}-{stage}
```

Requires `logs:FilterLogEvents` on the log group.

---

## Lambda Logs

### create-investigation

**What**: Every invocation including OIDC token validation results, authorized username and OIDC subject, group membership checks (pass/fail with actual groups), EFS access point creation/reuse, task definition registration, and ECS task launch with ARN.

**Where**: CloudWatch log group `/aws/lambda/{project}-{stage}-create-investigation`. Retention: `log_retention_days` (default 7).

### reap-tasks

**What**: Reaper runs, expired deadlines and stopped tasks, errors, and summary counts when tasks are found. Future deadlines and missing tags are logged only at DEBUG level; no-tasks runs do not log the final summary.

**Where**: CloudWatch log group `/aws/lambda/{project}-{stage}-reap-tasks`. Retention: `log_retention_days` (default 7).

**How to access**:

```bash
# create-investigation: who started what, when
aws logs filter-log-events \
  --log-group-name "/aws/lambda/rosa-boundary-dev-create-investigation" \
  --filter-pattern "Token validated"

# reap-tasks: what was stopped and why
aws logs filter-log-events \
  --log-group-name "/aws/lambda/rosa-boundary-dev-reap-tasks" \
  --filter-pattern "deadline exceeded"

# AWS Console → CloudWatch → Log groups → /aws/lambda/{project}-{stage}-*
```

Requires `logs:FilterLogEvents` on the respective Lambda log group.

---

## Bedrock Model Invocation Logs

**What**: Bedrock Runtime model invocation records, including request ID, model ID, caller IAM identity, token counts when available, and text prompt/response bodies. Text bodies up to 100 KB are included in the CloudWatch event; larger bodies are delivered to a separate S3 bucket and referenced from the event. These records may contain customer or other sensitive investigation content: limit read access accordingly.

**Scope and limitations**: The Terraform configuration enables **text** delivery for the entire AWS account and Region, not just Boundary tasks or a single investigation. Image, embedding, and video delivery are disabled. Bedrock invocation logging covers supported calls through `bedrock-runtime` (for example, `Converse`, `ConverseStream`, `InvokeModel`, and `InvokeModelWithResponseStream`), not all AI tools, all endpoints, or every CLI transcript. The `identity.arn` in a task's invocation record is its **ECS task role session**, not necessarily the SRE's OIDC identity. The configuration does not attach an investigation ID or SRE username to Bedrock requests. Correlate with the ECS task, its tags, and session logs rather than assuming a per-user or per-investigation log partition.

**Where**:

- CloudWatch log group `/aws/bedrock/{project}-{stage}/model-invocations`, log stream `aws/bedrock/modelinvocations`. Retention: `retention_days` (default 90). Encrypted with the dedicated KMS key `alias/{project}-{stage}-bedrock-invocations`.
- For text bodies larger than 100 KB: S3 bucket `{account_id}-{project}-{stage}-{region}-bedrock-invocations`, under `large-data/AWSLogs/{account_id}/BedrockModelInvocationLogs/`. S3 uses SSE-S3, blocks public access, and expires objects after `retention_days` (default 90). **Unlike the investigation audit bucket, this bucket does not have Object Lock or cross-account replication.** It is not the `/home/sre` audit escrow.

**How to access** (set the deployed project, stage, account and Region; use an authorized audit-reader identity):

```bash
LOG_GROUP="/aws/bedrock/${PROJECT}-${STAGE}/model-invocations"
PAYLOAD_BUCKET="${ACCOUNT_ID}-${PROJECT}-${STAGE}-${AWS_REGION}-bedrock-invocations"

# Confirm that logging is enabled in the selected account and Region
aws bedrock get-model-invocation-logging-configuration --region "${AWS_REGION}"

# Inspect records and locate the request ID, task-role identity, and any S3 references
aws logs filter-log-events --region "${AWS_REGION}" --log-group-name "${LOG_GROUP}" \
  --start-time "$(($(date +%s) - 7200))000"

# Inspect large-data objects, then download only the relevant object
aws s3 ls "s3://${PAYLOAD_BUCKET}/large-data/AWSLogs/${ACCOUNT_ID}/BedrockModelInvocationLogs/" \
  --recursive --region "${AWS_REGION}"
aws s3 cp "s3://${PAYLOAD_BUCKET}/${OBJECT_KEY}" ./bedrock-payload --region "${AWS_REGION}"
```

The reader needs `bedrock:GetModelInvocationLoggingConfiguration` to check the configuration, `logs:FilterLogEvents` on the log group to inspect records (and KMS decrypt access to the log-group key as applicable), and `s3:ListBucket`/`s3:GetObject` for the large-payload bucket. The ECS task role is not granted audit-read permissions. Deployment configuration is in `deploy/regional/bedrock-logging.tf` and `deploy/regional/bedrock-large-payloads.tf`.

---

## CloudTrail

**What**: AWS API activity, subject to the account's CloudTrail configuration. Event history includes recent management events (for example, ECS and STS calls). `s3:PutObject` and `lambda:InvokeFunction` are **data events**, which require separately configured selectors on a trail or event data store and are not available via ordinary Event history / `lookup-events` by default. CloudTrail API records do not contain Bedrock prompt/response content; see [Bedrock Model Invocation Logs](#bedrock-model-invocation-logs).

**Where**: AWS CloudTrail Event history for management events (90-day lookup window), or account/organization trails or event data stores if separately configured. This Terraform does not deploy a trail or enable S3/Lambda data-event selectors; verify their existence before relying on them.

**How to access**:

```bash
# Who exec'd into a task?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ExecuteCommand

# Who started a task?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunTask

# AWS Console → CloudTrail → Event history
# Filter management events by: ExecuteCommand, RunTask, StopTask, AssumeRoleWithWebIdentity
```

Event history requires `cloudtrail:LookupEvents`; accessing any separately configured trail or event data store requires its own permissions.

---

## Resource Tags

### ECS Task Tags

Applied at task creation by the create-investigation Lambda:

| Tag | Purpose |
|-----|---------|
| `oidc_sub` | OIDC subject claim (interpreted in the context of its issuer) |
| `{abac_tag_key}` (e.g., `username` or `uuid`) | ABAC identity for IAM policy enforcement |
| `investigation_id` | Investigation identifier |
| `cluster_id` | Target cluster |
| `oc_version` | OpenShift CLI version |
| `access_point_id` | EFS access point for this investigation |
| `created_at` | ISO 8601 creation timestamp |
| `deadline` | ISO 8601 deadline when `task_timeout > 0`; absent otherwise (reaper skips tasks without it) |
| `task_timeout` | Configured timeout in seconds |

### EFS Access Point Tags

These reflect access-point creation, not the identity of every subsequent task reusing it. The access point is deleted on investigation close; inspect individual task tags and Lambda logs for later launches.

| Tag | Purpose |
|-----|---------|
| `ClusterID` | Cluster identifier |
| `InvestigationID` | Investigation identifier |
| `oidc_sub` | OIDC subject UUID |
| `username` | Authenticated username |
| `ManagedBy` | `rosa-boundary-lambda` |

**How to access**:

```bash
# Task tags — who owns a running task?
aws ecs describe-tasks \
  --cluster rosa-boundary-dev \
  --tasks "${TASK_ARN}" \
  --include TAGS \
  --query 'tasks[0].tags'

# EFS access point tags — creation-time identity
aws efs describe-access-points \
  --file-system-id "${EFS_ID}" \
  --query 'AccessPoints[?Tags[?Key==`InvestigationID` && Value==`INC-12345`]]'

# AWS Console → ECS → Clusters → Tasks → Tags tab
# AWS Console → EFS → Access points → Tags tab
```

Requires `ecs:DescribeTasks` or `efs:DescribeAccessPoints` respectively.

---

## IAM Session Tags (Identity Propagation)

When configured, Keycloak injects `principal_tags.{abac_tag_key}` into the `https://aws.amazon.com/tags` JWT claim. STS propagates these as session tags during `AssumeRoleWithWebIdentity`. IAM policies use `aws:PrincipalTag/{abac_tag_key}` conditions to enforce per-user task access (exec, stop).

CLI actions using the assumed SRE role can be correlated with its role session and session tags. Investigation creation uses the invoker role; task launch uses the Lambda role; in-container Bedrock calls and S3 uploads use the ECS task role. Those downstream calls do **not** automatically carry the SRE's session tags. Correlate Lambda authorization logs and task tags with task-role activity; CloudTrail visibility still depends on event type and trail configuration.

---

## Summary

| Audit Source | What | Retention | Encryption |
|---|---|---|---|
| S3 audit bucket | Best-effort eligible `/home/sre` contents (credentials excluded) | 90 days WORM (configurable) | SSE-S3 |
| SSM session logs | ECS Exec session transcripts (not every keystroke) | 90 days (configurable) | KMS |
| Container logs | stdout/stderr | 7 days (configurable) | — |
| Lambda logs (create) | Auth, group checks, task creation | 7 days (configurable) | — |
| Lambda logs (reaper) | Deadline checks, task stops | 7 days (configurable) | — |
| Bedrock invocation logs | Bedrock Runtime metadata and text prompt/response bodies (account/Region-wide) | 90 days (configurable) | KMS (CloudWatch) |
| Bedrock large-payload bucket | Text bodies over 100 KB; no Object Lock | 90-day lifecycle (configurable) | SSE-S3 |
| CloudTrail | Management events; optional configured data events | 90-day Event history; trail policy if configured | Account policy |
| ECS/EFS resource tags | User identity, investigation metadata | Resource lifetime | — |

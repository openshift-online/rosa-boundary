# Auditing and Logging

This document describes what rosa-boundary audits, where audit data lives, and how to access it.

**Note**: This document should be considered accurate as of the last modified date in git.

---

## S3 Home Directory Escrow

**What**: The entire `/home/sre` directory — shell history, downloaded files, notes, kubeconfig, any artifact created during the investigation.

**When**: On every container exit (SIGTERM, SIGINT, SIGHUP, or normal exit). The entrypoint `sync_to_s3()` function runs inside a `SYNC_TIMEOUT` (default 300s) guard.

**Where**: S3 bucket `{account_id}-{project}-{stage}-{region}`, path:

s3://{bucket}/{cluster_id}/{investigation_id}/{YYYYMMDD}/{task_id}/

**Protections**:
- WORM compliance — S3 Object Lock in `COMPLIANCE` mode (`retention_days`, default 90). Objects cannot be deleted or overwritten during retention, even by root.
- Write-only — the task role has `s3:PutObject` only; no read, no delete.
- No symlink following — `--no-follow-symlinks` prevents exfiltration of files outside `/home/sre`.
- Optional cross-account replication to a separate audit account (`audit_replication_bucket_arn`).
- TLS-only bucket policy; SSE-S3 encryption.

**How to access**:

```bash
# Get the bucket name from Terraform outputs
BUCKET=$(cd deploy/regional && make output | grep bucket_name)

# List investigations for a cluster
aws s3 ls "s3://${BUCKET}/${CLUSTER_ID}/" --recursive

# Download a specific task's home directory
aws s3 cp "s3://${BUCKET}/${CLUSTER_ID}/${INVESTIGATION_ID}/${DATE}/${TASK_ID}/" ./audit/ --recursive

# AWS Console → S3 → {account_id}-{project}-{stage}-{region}
```

Requires `s3:GetObject` and `s3:ListBucket` on the audit bucket (the task role itself is write-only). Cross-account replicas are accessed in the audit account.

---

## ECS Exec Session Logs

**What**: Full interactive terminal I/O for every `ecs execute-command` (SSM) session — every keystroke and command output.

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

**What**: Container stdout/stderr — entrypoint output, tool invocations, and any output written to the console.

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

**What**: Every reaper run including number of tasks checked, deadline comparisons, tasks stopped (with deadline value), and summary counts (checked/stopped/skipped/errors).

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

## CloudTrail

**What**: All AWS API calls — `ecs:RunTask`, `ecs:ExecuteCommand`, `ecs:StopTask`, `sts:AssumeRoleWithWebIdentity`, `lambda:InvokeFunction`, `elasticfilesystem:CreateAccessPoint`, `s3:PutObject`, and everything else at the API level.

**Where**: Account-level or organization-level CloudTrail (not deployed by this Terraform — assumed to exist).

**How to access**:

```bash
# Who exec'd into a task?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ExecuteCommand

# Who started a task?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunTask

# AWS Console → CloudTrail → Event history
# Filter by: ExecuteCommand, RunTask, StopTask, InvokeFunction, AssumeRoleWithWebIdentity
```

CloudTrail is account-level; requires `cloudtrail:LookupEvents`.

---

## Resource Tags

### ECS Task Tags

Applied at task creation by the create-investigation Lambda:

| Tag | Purpose |
|-----|---------|
| `oidc_sub` | Immutable OIDC subject UUID — links task to IdP user |
| `{abac_tag_key}` (e.g., `username` or `uuid`) | ABAC identity for IAM policy enforcement |
| `investigation_id` | Investigation identifier |
| `cluster_id` | Target cluster |
| `oc_version` | OpenShift CLI version |
| `access_point_id` | EFS access point for this investigation |
| `created_at` | ISO 8601 creation timestamp |
| `deadline` | ISO 8601 deadline (enforced by reaper Lambda) |
| `task_timeout` | Configured timeout in seconds |

### EFS Access Point Tags

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

# EFS access point tags — who created an investigation?
aws efs describe-access-points \
  --file-system-id "${EFS_ID}" \
  --query 'AccessPoints[?Tags[?Key==`InvestigationID` && Value==`INC-12345`]]'

# AWS Console → ECS → Clusters → Tasks → Tags tab
# AWS Console → EFS → Access points → Tags tab
```

Requires `ecs:DescribeTasks` or `efs:DescribeAccessPoints` respectively.

---

## IAM Session Tags (Identity Propagation)

Keycloak injects `principal_tags.{abac_tag_key}` into the `https://aws.amazon.com/tags` JWT claim. STS propagates these as session tags during `AssumeRoleWithWebIdentity`. IAM policies use `aws:PrincipalTag/{abac_tag_key}` conditions to enforce per-user task access (exec, stop).

This means every AWS API call made through the SRE role carries the authenticated user's identity, visible in CloudTrail.

---

## Summary

| Audit Source | What | Retention | Encryption |
|---|---|---|---|
| S3 audit bucket | `/home/sre` contents on exit | 90 days WORM (configurable) | SSE-S3 |
| SSM session logs | Full terminal I/O | 90 days (configurable) | KMS |
| Container logs | stdout/stderr | 7 days (configurable) | — |
| Lambda logs (create) | Auth, group checks, task creation | 7 days (configurable) | — |
| Lambda logs (reaper) | Deadline checks, task stops | 7 days (configurable) | — |
| CloudTrail | All AWS API calls | Account policy | Account policy |
| ECS/EFS resource tags | User identity, investigation metadata | Resource lifetime | — |

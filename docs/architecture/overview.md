# System Architecture Overview

## 1. Purpose

rosa-boundary solves the problem of ephemeral, audited SRE access to ROSA/OpenShift clusters without standing AWS credentials or persistent IAM users.

**Problems it eliminates:**

- Shared, long-lived IAM credentials distributed to SRE laptops
- Per-user IAM roles that require manual lifecycle management
- SSH bastion hosts with their own patching burden and audit gaps
- Untracked terminal sessions with no artifact capture

**What it provides instead:**

- OIDC authentication via Red Hat SSO — SRE identity comes from the corporate IdP, not AWS
- Ephemeral Fargate containers that exist only for the duration of an investigation, isolated per cluster and per investigation
- Per-investigation EFS home directory: tools, notes, and kubeconfig are preserved across brief reconnects but destroyed when the investigation is closed
- Audit trail in S3 (full `/home/sre` sync on exit) and CloudWatch (ECS Exec session I/O and container stdout/stderr)
- Tamper-proof task timeout enforced by an external reaper Lambda, not by the container itself

---

## 2. Security Model

### 2.1 OIDC Authentication via Red Hat SSO

All access begins with an OIDC PKCE browser flow against Red Hat SSO (Keycloak). The CLI opens a browser, completes the flow, and caches the ID token at `~/.cache/rosa-boundary/`. No AWS credentials are distributed to SRE laptops directly.

The Keycloak client is configured with a custom protocol mapper that injects a `https://aws.amazon.com/tags` claim into the ID token. AWS STS automatically processes this claim as session tags during `AssumeRoleWithWebIdentity`, which is the mechanism that makes ABAC work without per-user roles.

Up to three OIDC providers can be registered simultaneously (dev Keycloak, Red Hat EmployeeIDP stage, Red Hat EmployeeIDP production), each with its own thumbprint and client ID. The create-investigation Lambda routes token validation by inspecting the unverified `iss` claim to select the correct JWKS endpoint.

### 2.2 Two-Step Role Assumption

The CLI performs two separate `AssumeRoleWithWebIdentity` calls before taking any action:

**Step 1 — lambda-invoker role:**

- Used to get SigV4 credentials for calling `lambda:InvokeFunction`
- Trust policy: federated via the IAM OIDC Provider, audience must equal `oidc_client_id`
- This role has exactly one permission: invoke the create-investigation Lambda
- An org-level SCP blocks `lambda:InvokeFunctionUrl` from OIDC-assumed sessions, so the CLI uses direct SDK invocation (`lambda:InvokeFunction`) instead

**Step 2 — sre-shared role:**

- Used to call `ecs:ExecuteCommand` and connect to a running task
- Trust policy: same federated trust, same audience condition
- The `sts:TagSession` action in the trust allows session tags from the JWT `https://aws.amazon.com/tags` claim to propagate
- The `abac_tag_key` variable (default: `username`) controls which claim key becomes the session tag

Both roles are assumed with the same ID token, but at different points in the workflow: the invoker role before creating the investigation, and the sre-shared role before connecting.

### 2.3 ABAC Task Isolation

All SREs assume a single shared role (`sre-shared`). Cross-user isolation is enforced at the AWS API layer using Attribute-Based Access Control.

**Tag flow:**

1. Keycloak maps the SRE's `preferred_username` (or `rhatUUID` for EmployeeIDP) to the `https://aws.amazon.com/tags` claim as `principal_tags.username`
2. STS propagates this as a session tag `username` on the assumed-role session
3. The create-investigation Lambda tags each ECS task with `username=<abac_tag_value>` using `ecs:TagResource` (applied explicitly after `RunTask` to guarantee tag availability for IAM evaluation)
4. The sre-shared role's ABAC policy condition: `ecs:ResourceTag/username == ${aws:PrincipalTag/username}`

**Two-statement ECS Exec policy design:**

`ecs:ExecuteCommand` requires permission on both the cluster resource AND the task resource. The policy uses two statements:

- `ExecuteCommandOnCluster`: cluster-level permission, no condition. All SREs pass this check. This alone grants no access to any task ("badge to enter the building").
- `ExecuteCommandOnOwnedTasks`: task-level permission, `StringEquals` condition on the `username` tag. Only tasks tagged with the caller's session tag pass.

**Fail-closed properties:**

- Missing session tag (Keycloak mapper misconfigured) → no `PrincipalTag` → condition fails → deny
- Untagged task → missing `ResourceTag` → condition fails → deny
- Cross-user exec attempt → tag mismatch → condition fails → deny

### 2.4 Tamper-Proof Task Timeout

The create-investigation Lambda computes a deadline at task creation time:

```
deadline = created_at + task_timeout  (ISO 8601 UTC)
```

This deadline is stored as an ECS task tag (`deadline=2026-02-16T12:34:56`). ECS task tags are only modifiable via the ECS API, which requires IAM permissions not granted to the task role. An SRE inside the container cannot extend their own session.

The reap-tasks Lambda runs on an EventBridge schedule (default: every 15 minutes). It lists all RUNNING tasks, calls `DescribeTasks` with `include=['TAGS']` to read the deadline tag, and calls `ecs:StopTask` for any task where `now > deadline`. Tasks without a deadline tag are skipped (fail-safe, not fail-open: tasks are not terminated speculatively).

The reaper's `ecs:StopTask` permission is conditioned on the task having a `deadline` tag (`ForAnyValue:StringLike`), preventing it from stopping tasks it does not manage.

### 2.5 Audit Trail

| Source | What is captured |
|--------|-----------------|
| CloudWatch `/ecs/rosa-boundary-dev` | Container stdout/stderr (awslogs driver) |
| CloudWatch `/ecs/rosa-boundary-dev/ssm-sessions` | Full ECS Exec session I/O (KMS encrypted) |
| CloudWatch `/aws/lambda/...-create-investigation` | Lambda invocations, OIDC validation results, group checks |
| CloudWatch `/aws/lambda/...-reap-tasks` | Reaper runs, tasks stopped, deadline values |
| CloudTrail | All AWS API calls: ECS, IAM, Lambda, EFS, STS |
| S3 audit bucket | Full `/home/sre` sync on container exit: shell history, notes, downloaded files |

The S3 path is deterministic: `s3://{bucket}/{cluster_id}/{investigation_id}/{YYYYMMDD}/{task_id}/`. The entrypoint's `sync_to_s3()` function runs on SIGTERM (ECS stop signal), SIGINT, SIGHUP, and normal exit. A `SYNC_TIMEOUT` (default 300s) prevents a hung S3 sync from blocking container shutdown past ECS's stop timeout.

---

## 3. Component Reference

### External

| Component | Role | Location |
|-----------|------|----------|
| `rosa-boundary` Go CLI | SRE workflow automation: login, start-task, join-task, list-tasks, stop-task, close-investigation | SRE laptop |
| Red Hat SSO / Keycloak | OIDC authentication and token issuance; group membership; session tag injection via `https://aws.amazon.com/tags` claim mapper | OpenShift cluster (RHBK operator) |
| ROSA/OpenShift cluster | Target cluster being investigated | AWS (managed) |

### IAM / STS

| Component | Role | Terraform |
|-----------|------|-----------|
| IAM OIDC Provider | Registers Keycloak as a trusted identity provider in AWS IAM; used in role trust policies | `oidc.tf` |
| IAM Role: `lambda-invoker` | First-step role; grants SRE credentials to call `lambda:InvokeFunction` | `lambda-invoker.tf` |
| IAM Role: `sre-shared` | Second-step role; ABAC policy enforces per-user task isolation via session tags | `oidc.tf` |
| STS | Issues temporary credentials for both role assumptions; propagates JWT session tags via `sts:TagSession` | AWS managed |

### Lambda

| Component | Role | Terraform |
|-----------|------|-----------|
| `create-investigation` | Validates OIDC token (JWKS), checks group membership, creates EFS access point, registers per-investigation task definition, runs ECS task with ABAC tags and deadline | `lambda-create-investigation.tf` |
| `reap-tasks` | Runs on EventBridge schedule; stops ECS tasks whose `deadline` tag has passed | `lambda-reap-tasks.tf` |
| EventBridge Rule | Triggers reap-tasks Lambda on a configurable schedule (default: 15 min) | `lambda-reap-tasks.tf` |

### ECS / VPC

| Component | Role | Terraform |
|-----------|------|-----------|
| ECS Fargate Cluster | Runs ephemeral investigation tasks; containerInsights enabled; execute command configured with KMS encryption | `ecs.tf` |
| ECS Task (per-investigation) | Ephemeral Fargate task; family name includes cluster ID, investigation ID, and timestamp; tagged with `username`, `oidc_sub`, `deadline` | Created at runtime by Lambda |
| Container: `rosa-boundary` | Multi-arch (amd64/arm64) container; runs as `sre` (uid=1000); includes `oc` 4.14–4.20, `aws` CLI, `claude` (Bedrock), `kubectl` | Built from `Containerfile` |
| Container: `kube-proxy` (optional) | Sidecar that runs `oc proxy` on localhost; exposes cluster API to the main container; must pass health check before main container starts | `ecs.tf` (`enable_kube_proxy`) |
| EFS Filesystem | Persistent storage; one access point per investigation; at-rest and in-transit encrypted | `efs.tf` |
| EFS Access Point | Per-investigation directory `/{cluster_id}/{investigation_id}/`; POSIX uid/gid=1000; mounts to `/home/sre` | Created by Lambda |
| KMS Key | Encrypts ECS Exec session data | `kms.tf` |
| Security Group | Applied to Fargate tasks; egress-all, no ingress | `ecs.tf` |
| VPC Interface Endpoints | `ssmmessages`, `kms`, `logs`, `ecr.api`, `ecr.dkr`, `ecs`; tasks have no internet egress requirement | `main.tf` or VPC config |

### AWS Managed Services

| Component | Role |
|-----------|------|
| SSM Session Manager | Relays ECS Exec WebSocket between the CLI's `session-manager-plugin` and the container | 
| ECR | Stores the `rosa-boundary` container image (multi-arch manifest) |
| CloudWatch Log Groups | `/ecs/rosa-boundary-dev` (container logs), `/ecs/rosa-boundary-dev/ssm-sessions` (session I/O) |
| S3 Audit Bucket | Receives `/home/sre` sync on container exit; 90-day WORM retention; optional cross-account replication |

---

## 4. Investigation Lifecycle

### Step 0: Prerequisites

```bash
# Install rosa-boundary CLI and session-manager-plugin
rosa-boundary configure   # writes ~/.config/rosa-boundary/config.yaml
```

Configure the CLI with:
- `lambda_function_name`: the `create-investigation` Lambda ARN or name
- `invoker_role_arn`: the `lambda-invoker` role ARN
- `sre_role_arn`: the `sre-shared` role ARN
- `ecs_cluster_name`: the ECS cluster name

### Step 1: Authenticate

```bash
rosa-boundary login
```

Opens a browser for the Keycloak PKCE flow. On success, the ID token is cached at `~/.cache/rosa-boundary/`. The token is valid for `oidc_session_duration` seconds (default: 3600).

### Step 2: Start an Investigation

```bash
rosa-boundary start-task \
  --cluster-id rosa-prod-01 \
  --investigation-id INC-12345 \
  [--oc-version 4.20] \
  [--task-timeout 3600] \
  [--connect]
```

What happens:
1. CLI calls STS `AssumeRoleWithWebIdentity` with the ID token → `lambda-invoker` temporary credentials
2. CLI calls `lambda:InvokeFunction` (SigV4) with the ID token in `X-OIDC-Token` header and investigation parameters in the body
3. Lambda validates the ID token against the Keycloak JWKS endpoint (RS256 signature, audience, expiry)
4. Lambda checks that the user is a member of at least one group in `REQUIRED_GROUPS` (e.g., `sre-team`)
5. Lambda creates (or reuses) an EFS access point at `/{cluster_id}/{investigation_id}/`
6. Lambda registers a per-investigation task definition with the EFS access point baked in and investigation environment variables (`CLUSTER_ID`, `INVESTIGATION_ID`, `OC_VERSION`, `S3_AUDIT_BUCKET`, `TASK_TIMEOUT`)
7. Lambda calls `RunTask` with `enableExecuteCommand=true`, `launchType=FARGATE`, `startedBy=sha256({cluster_id}:{investigation_id})[:36]`, and task tags including `username`, `oidc_sub`, `deadline`, `investigation_id`, `cluster_id`
8. Lambda calls `TagResource` explicitly to guarantee tags are visible to IAM before the SRE connects
9. CLI calls STS `AssumeRoleWithWebIdentity` with the ID token → `sre-shared` credentials with `username` session tag

If `--connect` is passed, the CLI immediately proceeds to join the task.

**Duplicate detection:** If a task with the same `startedBy` value is already RUNNING, the Lambda returns HTTP 409. The CLI reports the existing task ARN.

### Step 3: Connect to a Running Task

```bash
rosa-boundary join-task <task-id>
```

What happens:
1. CLI calls `ecs:DescribeTask` to check task status
2. If not yet RUNNING, the CLI polls until it is (or `--no-wait` is set)
3. CLI calls `ecs:ExecuteCommand` — IAM evaluates the two-statement ABAC policy (cluster permission + task username tag match)
4. AWS returns an SSM session token
5. CLI calls `syscall.Exec` (process replacement) into `session-manager-plugin` with the session token
6. `session-manager-plugin` opens a WebSocket to the SSM regional endpoint, which relays to the container via the `ssmmessages` VPC interface endpoint
7. The container runs `bash` as the `sre` user (the default `joinCommand` is `runuser -u sre -- bash`)

The user is now in an interactive shell with:
- `/home/sre` mounted from the investigation's EFS access point
- `oc` pointing at the target cluster via `~/.kube/config` (written by entrypoint using `KUBE_PROXY_PORT`)
- `claude` CLI configured for Bedrock

### Step 4: Task Expiry (Automatic)

The reap-tasks Lambda runs every 15 minutes. When `now > deadline` tag:
1. Lambda calls `ecs:StopTask` with reason `Task deadline exceeded (deadline: {deadline_str})`
2. ECS sends SIGTERM to the container
3. `entrypoint.sh` catches SIGTERM and calls `sync_to_s3()` before exiting

The deadline is computed by the create-investigation Lambda as:
```
deadline = datetime.utcnow() + timedelta(seconds=task_timeout)
```

It is immutable after task launch (task tags require `ecs:TagResource`, which the task role does not have).

### Step 5: Stop a Task Manually

```bash
rosa-boundary stop-task <task-id>
```

This calls `ecs:StopTask` using the sre-shared credentials. The container's SIGTERM trap fires, syncing `/home/sre` to S3 before exiting.

### Step 6: Close an Investigation

```bash
rosa-boundary close-investigation \
  --cluster-id rosa-prod-01 \
  --investigation-id INC-12345
```

This:
1. Stops all running tasks for the investigation
2. Deregisters all per-investigation task definitions
3. Deletes the EFS access point

Data in S3 is retained per the bucket's lifecycle policy (90-day WORM). Data in EFS is permanently deleted when the access point is deleted.

---

## 5. Configuration Reference

All Terraform variables are set in `deploy/regional/variables.tf`. Values without defaults must be supplied via `.env` (loaded by the `deploy/regional/Makefile`) or passed as `-var` flags.

### Required (no default)

| Variable | Description | Example |
|----------|-------------|---------|
| `keycloak_issuer_url` | Primary Keycloak OIDC issuer URL | `https://sso.example.com/realms/sre-ops` |
| `keycloak_thumbprint` | SHA1 of Keycloak TLS cert (for IAM OIDC Provider) | `aabbcc...` (40 hex chars) |
| `container_image` | Container image URI (ECR or other registry) | `123456789.dkr.ecr.us-east-1.amazonaws.com/rosa-boundary:latest` |
| `vpc_id` | VPC where Fargate tasks run | `vpc-0abc123` |
| `subnet_ids` | List of private subnet IDs for tasks and EFS mount targets | `["subnet-0abc", "subnet-0def"]` |
| `required_groups` | Keycloak groups that may create investigations (at least one must match) | `["sre-team"]` |

### Key Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `oidc_client_id` | `aws-sre-access` | Keycloak client ID; must equal `aud` claim in the JWT |
| `abac_tag_key` | `username` | ECS tag key for ABAC isolation. Use `username` for dev Keycloak, `uuid` (= `rhatUUID`) for Red Hat EmployeeIDP |
| `task_timeout_default` | `3600` | Default task lifetime in seconds (passed as `TASK_TIMEOUT` env var; enforced by reaper) |
| `task_timeout_minimum` | `30` | Minimum timeout a caller may request; lower values are rejected by the Lambda |
| `oidc_session_duration` | `3600` | Max session duration for the sre-shared role |
| `reaper_schedule_minutes` | `15` | How often the reap-tasks Lambda runs (1–1440) |
| `stage_keycloak_issuer_url` | `""` | Optional second OIDC provider (e.g., Red Hat EmployeeIDP stage). Leave empty to skip. |
| `prod_keycloak_issuer_url` | `""` | Optional third OIDC provider (e.g., Red Hat EmployeeIDP production). Leave empty to skip. |
| `enable_kube_proxy` | `false` | Include the `kube-proxy` sidecar in the base task definition |
| `container_cpu` | `1024` | Fargate CPU units (256/512/1024/2048/4096) |
| `container_memory` | `2048` | Fargate memory in MB |
| `log_retention_days` | `7` | CloudWatch log retention for Lambda and ECS container logs |
| `retention_days` | `90` | CloudWatch and S3 retention for session logs and audit data |
| `audit_replication_bucket_arn` | `""` | Cross-account S3 replication destination. Empty disables replication. |

### Lambda Environment Variables (set by Terraform, not editable at runtime)

| Variable | Source |
|----------|--------|
| `KEYCLOAK_URL` | Derived from `keycloak_issuer_url` |
| `KEYCLOAK_REALM` | Derived from `keycloak_issuer_url` |
| `KEYCLOAK_CLIENT_ID` | `oidc_client_id` |
| `REQUIRED_GROUPS` | Comma-separated `required_groups` list |
| `ABAC_TAG_KEY` | `abac_tag_key` |
| `TASK_TIMEOUT_DEFAULT` | `task_timeout_default` |
| `TASK_TIMEOUT_MINIMUM` | `task_timeout_minimum` |
| `ECS_CLUSTER` | ECS cluster name (both Lambdas) |
| `EFS_FILESYSTEM_ID` | EFS filesystem ID |
| `SHARED_ROLE_ARN` | ARN of the sre-shared IAM role |
| `S3_AUDIT_BUCKET` | S3 audit bucket name |
| `STAGE_KEYCLOAK_ISSUER_URL` | `stage_keycloak_issuer_url` (create-investigation only) |
| `PROD_KEYCLOAK_ISSUER_URL` | `prod_keycloak_issuer_url` (create-investigation only) |

### CLI Configuration (~/.config/rosa-boundary/config.yaml)

| Field | Env var | Description |
|-------|---------|-------------|
| `lambda_function_name` | `ROSA_BOUNDARY_LAMBDA_FUNCTION_NAME` | Lambda function name or ARN |
| `invoker_role_arn` | `ROSA_BOUNDARY_INVOKER_ROLE_ARN` | lambda-invoker role ARN |
| `sre_role_arn` | `ROSA_BOUNDARY_SRE_ROLE_ARN` | sre-shared role ARN |
| `ecs_cluster_name` | `ROSA_BOUNDARY_ECS_CLUSTER_NAME` | ECS cluster name |
| `efs_filesystem_id` | `ROSA_BOUNDARY_EFS_FILESYSTEM_ID` | EFS filesystem ID (required for `close-investigation`) |
| `aws_region` | `ROSA_BOUNDARY_AWS_REGION` | AWS region |

---

## 6. Operator Quick Reference

### Initial Setup

```bash
# Configure the CLI (interactive wizard)
rosa-boundary configure

# Verify the config
cat ~/.config/rosa-boundary/config.yaml
```

### Standard Investigation Workflow

```bash
# 1. Login (opens browser for Keycloak PKCE)
rosa-boundary login

# 2. Start a task and connect immediately
rosa-boundary start-task \
  --cluster-id <cluster-id> \
  --investigation-id <investigation-id> \
  --connect

# 2b. Or start without connecting (returns task ARN)
rosa-boundary start-task \
  --cluster-id <cluster-id> \
  --investigation-id <investigation-id>

# 3. List running tasks
rosa-boundary list-tasks

# 4. Reconnect to a running task
rosa-boundary join-task <task-id>

# 5. Stop a single task
rosa-boundary stop-task <task-id>

# 6. Close the investigation completely
#    (stops tasks, deregisters task defs, deletes EFS access point)
rosa-boundary close-investigation \
  --cluster-id <cluster-id> \
  --investigation-id <investigation-id>
```

### Custom Options

```bash
# Specific OC version and extended timeout
rosa-boundary start-task \
  --cluster-id <cluster-id> \
  --investigation-id <investigation-id> \
  --oc-version 4.18 \
  --task-timeout 7200 \
  --connect

# Create the EFS access point only (no task — useful for pre-staging)
rosa-boundary create-investigation \
  --cluster-id <cluster-id> \
  --investigation-id <investigation-id>

# Connect to a specific container in the task
rosa-boundary join-task <task-id> --container kube-proxy

# Run a non-interactive command
rosa-boundary join-task <task-id> --command "oc get nodes"
```

### Infrastructure Operations

```bash
cd deploy/regional

# Plan/apply Terraform changes
make plan
make apply          # also builds Lambda deps before terraform apply

# View Terraform outputs (Lambda ARN, role ARNs, etc.)
make output

# Run LocalStack integration tests
make localstack-up
make test-localstack-fast   # skip slow ECS task launch tests
make test-localstack        # full suite
make localstack-down

# Run Lambda unit tests
make test-lambda-create-investigation
make test-lambda-reap-tasks
```

### Debugging

```bash
# Check if a task has ECS Exec enabled and is connectable
aws ecs describe-tasks \
  --cluster <cluster-name> \
  --tasks <task-arn> \
  --include TAGS

# Check deadline tag
aws ecs describe-tasks \
  --cluster <cluster-name> \
  --tasks <task-arn> \
  --include TAGS \
  --query 'tasks[0].tags[?key==`deadline`].value'

# View Lambda logs
aws logs tail /aws/lambda/<project>-<stage>-create-investigation --follow

# View reaper logs
aws logs tail /aws/lambda/<project>-<stage>-reap-tasks --follow

# View session I/O logs
aws logs tail /ecs/<project>-<stage>/ssm-sessions --follow
```

---

## Related Documents

- [AWS IAM Policies](../configuration/aws-iam-policies.md) — full policy JSON for all roles
- [Keycloak Realm Setup](../configuration/keycloak-realm-setup.md) — realm, client, and claim mapper configuration
- [Investigation Workflow Runbook](../runbooks/investigation-workflow.md) — end-to-end walkthrough with troubleshooting
- [User Access Guide](../runbooks/user-access-guide.md) — onboarding guide for SREs
- [LocalStack Test README](../../tests/localstack/README.md) — integration test documentation

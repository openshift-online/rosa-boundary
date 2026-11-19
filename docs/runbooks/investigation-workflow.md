# Investigation Workflow

## Overview

This runbook describes the complete investigation lifecycle using the `rosa-boundary` CLI with
Lambda-based OIDC authentication, from creation through access to closure. The CLI handles
OIDC authentication, role assumption, and ECS Exec session hand-off; audit retrieval is a
separate operator/audit-reader workflow. Use an approved target and confirm the intended
account and region before creating a task.
Replace all `<...>` placeholders with approved values before running commands;
angle brackets in a shell command are redirection operators, not literal syntax.

## Workflow Diagram

```mermaid
stateDiagram-v2
    [*] --> LoggedIn: rosa-boundary login
    LoggedIn --> TaskRunning: rosa-boundary session create
    TaskRunning --> UserConnected: rosa-boundary session join
    UserConnected --> Investigation: Work in container
    Investigation --> UserDisconnected: exit
    UserDisconnected --> TaskStopped: rosa-boundary session close --wait
    TaskStopped --> InvestigationClosed: rosa-boundary investigation close
    InvestigationClosed --> [*]

    note right of LoggedIn
        - Browser PKCE by default; optional human-approved device flow
        - Boundary ID token cached under XDG cache directory
    end note

    note right of TaskRunning
        - CLI assumes invoker role via STS
        - Lambda validates OIDC token + group
        - EFS access point created
        - Task definition registered (per-investigation)
        - ECS task launched with identity/investigation tags
        - Lambda returns shared SRE role ARN
    end note

    note right of UserConnected
        - CLI assumes shared SRE ABAC role
        - ABAC compares the configured task and principal tag
        - ECS Exec session handed off to session-manager-plugin
    end note

    note right of TaskStopped
        - SIGTERM attempts entrypoint S3 sync
        - Verify CloudWatch and S3 evidence separately
    end note

    note right of InvestigationClosed
        - Owner-only CLI operation; requires independent verified receipt
        - --force permits stopping tasks, not bypassing audit verification
        - Task definitions deregistered
        - EFS access point deleted
    end note
```

## Prerequisites

```bash
# Build the CLI
make build-cli

# Verify session-manager-plugin is installed (required for session join)
session-manager-plugin --version
```

No existing AWS credentials or AWS CLI are required for normal Boundary CLI use.
An AWS CLI with separate CloudWatch Logs and S3 read permissions is needed for
the audit verification examples below.

## Configure for the intended deployment

Follow the [user access guide](user-access-guide.md#3-configure-cli) to create
a **named profile** using the operator-supplied account, region, project and
environment. If an old flat config exists, delete or move it and run `config init`
to create profiles from scratch; no migration is provided. Check the discovered Lambda, role ARNs,
cluster, and EFS filesystem before proceeding. Select the intended deployment
with `--profile <name>` on each invocation or `config use-profile <name>` to make it
active; `login` alone does not configure the roles needed by other commands.
On a headless server, pass `--use-device-code` explicitly to `config init` to
use device approval during auto-discovery and save `oidc_use_device_code: true`.
Without an explicit true flag, init uses a browser and writes `false` even if
the environment says true. Manual `config init --auto-discover=false` saves
the selected boolean without logging in.
Ordinary commands use explicit `--use-device-code=true|false` (bare means true)
> `ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE` > saved boolean > default `false`.
Explicit false overrides true for both providers; invalid booleans are errors.

## Phase 1: Authenticate

```bash
./bin/rosa-boundary --profile <profile-name> login
```

What it does:
- Opens a browser for Keycloak PKCE authentication by default when a fresh
  Boundary ID token is needed; with device mode, displays a URL and code on
  stderr to approve on another device while the CLI waits, without a local
  browser or callback port
- Caches the ID token under `${XDG_CACHE_HOME:-$HOME/.cache}/rosa-boundary/token-cache`
- Reuses a valid token until shortly before its actual `exp`, regardless of flow;
  `login --force` requests a fresh approval. An
  expired cache or STS rejection during a later command can also request
  fresh approval in the selected mode, with no automatic browser fallback.

Device approval is **per-user and human-in-the-loop**: it does not provide an
unattended service credential. Scripts must handle a challenge during **any**
auth-bearing command, not just a preceding `login`. See the
[user access guide's concurrent stderr-draining example](user-access-guide.md#script-driven-human-approved-login).

## Phase 2: Create Session

```bash
./bin/rosa-boundary --profile <profile-name> session create <cluster-id> \
  --investigation-id <investigation-id>
```

Optional flags:
```
  --session-timeout 1h    # task lifetime; must meet the deployment's policy
  --with-credentials none # opt out of default fresh OCM token injection
  --ocm-url production    # production, staging, integration, or canonical URL
  --ocm-auth-flow device  # explicit OCM-only override; otherwise follows global device preference
```

`session create` injects OCM credentials by default. `--with-credentials none`
opts out. `--no-wait` skips injection and warns with a follow-up
`session credentials configure ocm <session-id>` command to run once the task
is RUNNING; explicitly combining `--no-wait` and `--with-credentials ocm` is
rejected. If OCM authorization or injection fails after task creation, the
session remains usable, and the CLI warns with the session ID, a retry command,
and a profile-qualified cleanup command; OCM credentials are **not confirmed**.
A RUNNING wait failure still returns nonzero; the session may already be
STOPPED. Inspect `session list --status all` before retrying. `--no-wait`
reports launch only. By default, the CLI separately requests a fresh OCM access
token from the OCM issuer/client, not the cached Boundary ID token. The OCM
approval prompt appears while the task is still starting, so approve it without
waiting for RUNNING; the token is uploaded once the task is ready. The saved
device preference (or explicit global flag/env override) applies to both
providers by default, so a fresh Boundary token **and** OCM credentials may
require **two distinct human approvals** in one `session create`. A cached Boundary
token may eliminate only the Boundary challenge. An explicitly specified
`--ocm-auth-flow auth-code|device` overrides OCM only; `auth-code` still
requires a browser callback even if Boundary uses device mode. Any device
flow remains browser-free. OCM credential transfer uses task-scoped,
audit-excluded storage, not the Boundary token cache or EFS home.

Creation opens a shell by default; use `--no-connect` to join separately.
For scripted operation, use `session create ... --no-connect -o json`: stdout contains the
single session-result JSON document; stderr carries human-readable
authentication challenges and other diagnostics (not auth-event protocol lines).
Read stderr **as the CLI runs** and show each URL/code privately to the SRE,
not in shared CI logs. Check the **process exit status** before trusting the
result. If OCM approval or transfer fails after task creation, the command succeeds
with a warning on stderr (and `warnings` in JSON); JSON does not include
`credentials` unless configuration succeeded. Note the session ID and explicitly
retry credential configuration or stop the task and verify cleanup. A nonzero
exit from another failure still does not prove that the task was not created.

What it does:
1. **CLI assumes the invoker role** via STS using the OIDC ID token (no existing AWS credentials)
2. **Invokes the create-investigation Lambda** with the cached OIDC token
3. **Lambda validates** the token against Keycloak JWKS and checks the deployment's required group and ABAC claim
4. **Lambda creates an EFS access point**: `/<cluster-id>/<investigation-id>/`
5. **Lambda registers a per-investigation task definition** with the image-shipped oc and pre-set env vars
6. **Lambda launches the ECS task** with the deployment's ABAC tag and investigation/deadline tags
7. **Lambda returns the shared SRE role ARN** and task ARN
8. CLI prints connection command

Output includes the Boundary session ID (underlying ECS task ID or ARN), **not**
the short-lived SSM session ID created by ECS Exec. Save it for join and stop.
An investigation workspace can outlive multiple sessions.

### Timeouts and handover

The CLI defaults `--session-timeout` to **1h** and sends it explicitly; Terraform's
**8h** default applies only when the Lambda request omits the value. CLI accepts
`0s`, but the deployed default minimum of 30 seconds rejects it. Global
`--timeout` is a separate local command deadline, and explicit `--timeout 0s`
is invalid. Read the [timeout matrix](../architecture/session-lifecycle.md#timeout-matrix)
before selecting a value. A deadline is not a guaranteed stop time:
[strict-deadline and active-session policies remain unresolved](../architecture/session-lifecycle.md#unresolved-policy-decisions).

To hand over a workspace, coordinate with its current SRE and have them disconnect
Exec. The successor uses their own profile/identity to request a replacement:

```bash
./bin/rosa-boundary --profile <successor-profile> session create <cluster-id> \
  --investigation-id <existing-investigation-id>
```

Lambda checks existing RUNNING tasks for active SSM connections before stopping
any; a detected active connection returns 409. It waits for old tasks to STOP
before launching the replacement; stop/wait failures abort replacement, not
already initiated stops. Verify predecessor audit evidence independently.
This is not an atomic concurrency lock. See [handover details and limitations](../architecture/session-lifecycle.md#handover-is-replacement-not-joining-another-users-task).
The new task belongs to the caller, but the access point keeps its original
creator tags and creation time. CLI investigation-close ownership does not
transfer; see the separate [ROSAENG-75946 close-ownership work](https://redhat.atlassian.net/browse/ROSAENG-75946).
Same-user recreation is also currently possible, subject to the same active-session
checks; [ROSAENG-75947](https://redhat.atlassian.net/browse/ROSAENG-75947) tracks its
prevention and takeover policy. Credential mounts do not persist: configure fresh OCM credentials on
the new task. See [actual task/AP tags](../architecture/session-lifecycle.md#actual-resource-tags-creator-versus-actor).

## Phase 3: List Tasks

```bash
./bin/rosa-boundary --profile <profile-name> session list \
  --status RUNNING
```

Shows: session ID (ECS task ID), status, cluster, investigation ID, OWNER, start time.
OWNER is the task's `uuid` tag, falling back to `username`, not necessarily the
workspace creator. Use `--status all` to include stopped tasks.

## Phase 4: Connect to Container

```bash
./bin/rosa-boundary --profile <profile-name> session join <session-id>
```

What it does:
1. Assumes the shared SRE ABAC role (using the deployment's configured tag key)
2. Calls `ecs:ExecuteCommand` — IAM compares the task's ABAC tag with the caller's OIDC-derived session tag
3. Waits for the container exec agent to open its data channel
4. Hands the interactive session to `session-manager-plugin` for a seamless terminal

`session join -o json` and `session create -o json` show human authentication
guidance on stderr and keep shell I/O on `/dev/tty`. On successful shell exit,
stdout contains one JSON result with `status: disconnected`, `task_closed: false`,
and `investigation_closed: false`; the created session ID remains in the create
result. Exec failure returns nonzero with a failure JSON object (`error.code: command_failed`), **not** a success JSON object; after
create, stderr includes the session ID and cleanup guidance. Use a controlling
terminal for both commands. `session create --no-wait -o json` reports
`status: launched` rather than claiming readiness.

Inside the container (as `sre` user):
```bash
whoami              # sre
echo $CLUSTER_ID    # <cluster-id>
echo $INVESTIGATION_ID  # <investigation-id>
claude --version    # Confirms installation, not Bedrock access
oc version --client # OpenShift CLI shipped in this task's image
```

Exec does not inherit arbitrary entrypoint exports. Region and Bedrock defaults
come from the image/task definition and shell configuration; inspect the actual
shell environment after creating a fresh task. The image exposes AWS CLI via
`/usr/local/bin/aws` (alternatives) targeting `/usr/local/aws-cli/v2/current/aws`.
Check `command -v aws`, `readlink -f /usr/local/bin/aws`, and `aws --version` rather
than assuming `/usr/bin/aws`. See [Exec environment](../architecture/session-lifecycle.md#exec-environment-and-aws-cli)
and the [actual VPC endpoint inventory](../architecture/session-lifecycle.md#network-endpoints-are-deployment-specific);
this repository does not provision an SSM interface endpoint or guarantee no
internet egress requirement.

### Verify Bedrock access from a fresh task

After a regional Terraform change to the base ECS task definition, create a
**new** investigation task: Lambda copies the base container environment into
each per-investigation task definition, so a running task or an older
per-investigation definition does not acquire new defaults. In the new task,
use only a benign test prompt (Bedrock invocation logs can include the full
prompt and response):

```bash
printf 'Region: %s\nModel: %s\n' "$AWS_REGION" "$ANTHROPIC_MODEL"
claude "Reply with the word ready."
```

For the current staging configuration, the model should be
`us.anthropic.claude-sonnet-5` without manually setting `ANTHROPIC_MODEL`.
`claude --version` alone does not exercise inference. If invocation fails,
compare the profile with `claude_default_model` and the explicit profile-to-
foundation-model mapping in `deploy/regional/main.tf`. From **outside the
task**, using an operator identity with Bedrock control-plane permissions,
check the *foundation* model ID in the same account and Region:

```bash
aws bedrock get-foundation-model-availability \
  --region us-east-1 --model-id anthropic.claude-sonnet-5 \
  --query '{agreement:agreementAvailability.status,authorization:authorizationStatus,entitlement:entitlementAvailability,region:regionAvailability}'
```

The task role is not granted this availability-check API or AWS Marketplace
subscription permissions. For Anthropic models, first-time-use setup must
also be complete. An unlisted model may fail because it is not enabled, but
the agreement manifest is **not** an IAM allowlist: a model enabled elsewhere
in the account may work, and AWS documents that a first invocation can
temporarily succeed while subscription is attempted. Record the actual
availability and invocation results rather than treating a single 403 or
successful call as proof of model-allowlist enforcement. See the
[model-agreement guide](../configuration/bedrock-model-agreements.md) and
the [regional troubleshooting notes](../../deploy/regional/README.md#bedrock-access-denied).

Ordinary files in `/home/sre` persist to EFS across task restarts for the same
investigation. OCM state under `.config/ocm` and kubeconfig state under `.kube`
are task-scoped, excluded from S3 sync, and destroyed when the task stops.

### Configure or clear OCM on an existing task

```bash
# Uses a fresh OCM token; auth-code is the default unless device mode is selected
./bin/rosa-boundary --profile <profile-name> session credentials configure ocm <session-id> --ocm-url production

# Explicit OCM-only headless override (also works with browser-mode Boundary)
./bin/rosa-boundary --profile <profile-name> session credentials configure ocm <session-id> \
  --ocm-url staging \
  --auth-flow device

# Immediate removal; also removes credential-derived ~/.kube/config
./bin/rosa-boundary --profile <profile-name> session credentials clear ocm <session-id>
```

If `--ocm-url` is omitted, only the non-secret `url` field is read from the
workstation's `${XDG_CONFIG_HOME:-$HOME/.config}/ocm/ocm.json`. No local token
is reused or copied. Re-running configure atomically replaces an expired token.
Stopping the task remains authoritative cleanup even if clear is not run.
An explicitly supplied `--auth-flow auth-code|device` overrides only the OCM
flow, not Boundary's; otherwise the saved/global device preference selects
the OCM flow. Each OCM credential injection gets a new OCM access token and
can request human approval even if Boundary is cached. In JSON mode,
`session credentials configure ocm <session-id> -o json` still shows OCM (and,
if needed, Boundary) human approval guidance on stderr; on success it returns
one JSON object with `action: configured`, `session_id`, and `environment`.
`session credentials clear ocm ... -o json` returns `action: cleared` and
`session_id` on success. Without an ID, either operation returns a
`selection_required` result containing `eligible_count` and
`credentials_changed: false`, with a suggestion only for exactly one owned
RUNNING session. Check exit status before assuming credentials changed.

To exercise workspace persistence and audit without customer data, create a
harmless file such as `printf 'boundary smoke test\n' > ~/boundary-smoke-test.txt`
inside the task. Then `exit` the interactive shell. This **disconnects ECS Exec**;
the task stays running until stopped or reaped and no S3 sync is implied.

## Phase 5: Close Session (Stops Task; Triggers S3 Sync)

```bash
./bin/rosa-boundary --profile <profile-name> session close <session-id> --wait
```

What it does:
1. Sends SIGTERM to the ECS task
2. Container entrypoint attempts to sync non-credential `/home/sre/` content to S3
3. S3 path is auto-generated: `s3://<bucket>/<cluster-id>/<investigation-id>/<YYYYMMDD>/<task-id>/`

`--wait` confirms the task reached STOPPED, **not** that S3 sync succeeded.
Closing the session does not close its investigation or delete the reusable workspace.
Without a terminal, `session close` requires `--yes`; `-o json` returns a
single status document on stdout and human-readable authentication guidance on stderr.
A failed upload or report write produces a nonzero shutdown result. A killed
process might produce no report at all. Neither status zero nor a nonempty
prefix is proof that all eligible bytes reached S3.

## Verify Audit Evidence

Use an **operator/audit-reader AWS identity** with CloudWatch Logs and S3 read
permissions in the correct account and region. The Boundary SRE role and the task
role do not provide general audit-read access.

**For detailed audit log retrieval instructions**, including how to add yourself to
the audit reader role and retrieve S3 artifacts, see the
[**Audit Log Access**](audit-log-access.md) runbook.

If you already have audit reader access, obtain the deployed log group names and
audit bucket from the operator (or regional Terraform outputs); do not guess them
from a CLI task ID. In the following examples, supply the actual values:

```bash
aws logs describe-log-streams \
  --log-group-name '<ssm-session-log-group>' \
  --order-by LastEventTime --descending --region '<region>'
aws logs get-log-events \
  --log-group-name '<ssm-session-log-group>' \
  --log-stream-name '<stream-name-from-describe-log-streams>' --region '<region>'

# Inspect container output for audit-sync warnings (select its actual stream first).
aws logs describe-log-streams \
  --log-group-name '<container-log-group>' \
  --order-by LastEventTime --descending --region '<region>'

aws s3 ls 's3://<audit-bucket>/<cluster-id>/<investigation-id>/<YYYYMMDD>/<task-id>/' \
  --recursive --region '<region>'
```

Use the container stream for the **specified task**, not just the latest stream.
Find its `audit_sync` start and terminal events and record the investigation,
task, attempt UUID and exact destination (an explicit escrow base can differ
from the generated base above). Under `attempts/<uuid>/`, `workspace/` holds
data and `report.json` records the transfer. A matching `transfer_rc: 0` means
the CLI reported success, **not** that a concurrent writer was quiescent. A
failed or missing report leaves that task attempt unverified, even if every
expected object appears to exist. Never substitute a previous task's report.

Compare the exact set of relative keys, lengths and SHA-256 digests with an
independent manifest from the agreed write cut-off. Exclude credential mounts
(`.config/ocm/`, `.kube/`) and do not traverse symlinks. Verify the downloaded
bytes, not multipart ETags. Keep version IDs with the verified manifest in
restricted audit storage; do not attach paths, file contents or raw transcripts
to tickets. A mutable workspace without an independent cut-off cannot establish
what a historical session contained.

For a task attempt, `scripts/verify_workspace.py` performs this comparison with
read-only S3 calls. Prepare a private UTF-8 JSON array from the independent
cut-off manifest; each entry has `key` (eligible relative path), `length`
(bytes), and `sha256` (lowercase hex). Use the audit-reader identity and a
private directory outside the sync tree. Supply the exact `workspace/` URI
from the task's attempt (including its trailing slash):

```bash
uv run --group localstack python scripts/verify_workspace.py \
  --workspace-uri "$WORKSPACE_URI" --manifest "$PRIVATE_DIR/cutoff.json" \
  --evidence "$PRIVATE_DIR/$ATTEMPT-comparison.json"
```

The dependency group supplies boto3, not a LocalStack endpoint. A successful
comparison pins object versions in manifest order. Keep both evidence and
manifest; this command does not authorize deletion or verify a shared reaper
backup prefix.

**If verification fails: retention only.** Keep the AP and EFS data. Before the
configured reaper grace expires, have the operator [place a retention hold](#retention-hold). Use an authorized recovery
session on the retained investigation, or have the operator make a separate
read-only recovery copy under a new destination while writers are quiescent.
Verify the *whole* recovery copy, not just the missing keys. A successful
recovery does not change the original attempt's result. The scheduled reaper's
`reaper-final-backup/` is a separate recovery destination, not task evidence.
If necessary bytes are gone or recovery cannot be verified, do not authorize
close: assign an incident owner and an escalation deadline.

### Authorize close after verification (deployment operator)

This procedure needs a separate privileged operator; do not give the task or
shared SRE role permission to issue receipts or tag access points. Deploy the
updated create/reaper Lambdas, IAM and CLI together before using it. On old
images there may be no task reports; recover and verify independently instead.

1. Identify the exact regional audit bucket, filesystem and AP. Inventory all
   APs that can reach **any part** of the investigation tree, including a
   root (`/`) reaper AP. Check the effective filesystem and IAM policies and
   identify the clients using those mounts; an AP named for the reaper is not
   proof that only the reaper can use it. Coordinate a maintenance window
   with those clients' owners: stop new launches, drain in-flight create/reaper
   invocations and stop all tasks, including pending and stopping ones. A
   disconnected shell, an empty recent ECS listing, or an AP tag by itself
   is **not a write barrier**. Do not proceed with alternate writers or unknown
   unresolved sessions. Keep the workspace quiescent until close completes.
2. Tag the AP with `AuditCloseSeal=<fresh lowercase UUIDv4>` and
   `AuditCloseBucket=<regional audit bucket>`. A sealed workspace is not
   available for regular session creation; sealing does not revoke an existing
   mount. Never reuse a seal. Before resuming work, remove `AuditCloseVerified`
   first, then the seal; verification must start over with a new UUID.
3. Recheck quiescence. Reconcile all required task transfers or verified recovery
   with the independent manifest. Preserve the immutable manifest/version
   references in access-controlled audit storage. **Only after verification**,
   issue a small JSON receipt to the regional audit bucket at
   `_boundary-close/<access-point-id>/<seal>.json` (create only, e.g. S3
   PutObject with `If-None-Match: *`). Example shape, not evidence:

   ```json
   {"schema_version":1,"cluster_id":"<cluster>","investigation_id":"<investigation>","access_point_id":"<fsap-id>","seal":"<uuid>","status":"verified","manifest_ref":"<immutable verification evidence reference>"}
   ```

4. Read back the receipt and confirm the manifest reference and exact AP/seal.
   Last, set `AuditCloseVerified=<same seal>` on this AP. This authorizes
   deletion; never set it on a failed, stale or unreadable receipt. The CLI
   reads the operator receipt, not the task's self-report, and performs no
   backup of its own. An unreadable receipt or mismatched tags block close.

### Retention hold

For a new hold, the deployment operator sets a fresh `AuditCloseSeal` on the
exact AP without setting `AuditCloseVerified` or issuing a receipt.

If verification was granted prematurely, remove **only `AuditCloseVerified`**
from the affected AP immediately. Leave the seal in place as a retention hold.
Read the tags back and confirm `investigation close --dry-run` reports that
finalization is blocked. Preserve the original receipt and its version for
incident review; do not reauthorize its seal.

For every hold, assign an operator and record a review deadline. A hold prevents routine cleanup, not writes
through an existing mount.

## Phase 6: Close Investigation

```bash
./bin/rosa-boundary --profile <profile-name> investigation close \
  <cluster-id> <investigation-id> --dry-run
# After checking the complete plan and audit evidence, confirm in a terminal:
./bin/rosa-boundary --profile <profile-name> investigation close \
  <cluster-id> <investigation-id>
```

What it does:
1. Verifies that the authenticated creator's OIDC subject matches the access point's `oidc_sub` tag and that the access point is Lambda-managed; missing owner tags fail closed. Another SRE can join an authorized shared investigation but cannot close it through the CLI.
2. Resolves and previews the complete plan (account, region, cluster, filesystem, access point, active session IDs, and matching task definitions) **before** any mutation. `--dry-run` is read-only. A noninteractive close needs `--yes` unless dry-running.
3. Refuses active, pending, or still-shutting-down sessions without `--force`. With `--force`, plans stops for active sessions and waits for those already stopping to reach STOPPED before deregistering definitions or deleting the access point. The CLI rechecks the plan before mutation; changes require a new preview. Treat partial failures as incomplete and check the reported remaining actions.
4. Requires a verified operator seal and matching S3 receipt before deregistration or AP deletion. A forced stop is not authorization: rerun after verification. Deleting the access point does not erase the EFS directory.

Both positional IDs are required. Ensure the selected profile has the correct
`efs_filesystem_id` and ECS cluster. CLI owner validation does **not** constrain
direct AWS clients using the SRE role; IAM ownership and atomic exclusion of
concurrent starts/closes remain separate infrastructure work.

## Complete Example

```bash
# After configuring the intended deployment, choose an approved target and profile.
PROFILE="<saved-profile-name>"
CLUSTER_ID="<approved-cluster-id>"
INV_ID="<unique-investigation-id>"

# 1. Authenticate
./bin/rosa-boundary --profile "$PROFILE" login

# 2. Start an investigation session (save SESSION_ID from output)
./bin/rosa-boundary --profile "$PROFILE" session create "$CLUSTER_ID" \
  --investigation-id "$INV_ID" --no-connect

SESSION_ID="<session ID from output>"

# 3. Connect
./bin/rosa-boundary --profile "$PROFILE" session join "$SESSION_ID"

# Inside the task: printf 'boundary smoke test\n' > ~/boundary-smoke-test.txt
# Then exit the interactive shell (task remains running).

# 4. Stop task
./bin/rosa-boundary --profile "$PROFILE" session close "$SESSION_ID" --wait

# 5. Verify CloudWatch and S3 audit evidence using an audit-reader identity
# (see "Verify Audit Evidence" above).

# 6. Review the read-only close plan, then confirm closure in a terminal
./bin/rosa-boundary --profile "$PROFILE" investigation close "$CLUSTER_ID" "$INV_ID" --dry-run
./bin/rosa-boundary --profile "$PROFILE" investigation close "$CLUSTER_ID" "$INV_ID"
```

## Authorization Model

The deployment's shared SRE role is scoped at runtime by ABAC:

- Lambda tags tasks with the configured ABAC tag key and identity value
- STS derives principal session tags from the OIDC token's `https://aws.amazon.com/tags` claim; the IAM role trust permits `sts:TagSession`
- The role policy compares `ecs:ResourceTag/<configured-key>` with `aws:PrincipalTag/<configured-key>` for ECS Exec
- Cross-user task access is prevented at IAM policy level without per-user roles

For log retrieval use [Verify Audit Evidence](#verify-audit-evidence), not the task's AWS identity.

## Troubleshooting

### Token cache stale
```bash
./bin/rosa-boundary login --force
```

On a headless host, confirm `oidc_use_device_code: true` is a YAML boolean
or pass `--use-device-code` to the command. `--use-device-code=false` selects
browser flow for both providers even if saved true; an explicit OCM
`--ocm-auth-flow auth-code` / `--auth-flow auth-code` selects a browser callback
for OCM only. If a device request expires, is denied, or is canceled, verify
the SRE approved the **correct provider's** URL and code and start a new,
bounded attempt; do not expect a browser fallback. Human-readable approval
guidance and other diagnostics appear on stderr even in JSON mode; stdout
result JSON is separate. Completing authentication is not evidence of STS
success, task creation, credential transfer, or audit sync; check exit status
and the steps below.

### AccessDeniedException on session join
- Possible cause: task and OIDC-derived principal tags do not match for the deployment's ABAC key. Ask an operator with ECS read access to inspect the task tags and check the identity provider mapping and IAM policy.

### Lambda returns 403 Forbidden
- Possible cause: missing configured group or ABAC claim. An STS role-trust denial occurs *before* Lambda and needs different troubleshooting. Confirm the failing stage and ask the operator about the deployment's trust and group settings.

### session-manager-plugin: connection drops immediately
- Cause: Container exec agent hasn't opened its WebSocket yet
- The CLI waits for the agent; if it still fails, check whether ECS Exec is enabled on the task

## Related

- [Troubleshooting](troubleshooting.md)
- [User Access Guide](user-access-guide.md)
- [AWS IAM Policies](../configuration/aws-iam-policies.md)

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
    TaskStopped --> CloseRequested: rosa-boundary investigation close
    CloseRequested --> InvestigationClosed: reaper verifies backup and completes cleanup
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
        - Any authorized Boundary SRE may request close after all shells detach
        - --force permits stopping tasks, not bypassing shell checks or audit verification
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

### Measure session startup

For an approved dev baseline, run `rosa-boundary --verbose session create <cluster-id> --with-credentials none --no-connect -o json` without `--no-wait`. Save `task_arn` and `startup_timings`, then close the session and investigation as usual. In verbose mode, the CLI reports:

- `lambda_round_trip_ms`: client-observed time for the create Lambda call, including network and SDK overhead. This is not the Lambda runtime duration.
- `invoke_to_running_ms`: from the start of that call until the CLI observes ECS `RUNNING`. It includes role assumption and polling delay, but not initial Boundary login, OCM injection, or ECS Exec readiness. It overlaps the ECS intervals; do not add them together.
- `ecs`: ECS `created_at`, `pull_started_at`, `pull_stopped_at`, and `started_at`, when present. The derived `ecs_created_to_pull_ms` includes provisioning such as ENI setup but does not isolate ENI time; `ecs_image_pull_ms` measures the pull; `ecs_after_image_pull_ms` covers the rest of startup. A missing or reversed timestamp pair produces no duration, not zero.

In verbose mode, `--no-wait` reports only the Lambda round trip. Startup timings also appear on stderr as debug messages before credential injection or interactive connection. Without `--verbose`, timings are absent from both stderr and JSON.

For the server-side duration, use the authorized operator/audit-reader identity in the same region. In CloudWatch Logs Insights, select `/aws/lambda/<create-investigation-function>` and a narrow launch window. Find the invocation that logged the exact task ARN, returning only `@requestId` and `@logStream` (not the log message). Then filter that stream to the same request ID and `@type = "REPORT"`, and select `@duration` and, when present, `@initDuration` (milliseconds). Keep cold-start initialization separate from runtime duration; don't substitute a function-wide metric for this invocation. If correlation is unavailable, record the runtime duration as unknown.

Before deciding between SOCI and image slimming, repeat on fresh tasks and record the actual container `imageDigest` (from `DescribeTasks`), task architecture/platform version, and cold-start status alongside the phase times. If pull time consistently dominates, compare candidate images or SOCI against the same baseline. For SOCI, also measure time to a usable ECS Exec shell and first representative tool invocation: lazy loading can shift I/O past `RUNNING` rather than remove it. Recheck the existing image/tool acceptance gates before adopting either approach.

### Timeouts and handover

The CLI defaults `--session-timeout` to **1h** and sends it explicitly; Terraform's
**8h** default applies only when the Lambda request omits the value. CLI accepts
`0s`, but the deployed default minimum of 30 seconds rejects it. Global
`--timeout` is a separate local command deadline, and explicit `--timeout 0s`
is invalid. Read the [timeout matrix](../architecture/session-lifecycle.md#timeout-matrix)
before selecting a value. A deadline is not a guaranteed stop time:
[strict-deadline policy remains unresolved](../architecture/session-lifecycle.md#unresolved-policy-decisions).

To hand over a workspace, coordinate with its current SRE and have them disconnect
Exec. The successor uses their own profile/identity to request a replacement:

```bash
./bin/rosa-boundary --profile <successor-profile> session create <cluster-id> \
  --investigation-id <existing-investigation-id>
```

Lambda stops and replaces existing tasks only when every candidate has a known
different owner and no active SSM sessions. An active session returns HTTP 409;
unknown ownership or session state blocks replacement. Lambda waits for tasks to
stop before launching the replacement. Verify predecessor audit evidence
independently. The new task belongs to the caller, but the access point keeps its
original creator tags and creation time.

If you already have a task, repeat create returns HTTP 409 and leaves it unchanged.
When the task matches your current ABAC identity, the CLI prints a copy-pasteable
[`session join`](#phase-4-connect-to-container) command with the existing session ID
and the current profile, region, and ECS cluster. If no command is shown, use
[`session list`](#phase-3-list-tasks) to find the task; joining still requires matching
ABAC identity. Credential mounts do not persist across replacement: configure fresh
OCM credentials on the new task. See [actual task/AP tags](../architecture/session-lifecycle.md#actual-resource-tags-creator-versus-actor).

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

An ECS Exec agent can report `RUNNING` before Session Manager can connect. The
CLI retries AWS `TargetNotConnectedException` for up to 15 seconds before
reporting the failure. It does not retry authorization errors or requests whose
outcome is unknown.

Plain join leaves existing credentials alone. To explicitly authorize and replace
them, then renew during the attachment to the default shell:

```bash
./bin/rosa-boundary --profile <profile-name> session join <session-id> \
  --renew-ocm --ocm-url staging --ocm-auth-flow device
```

Renewal requires a renewal-capable task image, a known expiry, and an online
refresh grant from OCM. Older task images with the original OCM helper
automatically get one-shot configuration. Use `session create --no-ocm-renewal`
to explicitly configure once. See the
[CLI authentication guide](../architecture/cli-authentication.md) for option
precedence. Scheduling and successful renewals are silent unless you pass
`--verbose`. If renewal stops, the shell remains open and the CLI prints a
profile-qualified manual configure command on stderr. Disconnect cancels the
local worker without clearing credentials or stopping the task. Manual clear
or configure prevents the old worker from replacing those credentials again.

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
recovery does not change the original attempt's result. The close service's
own copy under `_boundary-close/evidence/<access-point-id>/attempts/<attempt>/workspace/`
is a separate recovery destination, not task evidence. (Deployments that ran
earlier revisions also have a historical `reaper-final-backup/` prefix, which
is no longer written and cannot show which attempt produced it.)
If necessary bytes are gone or recovery cannot be verified, do not authorize
close: assign an incident owner and an escalation deadline.

### Authorize close (automated)

Close is requested by an authenticated SRE and performed by the investigation
reaper. There is no separate privileged operator step and no manual receipt
handoff: the request handler cannot write evidence, and the reaper will not
accept an SRE's word for a backup it did not verify itself.

Who may ask:

| Observed state | Who may request close |
| --- | --- |
| Any shell attached | Nobody, including the attached SRE. Disconnect all shells and retry. |
| Shell observed after acceptance | The accepted explicit request waits. A handover to another active SRE supersedes session-bound callbacks and intents. |
| No active sessions | any authenticated SRE authorized to use Boundary |
| Unclear or unavailable | No new request is recorded; retry when the service can confirm no shells are attached. The reaper defers an already accepted request. |

After rechecking that no shell is attached, the reaper will apply a managed close marker, stop only
the tasks the request consented to stop, observe the workspace quiet twice with
a configured interval between, measure every eligible file itself, copy into an
attempt prefix of its own, compare that copy against its own measurements
including S3 object versions, re-check the source and the task list, and only
then deregister task definitions, delete the access point and publish a
receipt. Any late task, read error, changed byte or ambiguous answer retains
the data; the status says whether the reaper will start a fresh attempt by
itself or whether the outcome needs a person.

Read a `schema_version: 2` receipt as what it says it is:

```json
{"schema_version":2,"assurance":"observed-quiescence","status":"verified","seal":"<uuid>","request_token":"<uuid>","attempt_id":"<uuid>","manifest_ref":"s3://<bucket>/_boundary-close/evidence/<fsap-id>/attempts/<attempt>/source-manifest.json","verification_ref":"s3://<bucket>/_boundary-close/evidence/<fsap-id>/attempts/<attempt>/verification.json","directory_retained":true}
```

It attests that the copy matched the recorded source observations. It does not
attest that no later write is possible: sealing is best effort, and a launch
that already passed its marker check can still appear. The legacy
`schema_version: 1` operator receipt and its separate `AuditCloseVerified` tag
are still accepted unchanged; the reaper deliberately does not set that tag
alongside v2 evidence, so an older CLI refuses a v2 close instead of mistaking
it for the stronger guarantee.

### Retention hold

To hold an investigation, set a fresh `AuditCloseSeal` on the exact access
point **without** `AuditCloseManagedBy`. The reaper treats a seal it did not
apply as a manual hold: it never replaces it, never deletes behind it, and
reports the workspace as retained for review. IAM enforces the same thing —
the reaper's grants refuse to overwrite an existing seal of any kind and
refuse to delete an access point carrying an unmanaged seal.

To release a hold, remove the seal. For every hold, assign an owner and record
a review deadline. A hold prevents routine cleanup, not writes through an
existing mount.

If a close is in flight and must be stopped, removing nothing is usually
correct: the reaper retains data on any ambiguity, and `--status` shows the
current disposition.

## Phase 6: Close Investigation

```bash
./bin/rosa-boundary --profile <profile-name> investigation close \
  <cluster-id> <investigation-id> --dry-run
# After checking the complete plan and audit evidence, confirm in a terminal:
./bin/rosa-boundary --profile <profile-name> investigation close \
  <cluster-id> <investigation-id> --wait
```

What it does:

1. Resolves and previews the complete plan (account, region, cluster,
   filesystem, access point, visible session IDs, matching task definitions and
   any close seal) **before** anything is requested. `--dry-run` is read-only.
   A noninteractive close needs `--yes`.
2. Submits an authenticated close request and prints its token. The close
   service decides eligibility: the CLI cannot observe attached sessions and
   does not pretend to. The access point's creator tag is provenance, not
   permission.
3. If any ECS Exec shell is attached (including yours), the service refuses the request with 409. Disconnect all shells and retry. A running task alone does not block acceptance. If a shell appears after acceptance, the reaper waits for detachment without a new request. Without `--force` it also waits for tasks to stop; `--force` consents to stopping tasks, not bypassing the shell check or backup verification.
4. With `--wait`, polls until the service reports an outcome it will not leave
   by itself, bounded in wall-clock time. Stopping the wait does not cancel the
   request. A `retained` or `cleanup_incomplete` result is reported as a
   failure, the data is kept, and the message says whether the reaper will
   retry it.

Status values are deliberately distinguishable — `accepted`,
`waiting_for_tasks`, `verifying`, `retained`, `cleanup_incomplete`,
`completed`. **Accepted is not closed.** Status stays answerable after the
access point is deleted: use `investigation close <cluster-id> <investigation-id> --status` (optionally `-o json`). This lookup never submits a request.

The EFS directory is retained on a normal close. Only the stale sweep may
reclaim a directory, behind the same verified gate. Do not recreate a closed
investigation over a retained directory; choose a distinct investigation ID.

### Close when the session ends

After a normal interactive exit, `session create` and `session join` offer to
request close. The default is to leave the investigation open, and there is no
prompt for JSON output, a failed attachment, a timeout or a lost connection.

```bash
# Ask once, when the shell exits (default is "no")
./bin/rosa-boundary --profile "$PROFILE" session join "$SESSION_ID"

# Decide up front: request close on a normal disconnect, no prompt
./bin/rosa-boundary --profile "$PROFILE" session join "$SESSION_ID" --auto-close

# Also consent to stopping the investigation's other tasks
./bin/rosa-boundary --profile "$PROFILE" session create "$CLUSTER_ID" \
  --auto-close --auto-close-stop-all
```

`--auto-close` records its intent before attaching, so a crashed CLI still
leaves it recorded; if the intent cannot be recorded, the command fails instead
of attaching without it, and if the session then fails to attach the intent is
withdrawn. There is no heartbeat: a laptop that disappears while
its task keeps running is not detected immediately. The reaper activates the
intent only after that task stops and no shell is attached. Unless `--auto-close-stop-all` was set, other tasks must also stop. Intent alone does not block joins. A handover to another active SRE
supersedes it rather than closing the new holder's session.

Both positional IDs are required for `investigation close`. Ensure the selected
profile has the correct `efs_filesystem_id`, ECS cluster, `invoker_role_arn`
and `lambda_function_name`. See
[Automated investigation close](../architecture/investigation-close.md) for the
full contract, including what the receipt does not prove.

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

# 6. Review the read-only close plan, then request closure in a terminal.
# --wait follows the close service until its status is terminal; the EFS
# directory is retained either way.
./bin/rosa-boundary --profile "$PROFILE" investigation close "$CLUSTER_ID" "$INV_ID" --dry-run
./bin/rosa-boundary --profile "$PROFILE" investigation close "$CLUSTER_ID" "$INV_ID" --wait
```

## Authorization Model

The deployment's shared SRE role is scoped at runtime by ABAC:

- Lambda tags tasks with the configured ABAC tag key and identity value
- STS derives principal session tags from the OIDC token's `https://aws.amazon.com/tags` claim; the IAM role trust permits `sts:TagSession`
- The role policy compares `ecs:ResourceTag/<configured-key>` with `aws:PrincipalTag/<configured-key>` for ECS Exec
- Cross-user task access is prevented at IAM policy level without per-user roles

Investigation close has its own authorization, enforced service-side rather
than by ABAC: any authorized Boundary SRE may explicitly request close,
but only after all shells detach. A task left running after its SRE detached does not keep the investigation
held — but stopping that task still needs the explicit consent of whoever
requests the close. Creating an investigation confers no standing authority
over it. See
[Automated investigation close](../architecture/investigation-close.md).

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

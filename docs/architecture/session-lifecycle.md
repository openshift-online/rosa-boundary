# Session lifecycle: implemented limits and identity

This reference describes current Boundary behavior, not a decision about future
lifetime or active-session policy. A Boundary **session ID is an ECS task ID**;
each ECS Exec connection has a separate SSM session. An investigation is the
reusable EFS workspace and can span replacement tasks. Use the
[investigation workflow](../runbooks/investigation-workflow.md) for commands and
[CLI authentication](cli-authentication.md) for identity setup.

## Timeout matrix

Defaults below are source defaults, not assertions about an existing deployment.
Check the owning workspace's configured values before an operational test.

| Layer / setting | Default and limits | Explicit zero / minimum behavior | What expires |
|---|---|---|---|
| CLI global `--timeout` | No default with a controlling terminal; 5m without one. Explicit duration must be positive. | Explicit `0s` and negative durations are errors; omitted zero is an internal sentinel, not a user opt-out. | Whole local invocation, including human approvals and Exec; cancellation does **not** stop the task. |
| CLI `session create --session-timeout` | `1h`; whole seconds in `0..24h`. CLI always sends `task_timeout`, even when the flag is omitted. | CLI accepts `0s`, but Lambda can reject it. CLI does not enforce the deployed minimum. | Requested task lifetime, not the local command or SSM connection. |
| Terraform `task_timeout_default` | `28800` seconds (8h); validation range `0..86400`. Passed as Lambda `TASK_TIMEOUT_DEFAULT`. | Zero is within Terraform's range, but still subject to Lambda minimum validation when used. | Fallback for a request **omitting** `task_timeout`; it does not override CLI's explicit 1h. |
| Terraform `task_timeout_minimum` | `30` seconds; validation range `0..86400`. Passed as `TASK_TIMEOUT_MINIMUM`. | `0` disables the lower-bound check, not the 24h upper bound. Terraform does not require default ≥ minimum. | Request validation only. |
| Create Lambda request validation | `int(task_timeout)` must be `0..86400` and at least the configured minimum when positive. If omitted, uses `TASK_TIMEOUT_DEFAULT` (fallback `3600` if environment unset); minimum fallback is `30`. | With minimum 30, zero and 1–29 are rejected (400). With minimum 0, zero and 1 are accepted. Accepted zero omits `deadline`; positive values set it to creation time + seconds. Omitted defaults undergo the same validation. | Computes a deadline tag; no in-container timer. |
| Task reaper Lambda / EventBridge | Schedule default 15m (`reaper_schedule_minutes`, range 1–1440). Checks RUNNING tasks with `now > deadline`. | Missing deadline is skipped. Active SSM sessions or uncertain session state defer reaping. | Eligible task is stopped on a later successful sweep, **not exactly at the deadline**. |
| Lambda execution budgets | Create function 300s; task reaper 120s in Terraform. | Not a task-lifetime opt-out or minimum. | One Lambda invocation; unrelated to the requested task lifetime. |
| ECS / CLI waits | CLI RUNNING/STOPPED waiters cap at 10m; handover's Lambda STOPPED waiter uses 6s × 25 attempts. | Not controlled by `--session-timeout`; the whole-command deadline can end a CLI wait earlier. | Waiting ends; this alone does not prove cleanup or audit completion. |
| SSM-backed ECS Exec connection | AWS documents a fixed **20-minute idle timeout** for ECS Exec. This repository does not configure an SSM maximum-session-duration preference. | Neither CLI `--session-timeout 0s` nor Terraform zero disables the AWS idle limit. There is no Boundary SSM minimum/zero setting. | Exec connection, not task or investigation. Do not equate an `Active` SSM record with recent human input. |

Source: [`cli.go`](../../internal/cmd/cli.go),
[`start_session.go`](../../internal/cmd/start_session.go),
[`variables.tf`](../../deploy/regional/variables.tf),
[`lambda-create-investigation.tf`](../../deploy/regional/lambda-create-investigation.tf),
[`create handler`](../../lambda/create-investigation/handler.py),
[`lambda-reap-tasks.tf`](../../deploy/regional/lambda-reap-tasks.tf),
[`reaper handler`](../../lambda/reap-tasks/handler.py), and
[AWS ECS Exec considerations](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html).
The SSM value is a service constraint, not a locally tested Terraform setting.

The entrypoint only displays `TASK_TIMEOUT`. Its separate S3 `SYNC_TIMEOUT`
defaults to 85s (valid override: 1–85 whole seconds). Allowing 3s for an
in-flight startup metadata request, a 105s shutdown watchdog and 2s kill grace
leaves 10s before the base container's 120s ECS `stopTimeout`. Neither task
STOPPED nor a successful CLI wait proves audit
escrow. See [audit verification](../runbooks/investigation-workflow.md#verify-audit-evidence).

### Unresolved policy decisions

- [ROSAENG-75948 — Resolve strict task deadlines versus active-session reaper exemption](https://redhat.atlassian.net/browse/ROSAENG-75948): strict-deadline policy remains unresolved. The scheduled, active-session-aware reaper described here is **not** a hard maximum task lifetime.
- [ROSAENG-75947 — Prevent same-user handover and define active-session takeover policy](https://redhat.atlassian.net/browse/ROSAENG-75947): takeover policy remains unresolved. Same-user recreation is currently possible; Lambda does not reject handover merely because the new caller also created the old task. Current checks are implementation observations, not a settled definition of activity, grace period, or authorization to interrupt an SRE.

Do not change deployment settings or infer a policy decision from this documentation.

## Actual resource tags: creator versus actor

These are Lambda-supplied tags, with exact case. They are not a promise that AWS
adds no service-managed tags (`enableECSManagedTags` is enabled for tasks).

| Resource | Tags written by create Lambda |
|---|---|
| ECS task | `oidc_sub`, the configured ABAC key (for example `uuid`), `investigation_id`, `cluster_id`, `access_point_id`, `task_timeout`, `created_at`; additionally `deadline` only when timeout > 0 |
| EFS access point | `Name` = `<cluster-id>-<investigation-id>`, `ClusterID`, `InvestigationID`, `oidc_sub`, `username`, `ManagedBy` = `rosa-boundary-lambda`, `CreatedAt` |

The task's `oidc_sub` and ABAC value identify the caller creating **that task**.
There is no additional unconditional task `username` tag: it appears when that
is the selected ABAC key. Access-point `username` and `oidc_sub` identify the
**original workspace creator**. Reuse does not retag the access point or reset
`CreatedAt`. Those tags are provenance and do **not** decide who may close: the
close service derives the current holder from the sessions attached to the
investigation's tasks, so the reaper can defer an explicit request from a different SRE
without interrupting the attached session. Handover supersedes session-bound callbacks. A task's own `oidc_sub` tag is provenance for
the same reason: a task still RUNNING after its SRE detached leaves the
investigation idle, not held. A successor's task can therefore
have a different subject from its access point. Investigation age-based cleanup
uses creation age, not time since handover or last activity. See
[automated investigation close](investigation-close.md).

Close adds its own access-point tags once finalization begins: `AuditCloseSeal`,
`AuditCloseManagedBy`, `AuditCloseRequest` and `AuditCloseBucket`. A seal
without `AuditCloseManagedBy` is a manual retention hold.

The creation metric's optional `ActorUUID` log property is extracted from the
validated caller token's `principal_tags.uuid` (a valid normalized UUID); it is
not an AP tag, not the original creator, not a request-body field, and not a
metric dimension. It can be absent. `session list` displays `OWNER` using task
`uuid`, falling back to `username`; this presentation is not a general resolver
for every configurable ABAC key.

See [`create handler`](../../lambda/create-investigation/handler.py), its
[tag, timeout, metric, and handover tests](../../lambda/create-investigation/test_handler.py),
and [`list_sessions.go`](../../internal/cmd/list_sessions.go). Service-side
close eligibility does not imply an equivalent direct-AWS IAM ownership
constraint.

## Handover is replacement, not joining another user's task

Run `session create <cluster-id> --investigation-id <existing-id>` to request a
replacement session in the same workspace; `session join <session-id>` connects
to a particular task subject to its ABAC identity. Handover does not grant a
successor access to the predecessor's task or credentials.

On task creation, Lambda finds RUNNING tasks by the deterministic `startedBy`
value, whether or not it found an existing access point. This includes same-user
recreation; there is no distinct-user requirement. Before stopping any, it describes them and checks Active SSM
sessions for containers with runtime IDs. An active session blocks replacement
with 409; missing task details and AWS lookup errors fail the handover. It then
stops the old tasks and waits for STOPPED before reusing the AP, registering a
new definition and launching the caller's task. Stop/wait failure aborts the
replacement, but already initiated stops are not rolled back. This preflight
is not an atomic lock against concurrent starts or new Exec connections; do not
claim it covers every unknown-state case (for example a missing runtime ID).

Coordinate with the preceding SRE, disconnect their Exec shell, and verify their
audit evidence before replacing their task. The workspace persists, but OCM and
kubeconfig credential mounts are task-scoped and must be configured afresh.
After handover the successor, not the original creator, is the SRE who may
close the investigation; when no sessions are active, any authorized Boundary
SRE may. An earlier holder's close request or auto-close intent is superseded
rather than inherited. [ROSAENG-75946](https://redhat.atlassian.net/browse/ROSAENG-75946)
tracks the separate IAM-level close-ownership work.

## Exec environment and AWS CLI

ECS Exec starts a separate process, not a child of `entrypoint.sh`. Arbitrary
entrypoint `export`s do **not** propagate into it. The base task definition sets
`AWS_REGION`, `CLAUDE_CODE_USE_BEDROCK` and model defaults; Lambda copies the base
environment and overrides investigation values such as `CLUSTER_ID`,
`INVESTIGATION_ID`, `S3_AUDIT_BUCKET` and `TASK_TIMEOUT` when it
registers the per-investigation definition. Image/task environment, shell startup
files and persisted configuration—not entrypoint exports—determine the Exec
shell's settings. The default CLI Exec command uses `runuser` to enter a login
shell as `sre`. Create a replacement task after changing task-definition defaults;
an existing task does not acquire them.

The image installs AWS CLI v2 at `/usr/local/aws-cli/v2/current/aws` and exposes
`/usr/local/bin/aws` through alternatives. Use `command -v aws`,
`readlink -f /usr/local/bin/aws`, and `aws --version` inside the task, not an
assumed `/usr/bin/aws` or `.../current/bin/aws` path. Workstation Boundary commands
use the Go AWS SDK and do not require AWS CLI; the separate audit-reader workflow
does. Sources: [`Containerfile`](../../Containerfile),
[`ecs.tf`](../../deploy/regional/ecs.tf), [`entrypoint.sh`](../../entrypoint.sh),
and [`image path verification`](../../build/verify_sre_tools.py).

## Network endpoints are deployment-specific

The repository's [`network root`](../../deploy/network/vpc.tf) provisions private
subnet NAT routing and an **S3 gateway endpoint**. The regional root provisions a
**Bedrock Runtime interface endpoint** with private DNS in
[`bedrock-endpoint.tf`](../../deploy/regional/bedrock-endpoint.tf). It does not
provision a blanket set of `ssmmessages`, `kms`, `logs`, `ecr.api`, `ecr.dkr` or
`ecs` interface endpoints. Do not claim that tasks need no internet egress or
that an Exec connection proves use of a private SSM endpoint. Supplied VPCs may
have additional endpoints; inspect the actual routes, DNS and endpoint policies.
Exec needs reachable service endpoints (including `ssmmessages`); identity,
image pulls, tool downloads and target APIs have their own connectivity needs.
A deployment without NAT needs an explicitly verified endpoint/egress design,
not an assumption based on this source inventory.

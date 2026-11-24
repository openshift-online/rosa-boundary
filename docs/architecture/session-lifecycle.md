# Session and investigation lifecycle

A **session** is an ECS task, identified by its task ID or ARN. A **shell** is
the interactive SSM connection that `session join` opens through ECS Exec.
Exiting the shell does not stop the session. An **investigation** is the
persistent EFS workspace and its access point, identified by cluster and
investigation ID. Any Boundary-authorized user can create one; a cluster can
have several investigations. Choose the investigation ID when sharing a workspace.

## States and admission

| Resource | State | Meaning |
|---|---|---|
| Session | ACTIVE | Not stopped, and either a shell is attached or the configured session timeout has not elapsed since launch. |
| Session | IDLE | No shell is attached and task age has reached the configured timeout. Any Boundary-authorized user may close an idle session; only its creator may Join. |
| Session | CLOSED | ECS has stopped the task. This is not proof of a successful backup. |
| Investigation | IDLE | Newly created, or no linked shell remains attached. A running, shell-less task can still write to the workspace. |
| Investigation | ACTIVE | At least one linked shell is attached. Last-shell detach returns an open investigation to IDLE. |
| Investigation | PENDING_CLOSURE | Admission is closed and the reaper has confirmed no shells are attached. Late activity delays finalization; it does not reopen the investigation. |
| Investigation | CLOSED | All associated tasks stopped and backup coverage of the final workspace was independently verified before cleanup. |

These are lifecycle states, not ECS status strings. For example, ten minutes
after launching a one-hour task without a shell, the **session is ACTIVE** but
the **investigation is IDLE**. Unknown shell state is not evidence of IDLE.

An authorized user's accepted close request, eight hours of investigation idle
time, or expiry makes an investigation eligible for closure. Expiry is measured
from creation (`investigation_grace_period_hours`, default 168 hours / 7 days).
**At expiry or once closure intent is recorded, neither Create nor Join may
admit a new session or shell**, even while an earlier shell is still attached.
Expiry alone does not disconnect that shell. The later finalization seal is
not the admission cutoff. Requests already in flight can race these checks;
recheck for late activity before finalizing. Neither handover nor admission
is an atomic lock.

### How investigation idle time is estimated

The idle window starts at creation if no session has run, otherwise at the
last shell detach. Boundary does not reliably observe that instant: it uses
launch time plus the configured task timeout as a proxy. The reaper uses
launch-specific task definition registration (just before launch) as its durable
timestamp because ECS does not keep stopped tasks indefinitely; it does not
start the clock earlier than workspace creation. For a task with a zero timeout
(no configurable deadline), the estimate uses eight hours from registration.
For example, a session launched at 09:00 with a one-hour timeout gives an
estimated idle start of 10:00 and an idle-closure threshold of 18:00, not a
scheduled deletion at 18:00. The estimate can be early if a shell stays
attached past the timeout, or late if it disconnects promptly. It is not a
record of human inactivity and cannot substitute for checking shell state.

Once admission is closed, wait for confirmed shell drain before entering
PENDING_CLOSURE. If observations fail, retry without reopening admission.
Every task must stop. A last-task backup suffices only with independent proof
that it covers the final workspace; a successful stop, sync message or S3
object listing is insufficient. Without that proof (including when no task
ever ran), verify a final EFS backup. On late activity, incomplete evidence
or verification failure, retain the workspace and retry; never revert pending
closure to ACTIVE or IDLE. See [automated investigation close](investigation-close.md)
for the verification procedure and [the runbook](../runbooks/investigation-workflow.md)
for operator commands.

## Timeout matrix

Defaults below are source defaults, not assertions about an existing deployment.
Check the owning workspace's configured values before an operational test.

| Layer / setting | Default and limits | Explicit zero / minimum behavior | What expires |
|---|---|---|---|
| CLI global `--timeout` | No default with a controlling terminal; 5m without one. Explicit duration must be positive. | Explicit `0s` and negative durations are errors; omitted zero is an internal sentinel, not a user opt-out. | Whole local invocation, including human approvals and Exec; cancellation does **not** stop the task. |
| CLI `session create --session-timeout` | `1h`; whole seconds in `0..8h`. CLI always sends `task_timeout`, even when the flag is omitted. | CLI accepts `0s`, but Lambda can reject it. CLI does not enforce the deployed minimum. | Shell-less task age threshold, not the local command or SSM connection. |
| Terraform `task_timeout_default` | `28800` seconds (8h); validation range `0..28800`. Passed as Lambda `TASK_TIMEOUT_DEFAULT`. | Zero is within Terraform's range, but still subject to Lambda minimum validation when used. | Fallback for a request **omitting** `task_timeout`; it does not override CLI's explicit 1h. |
| Terraform `task_timeout_minimum` | `30` seconds; validation range `0..28800`. Passed as `TASK_TIMEOUT_MINIMUM`. | `0` disables the lower-bound check, not the 8h upper bound. Terraform does not require default ≥ minimum. | Request validation only. |
| Create Lambda request validation | `int(task_timeout)` must be `0..28800` and at least the configured minimum when positive. If omitted, uses `TASK_TIMEOUT_DEFAULT` (fallback `3600` if environment unset); minimum fallback is `30`. | With minimum 30, zero and 1–29 are rejected (400). With minimum 0, zero and 1 are accepted. Accepted zero disables the configurable timer, not the independent 8h age limit, and omits `deadline`; positive values set it to creation time + seconds. Omitted defaults undergo the same validation. | Computes a deadline tag; no in-container timer. |
| Task reaper Lambda / EventBridge | Schedule default 15m (`reaper_schedule_minutes`, range 1–1440). At the configured threshold, require confirmed shell absence. | Independently, at 8h of task age even an attached shell does not exempt the task. | Eligible task is stopped on a later successful sweep, **not exactly at the deadline**. |
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

## Actual resource tags: creator versus actor

These are Lambda-supplied tags, with exact case. They are not a promise that AWS
adds no service-managed tags (`enableECSManagedTags` is enabled for tasks).

| Resource | Tags written by create Lambda |
|---|---|
| ECS task | `BoundaryResource=session`, `oidc_sub`, the configured ABAC key (for example `uuid`), `investigation_id`, `cluster_id`, `access_point_id`, `task_timeout`, `created_at`; additionally `deadline` only when timeout > 0 |
| EFS access point | `BoundaryResource=investigation`, `Name` = `<cluster-id>-<investigation-id>`, `ClusterID`, `InvestigationID`, `oidc_sub`, `username`, `ManagedBy` = `rosa-boundary-lambda`, `CreatedAt` |

The task's `oidc_sub` and ABAC value identify the caller creating **that task**.
There is no additional unconditional task `username` tag: it appears when that
is the selected ABAC key. Access-point `username` and `oidc_sub` identify the
**original workspace creator**. Reuse does not retag the access point or reset
`CreatedAt`. Those tags are provenance and do **not** decide who may close: the
close service rejects a new request if any shell is attached, including the requester's own. If the reaper observes a shell after acceptance, the request waits; stop consent does not override this check. Handover supersedes session-bound callbacks. A task's own `oidc_sub` tag is provenance for
the same reason: a task still RUNNING after its SRE detached leaves the
investigation idle, not held. A successor's task can therefore
have a different subject from its access point. Expiry and estimated idle duration are separate clocks. See
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

On task creation, Lambda finds existing tasks by the deterministic `startedBy`
value (ECS desired status RUNNING), whether or not it found an access point.
The [ROSAENG-75947 policy](https://redhat.atlassian.net/browse/ROSAENG-75947?focusedCommentId=19713772)
applies before any stop:

| Existing candidate | Create response |
| --- | --- |
| Caller's task (matching configured ABAC tag or OIDC subject) | **409** regardless of shell state; leave the task unchanged. The CLI prints an exact `rosa-boundary session join` command only when both the ABAC identity and creator subject match. A partial match blocks replacement without suggesting Join. |
| Different owner with any active SSM session | **409**; no takeover. Coordinate with the current SRE and retry after they disconnect. |
| Unknown owner or session state | **500**; no takeover. Missing task details, owner tags, runtime IDs, incomplete SSM results, and AWS lookup errors are not evidence that a task is idle. |
| Every candidate has a known different owner and all checked targets are inactive | Stop the candidates, wait for STOPPED, then launch the caller's task in the same workspace. |

The task's configured ABAC tag and `oidc_sub` identify the previous caller;
the EFS access point's creator tags do not. The preflight checks every
candidate before any stop. Stop/wait failure aborts replacement without
rolling back stops already issued. This is not an atomic lock against concurrent
starts or new Exec connections; distributed race work is tracked separately
in [ROSAENG-67463](https://redhat.atlassian.net/browse/ROSAENG-67463).

Coordinate with the preceding SRE, disconnect their Exec shell, and verify their
audit evidence before replacing their task. The workspace persists, but OCM and
kubeconfig credential mounts are task-scoped and must be configured afresh.
After handover, any authorized SRE may request close once all shells detach. An accepted explicit request waits; a session-exit callback or auto-close intent from the previous holder is superseded, not inherited. [ROSAENG-75946](https://redhat.atlassian.net/browse/ROSAENG-75946)
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

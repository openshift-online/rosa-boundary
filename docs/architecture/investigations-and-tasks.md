# Investigations and Tasks

This document explains the conceptual model behind investigations and tasks in rosa-boundary: what they are, how they relate to each other, how their state is recorded, and how users are expected to work with them.

---

## Overview

Rosa-boundary uses two core abstractions to manage SRE access to clusters. The CLI calls a task a **session**; an ECS Exec shell connection is a separate short-lived session and does not stop the underlying Boundary session when disconnected.

- **Investigation**: A persistent workspace tied to a specific cluster incident.
- **Task**: An ephemeral container session launched within an investigation.

An investigation is the parent; tasks are its children. One investigation can have many tasks over its lifetime. Lambda attempts serial handover only when every candidate belongs to a known different owner and has no active SSM sessions. Same-user create and active shells return 409; unknown ownership or session state also blocks replacement. This is not an atomic one-task lock. Every task within the same investigation shares the same persistent filesystem. See the [implemented lifecycle reference](session-lifecycle.md) for the timeout matrix, exact tags, handover limitations and unresolved timeout policy.

## What Is an Investigation?

An investigation is a logical workspace identified by a `(cluster_id, investigation_id)` pair. It represents the full scope of an SRE's work on a particular cluster incident — from first login to final close-out.

Its physical manifestation is an **EFS access point** with a root directory at `/{cluster_id}/{investigation_id}/`. This directory is mounted to `/home/sre` inside every task container launched for that investigation, providing persistent storage that survives container restarts.

An investigation is created implicitly by `session create <cluster-id>` or explicitly by `investigation create <cluster-id>`.

## What Is a Task?

A task is an **ECS Fargate container** that provides an interactive SRE terminal session. CLI-created tasks request 1 hour by default; Terraform configures an 8-hour fallback for requests omitting the timeout. Reaping is periodic and defers for active or uncertain SSM session state, not a strict lifetime limit. A new `session create` can stop and replace a previous task through handover; it is not unconditionally rejected just because a task is running.

Each task launch:

1. Registers a new **ECS task definition** cloned from the base definition, with the investigation's EFS access point injected as a volume mount and environment variables (`CLUSTER_ID`, `INVESTIGATION_ID`, `TASK_TIMEOUT`, etc.) baked in.
2. Starts an **ECS Fargate task** with tags for ABAC enforcement, audit tracking, and timeout management.
3. On exit, the container **attempts to sync non-credential `/home/sre` content to S3** at a deterministic path: `s3://{bucket}/{cluster_id}/{investigation_id}/{date}/{task_id}/`.

SREs connect to running tasks via `session join <session-id>`, which uses ECS Exec (SSM) for interactive shell access. A Boundary session ID is an ECS task ID or ARN, not an SSM Exec connection ID.

## How They Relate

```
Investigation (EFS Access Point)
├── Task 1 (stopped)  ──► S3 audit sync on exit
├── Task 2 (stopped)  ──► S3 audit sync on exit
└── Task 3 (running)  ──► /home/sre mounted from EFS
```

The investigation outlives its tasks. When a task is stopped or reaped:

- The container attempts to sync non-credential `/home/sre` content to S3 (verify audit escrow separately).
- The EFS directory retains ordinary workspace files.
- A new task can be launched with `session create`; ordinary workspace files persist, but OCM credentials and derived kubeconfigs live on task-scoped, audit-excluded mounts and must be configured afresh.

This separation exists because tasks are kept short-lived for security (enforced timeouts, ABAC-scoped access), while investigations need to persist across sessions for usability.

## How State Is Recorded

Rosa-boundary has no database or API for tracking state. **AWS resources are the database.** The existence and metadata of investigations and tasks are recorded entirely through AWS resource tags and naming conventions:

| Resource | Represents | Created By | Discovered By | Cleaned Up By |
|----------|-----------|------------|---------------|---------------|
| EFS Access Point | Investigation | Lambda | `investigation list` (tag scan) | `investigation close` |
| ECS Task Definition | Task template | Lambda | `investigation close` (family prefix listing) | `investigation close` |
| ECS Fargate Task | Running session | Lambda | `session list` (describe + tags) | `session close` / reaper Lambda |
| S3 Objects | Audit artifacts | `entrypoint.sh` on task exit | AWS Console / CLI | S3 lifecycle policy |

### EFS Access Point Tags

Every investigation's access point is tagged with:

- `ClusterID` and `InvestigationID` — the investigation identity
- `username` — the SRE who created it
- `oidc_sub` — the OIDC subject UUID (audit)
- `ManagedBy: rosa-boundary-lambda`
- `Name` — `<cluster-id>-<investigation-id>`
- `CreatedAt` — original creation timestamp

These are creator tags, recorded for provenance. Handover does not update
them, and they do not decide who may close: any authorized Boundary SRE may request close once all shells detach. An attached shell blocks a new request, even with `--force`. If observed after acceptance, it makes the reaper wait. A running task whose SRE has detached leaves the investigation idle;
its `oidc_sub` tag is provenance too. See [creator-versus-actor semantics](session-lifecycle.md#actual-resource-tags-creator-versus-actor)
and [automated investigation close](investigation-close.md).

The close service's own markers also live here once a close begins:
`AuditCloseSeal`, `AuditCloseManagedBy`, `AuditCloseRequest` and
`AuditCloseBucket`. A seal without `AuditCloseManagedBy` is a manual retention
hold that automation never removes.

The `investigation list` command discovers investigations by scanning access points on the configured filesystem and filtering for both `ClusterID` and `InvestigationID` tags.

### ECS Task Tags

Every task is tagged with:

- `cluster_id` and `investigation_id` — links task to investigation
- Configured ABAC key (for example `uuid`, not an unconditional `username`) — current task caller's identity
- `oidc_sub` — current task caller's subject
- `deadline` — ISO 8601 timestamp, only when timeout is positive
- `access_point_id` — the EFS access point ID
- `created_at` and `task_timeout` — audit metadata

### Handover (Best-Effort Serial Replacement)

Before launching a task, Lambda checks existing RUNNING tasks using the ECS `startedBy` field — the first 36 hex characters of SHA-256 of `{cluster_id}:{investigation_id}`. This lookup is user-agnostic. Before any stop, Lambda requires a known different owner and verified inactive SSM state for every candidate. Same-user create returns 409 with list/join guidance; active shells also return 409. Unknown ownership or session state blocks replacement. If preflight passes, Lambda stops the old tasks and waits for STOPPED. Stop/wait failures abort replacement without rolling back stops already issued. `session join` is subject to the existing task's ABAC identity; it is not a cross-user handover mechanism. See [handover limits](session-lifecycle.md#handover-is-replacement-not-joining-another-users-task).

Using `startedBy` for this check (rather than a tag scan) avoids a cluster-wide `describe_tasks` call and sidesteps tag propagation race conditions, since `startedBy` is set atomically at task launch time.

## Creation Workflows

### `session create` (Primary Workflow)

This is the standard way to begin working on a cluster. It creates the investigation implicitly if one does not already exist:

1. Authenticate via OIDC (Keycloak PKCE browser flow)
2. Assume the Lambda invoker role
3. Invoke Lambda — which performs handover checks/stops for existing RUNNING tasks, creates or reuses the EFS access point, registers a per-investigation task definition, and launches a task
4. Optionally wait for the task to reach RUNNING state and auto-connect

### `investigation create` (Pre-staging)

This creates only the EFS access point without launching a container. Use it to pre-stage a workspace and later launch a task with `session create`.

### How the Lambda Handles Both

Both CLI commands invoke the same Lambda (`create-investigation`). The difference is a single `skip_task` flag:

- `session create` sets `skip_task=false` (default) — the Lambda creates the access point AND launches a task.
- `investigation create` sets `skip_task=true` — the Lambda creates only the access point.

The access point creation is idempotent. If an access point already exists with matching `ClusterID`/`InvestigationID` tags, it is reused regardless of which command is run.

## Lifecycle

### Active Use

```
investigation create (optional)
        │
        ▼
   session create  ──►  session join  ──►  work  ──►  session close (or reaper timeout)
        │                                              │
        │              ┌───────────────────────────────┘
        ▼              ▼
   session create  ──►  session join  ──►  work  ──►  session close
        │
        ▼
   investigation close
```

An SRE can cycle through start/stop iterations or request handover. Lambda waits for predecessor tasks it found to stop before launching a replacement, but concurrent requests are not atomically excluded. Each task mounts the same EFS directory, so ordinary work carries over. Each task exit attempts an S3 snapshot; verify completion independently.

### Closing an Investigation

`investigation close <cluster-id> <investigation-id>` previews the plan, confirms, and then **requests** a close. The CLI performs no cleanup of its own. The investigation reaper revalidates who may close, seals the workspace, stops only the tasks the request consented to stop, copies the workspace to its own attempt prefix in the audit bucket, verifies that copy independently, and only then:

1. **Deregisters task definitions** matching the investigation's family prefix
2. **Deletes the EFS access point**

Deleting the access point removes the entry point; the underlying EFS files at `/{cluster_id}/{investigation_id}/` are deliberately preserved on a normal close. The S3 audit bucket retains per-task snapshots and the close attempt's verified copy, subject to the bucket's retention policy.

Accepted is not closed: `--wait`, or a later `--status`, reports the service's current status. Any late task, read error or changed byte retains the data and starts a fresh attempt on the next schedule.

If an investigation is left open, the same reaper eventually reaps it as a stale candidate, through the same verified gate. Unlike a normal close, the stale route may also remove the EFS directory. See [automated investigation close](investigation-close.md).

### Timeout Enforcement

The task reaper runs every 15 minutes by default. It checks RUNNING tasks' deadline tags and stops expired tasks only after confirming no active SSM session. Active or uncertain session state defers reaping; missing deadlines are skipped. Zero is rejected by the default 30-second minimum, but if the minimum is disabled an accepted zero omits the deadline. See the [timeout matrix](session-lifecycle.md#timeout-matrix). [ROSAENG-75947 and ROSAENG-75948 remain unresolved policy work](session-lifecycle.md#unresolved-policy-decisions).

The reaper only stops **tasks** — it does not close investigations or clean up EFS access points.

### Stale Investigation Cleanup

The investigation reaper runs on a separate EventBridge schedule (default: every 8 hours). It checks managed EFS access points for running tasks and a `CreatedAt` tag; an investigation without running tasks becomes eligible once its configured grace period (default: 168 hours) has elapsed. Age is measured from original creation, not idle duration or handover. The current legacy-backfill path treats missing `CreatedAt` as stale when no tasks are running; it does not enforce the age grace period for those access points. Before recording a stale request it must observe no attached shells and no non-terminal tasks (including stopping tasks). It rechecks activity before cleanup, then runs the same verified finalization pipeline an explicit close runs — seal, observe quiet twice, measure, copy, verify independently — and only then removes the EFS directory, access point and associated task definitions. There is no backup-only route around that gate. Failures are logged; remaining tagged access points can be retried on a later run. See the [Lambda implementation](../../lambda/reap-investigations/handler.py) and [regional Terraform](../../deploy/regional/lambda-reap-investigations.tf) for current behavior and configuration.

## Known Gaps

**Normal close retains EFS directories, deliberately.** `investigation close` removes the access point but keeps the underlying files; reclaiming them is a stricter, separate decision. Only the stale route may reclaim a directory. Because close removes the tagged access point the reaper uses for discovery, a retained directory's path is recorded in the close status record instead, which stays readable after the access point is gone. Do not recreate a closed investigation over a retained directory.

**No guaranteed final sync.** The S3 audit sync happens on task exit, not on investigation close. If a task was force-killed or the sync timed out, the latest EFS state may not be in S3 before the access point is deleted.

**TOCTOU race in duplicate detection.** The one-task-per-investigation constraint relies on `ecs.list_tasks(desiredStatus='RUNNING')`. If two requests arrive simultaneously before either task reaches `RUNNING` state, both can pass the duplicate check. There is no distributed lock; the `startedBy` check is best-effort. In this unlikely case, both tasks would mount the same EFS directory with the same POSIX UID, and concurrent writes could conflict.

The investigation reaper does not guarantee a final S3 sync before deleting a stale investigation. Verify task audit evidence before manual close or relying on automatic cleanup.

---

## FAQ

### Can I create a task without an investigation?

No. The Lambda always creates an EFS access point before launching a task — there is no code path that skips it. Every task is always scoped to an investigation, always gets a persistent filesystem, and always has its audit trail grouped under `{cluster_id}/{investigation_id}/`.

However, you don't need to explicitly create an investigation first. `session create` creates it implicitly if one doesn't already exist for the pair.

### When would I use `investigation create` instead of `session create`?

`investigation create` is for pre-staging. In most cases `session create` creates the investigation as a side effect.

### What happens to my files when a task is stopped or reaped?

Two things:

1. The container attempts to sync `/home/sre` to S3 at `s3://{bucket}/{cluster_id}/{investigation_id}/{date}/{task_id}/` (audit escrow).
2. The EFS directory retains ordinary workspace files. On a subsequent `session create`, task-scoped credentials and kubeconfig state must be configured again.

### Are investigations automatically cleaned up?

Expired tasks are eligible for periodic reaping subject to active-session protection; a separate investigation reaper can also clean up eligible investigations with no running tasks after its creation-age grace period. Do not assume an open investigation persists indefinitely.

### What does `investigation close` actually delete?

It asks the close service to finalize the investigation. The service stops tasks only with explicit consent (`--force`), deregisters per-investigation task definitions and deletes the EFS access point after verifying its own copy of the workspace. It does **not** delete the underlying EFS directory data or the S3 audit artifacts.

### What is the maximum number of open investigations?

AWS allows 10,000 EFS access points per filesystem. Since each investigation corresponds to one access point, this is the hard upper limit.

### Are investigation filesystems shared across SREs?

Yes. The EFS access point path is computed from `/{cluster_id}/{investigation_id}/` — it does not include a username or any per-user identifier. If SRE Alice creates an investigation for cluster `c1` with ID `inv-123`, and SRE Bob later runs `session create` with the same pair, Bob's task reuses Alice's EFS access point and mounts the same directory as `/home/sre`. Bob has full read/write access to ordinary files Alice left behind; task-scoped OCM and kubeconfig credentials are not persisted there. Neither Alice nor Bob can submit a close request while Bob's shell is attached. After he detaches, either may request close. Without stop consent it also waits for his task to stop. Alice gains nothing from having created it, and Bob gains nothing lasting from having launched the task. This is enforced service-side by the close service and rechecked by the reaper, not by IAM against direct use of other AWS clients. See [automated investigation close](investigation-close.md) and the separate [ROSAENG-75946 close-ownership work](https://redhat.atlassian.net/browse/ROSAENG-75946).

This is by design. The investigation ID represents a **shared workspace** for a cluster incident, not a per-user workspace. The isolation boundary is at the `(cluster_id, investigation_id)` level. Per-user isolation is enforced at the **ECS Exec layer** via the deployment's configured ABAC task/principal tag (which may be `uuid` or `username`); this restricts who can `exec` into a running container, but not who can mount the shared workspace through a new authorized task.

### If multiple SREs create a task against the same investigation at the same time, are they sharing a filesystem at `/home/sre`?

Yes, if concurrent requests escape the best-effort handover check, they mount the same workspace. Lambda looks up existing tasks by the user-agnostic `startedBy` hash and can only replace known different owners' inactive tasks. It never grants cross-user Exec access. SREs should coordinate handover; the new task mounts the same workspace but not predecessor credentials.

There is a narrow TOCTOU race: if two SREs invoke the Lambda at the exact same moment before either task reaches `RUNNING` state (visible in `list_tasks`), both could pass the duplicate check. In that unlikely case, yes — both containers would mount the same EFS directory as `/home/sre` with the same POSIX UID (1000), and concurrent writes could conflict. There is no distributed lock to prevent this.

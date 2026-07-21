# Investigations and Tasks

This document explains the conceptual model behind investigations and tasks in rosa-boundary: what they are, how they relate to each other, how their state is recorded, and how users are expected to work with them.

---

## Overview

Rosa-boundary uses two core abstractions to manage SRE access to clusters:

- **Investigation**: A persistent workspace tied to a specific cluster incident.
- **Task**: An ephemeral container session launched within an investigation.

An investigation is the parent; tasks are its children. One investigation can have many tasks over its lifetime, but **only one task may be running per investigation at any given time**. The Lambda enforces this constraint — attempting to start a second task for the same investigation returns HTTP 409. Every task within the same investigation shares the same persistent filesystem.

## What Is an Investigation?

An investigation is a logical workspace identified by a `(cluster_id, investigation_id)` pair. It represents the full scope of an SRE's work on a particular cluster incident — from first login to final close-out.

Its physical manifestation is an **EFS access point** with a root directory at `/{cluster_id}/{investigation_id}/`. This directory is mounted to `/home/sre` inside every task container launched for that investigation, providing persistent storage that survives container restarts.

An investigation is created implicitly the first time a task is launched for a given `(cluster_id, investigation_id)` pair, or explicitly via the `create-investigation` CLI command.

## What Is a Task?

A task is an **ECS Fargate container** that provides an interactive SRE terminal session. Tasks are intentionally ephemeral — they are forcibly reaped after a configurable timeout (default: 1 hour) by the reaper Lambda. Only one task may run per investigation at a time; the Lambda rejects concurrent launches with HTTP 409. To start a new task, the previous one must be stopped first (manually or by the reaper).

Each task launch:

1. Registers a new **ECS task definition** cloned from the base definition, with the investigation's EFS access point injected as a volume mount and environment variables (`CLUSTER_ID`, `INVESTIGATION_ID`, `OC_VERSION`, etc.) baked in.
2. Starts an **ECS Fargate task** with tags for ABAC enforcement, audit tracking, and timeout management.
3. On exit, the container **syncs `/home/sre` to S3** at a deterministic path: `s3://{bucket}/{cluster_id}/{investigation_id}/{date}/{task_id}/`.

SREs connect to running tasks via `join-task`, which uses ECS Exec (SSM) for interactive shell access.

## How They Relate

```
Investigation (EFS Access Point)
├── Task 1 (stopped)  ──► S3 audit sync on exit
├── Task 2 (stopped)  ──► S3 audit sync on exit
└── Task 3 (running)  ──► /home/sre mounted from EFS
```

The investigation outlives its tasks. When a task is stopped or reaped:

- The container syncs `/home/sre` to S3 (audit escrow).
- The EFS directory retains all files.
- A new task can be launched with `start-task`, and the SRE picks up exactly where they left off — shell history, kubeconfigs, mustgathers, notes, and scripts are all preserved.

This separation exists because tasks are kept short-lived for security (enforced timeouts, ABAC-scoped access), while investigations need to persist across sessions for usability.

## How State Is Recorded

Rosa-boundary has no database or API for tracking state. **AWS resources are the database.** The existence and metadata of investigations and tasks are recorded entirely through AWS resource tags and naming conventions:

| Resource | Represents | Created By | Discovered By | Cleaned Up By |
|----------|-----------|------------|---------------|---------------|
| EFS Access Point | Investigation | Lambda | `list-investigations` (tag scan) | `close-investigation` |
| ECS Task Definition | Task template | Lambda | `close-investigation` (family prefix listing) | `close-investigation` |
| ECS Fargate Task | Running session | Lambda | `list-tasks` (describe + tags) | `stop-task` / reaper Lambda |
| S3 Objects | Audit artifacts | `entrypoint.sh` on task exit | AWS Console / CLI | S3 lifecycle policy |

### EFS Access Point Tags

Every investigation's access point is tagged with:

- `ClusterID` and `InvestigationID` — the investigation identity
- `username` — the SRE who created it
- `oidc_sub` — the OIDC subject UUID (audit)
- `ManagedBy: rosa-boundary-lambda`

The `list-investigations` command discovers investigations by scanning all access points on the filesystem and filtering for ones with both `ClusterID` and `InvestigationID` tags.

### ECS Task Tags

Every task is tagged with:

- `cluster_id` and `investigation_id` — links task to investigation
- `username` — the SRE's identity (used for ABAC enforcement)
- `deadline` — ISO 8601 timestamp for reaper enforcement
- `access_point_id` — the EFS access point ID
- `created_at` and `task_timeout` — audit metadata

### Duplicate Detection (One Task Per Investigation)

The Lambda enforces a **one running task per investigation** constraint. Before launching a task, it checks for existing running tasks using the ECS `startedBy` field — a deterministic SHA-256 hash of `{cluster_id}:{investigation_id}`. This check is user-agnostic: it blocks a second task for the same investigation regardless of which SRE is requesting it. If a task is already running, the Lambda returns HTTP 409 with the existing task ARN(s) so the caller can `join-task` instead.

Using `startedBy` for this check (rather than a tag scan) avoids a cluster-wide `describe_tasks` call and sidesteps tag propagation race conditions, since `startedBy` is set atomically at task launch time.

## Creation Workflows

### `start-task` (Primary Workflow)

This is the standard way to begin working on a cluster. It creates the investigation implicitly if one does not already exist:

1. Authenticate via OIDC (Keycloak PKCE browser flow)
2. Assume the Lambda invoker role
3. Invoke the Lambda — which checks for an existing running task (returning HTTP 409 if one exists), idempotently creates the EFS access point, registers a per-investigation task definition, and launches an ECS task
4. Optionally wait for the task to reach RUNNING state and auto-connect

### `create-investigation` (Pre-staging)

This creates only the EFS access point without launching a container. Use this when you want to set up a workspace ahead of time — for example, before a scheduled maintenance window — and launch a task later with `start-task`.

### How the Lambda Handles Both

Both CLI commands invoke the same Lambda (`create-investigation`). The difference is a single `skip_task` flag:

- `start-task` sets `skip_task=false` (default) — the Lambda creates the access point AND launches a task.
- `create-investigation` sets `skip_task=true` — the Lambda creates only the access point.

The access point creation is idempotent. If an access point already exists with matching `ClusterID`/`InvestigationID` tags, it is reused regardless of which command is run.

## Lifecycle

### Active Use

```
create-investigation (optional)
        │
        ▼
   start-task  ──►  join-task  ──►  work  ──►  stop-task (or reaper timeout)
        │                                              │
        │              ┌───────────────────────────────┘
        ▼              ▼
   start-task  ──►  join-task  ──►  work  ──►  stop-task
        │
        ▼
   close-investigation
```

An SRE can cycle through as many start/stop iterations as needed, but the previous task must be stopped (or reaped) before a new one can be started — only one task may run per investigation at a time. Each task mounts the same EFS directory, so work carries over. Each task exit syncs a snapshot to S3.

### Closing an Investigation

`close-investigation` performs cleanup in order:

1. **Stops running tasks** (requires `--force` if any are active)
2. **Deregisters task definitions** matching the investigation's family prefix
3. **Deletes the EFS access point**

Note: deleting the access point removes the entry point, but the underlying EFS files at `/{cluster_id}/{investigation_id}/` are preserved on the filesystem. The S3 audit bucket retains per-task snapshots subject to the bucket's retention policy.

### Timeout Enforcement

The reaper Lambda runs on an EventBridge schedule (default: every 15 minutes). It lists all running tasks in the cluster, checks each task's `deadline` tag, and stops any task where the current time exceeds the deadline. Tasks without a `deadline` tag are skipped.

The reaper only stops **tasks** — it does not close investigations or clean up EFS access points.

## Known Gaps

**No automatic investigation reaping.** Tasks are automatically reaped by the reaper Lambda, but investigations (EFS access points) persist until manually closed. AWS allows a maximum of 10,000 access points per filesystem, creating a hard upper limit on open investigations.

**No EFS directory cleanup.** `close-investigation` deletes the access point but not the underlying files. The EFS directory data at `/{cluster_id}/{investigation_id}/` accumulates indefinitely.

**No guaranteed final sync.** The S3 audit sync happens on task exit, not on investigation close. If a task was force-killed or the sync timed out, the latest EFS state may not be in S3 before the access point is deleted.

**TOCTOU race in duplicate detection.** The one-task-per-investigation constraint relies on `ecs.list_tasks(desiredStatus='RUNNING')`. If two requests arrive simultaneously before either task reaches `RUNNING` state, both can pass the duplicate check. There is no distributed lock; the `startedBy` check is best-effort. In this unlikely case, both tasks would mount the same EFS directory with the same POSIX UID, and concurrent writes could conflict.

A garbage collection strategy will need to address automatic reaping of stale access points, orphaned task definitions, a final S3 sync before cleanup, and removal of EFS directory contents after successful sync.

---

## FAQ

### Can I create a task without an investigation?

No. The Lambda always creates an EFS access point before launching a task — there is no code path that skips it. Every task is always scoped to an investigation, always gets a persistent filesystem, and always has its audit trail grouped under `{cluster_id}/{investigation_id}/`.

However, you don't need to explicitly create an investigation first. `start-task` creates the investigation implicitly if one doesn't already exist for the given `(cluster_id, investigation_id)` pair.

### When would I use `create-investigation` instead of `start-task`?

`create-investigation` is for pre-staging. If you know you'll need to work on a cluster tomorrow but want the workspace ready in advance, you can create the investigation now and `start-task` later. In most cases, `start-task` is all you need — it handles investigation creation as a side effect.

### What happens to my files when a task is stopped or reaped?

Two things:

1. The container attempts to sync `/home/sre` to S3 at `s3://{bucket}/{cluster_id}/{investigation_id}/{date}/{task_id}/` (audit escrow).
2. The EFS directory retains all files. When you `start-task` again for the same investigation, everything is still there.

### Are investigations automatically cleaned up?

No. Tasks are automatically reaped by the reaper Lambda after their deadline expires, but investigations persist indefinitely until someone runs `close-investigation`. This is a known gap — see [Known Gaps](#known-gaps).

### What does `close-investigation` actually delete?

It stops running tasks (with `--force`), deregisters per-investigation task definitions, and deletes the EFS access point. It does **not** delete the underlying EFS directory data or the S3 audit artifacts.

### What is the maximum number of open investigations?

AWS allows 10,000 EFS access points per filesystem. Since each investigation corresponds to one access point, this is the hard upper limit.

### Are investigation filesystems shared across SREs?

Yes. The EFS access point path is computed from `/{cluster_id}/{investigation_id}/` — it does not include a username or any per-user identifier. If SRE Alice creates an investigation for cluster `c1` with ID `inv-123`, and SRE Bob later runs `start-task` with the same `(c1, inv-123)` pair, Bob's task reuses Alice's EFS access point and mounts the same directory as `/home/sre`. Bob has full read/write access to everything Alice left behind.

This is by design. The investigation ID represents a **shared workspace** for a cluster incident, not a per-user workspace. The isolation boundary is at the `(cluster_id, investigation_id)` level. Per-user isolation is enforced at the **ECS Exec layer** via ABAC tags — the `username` tag on the ECS task controls who can `exec` into a running container, but not who can mount the filesystem.

### If multiple SREs create a task against the same investigation at the same time, are they sharing a filesystem at `/home/sre`?

They would be, but the Lambda prevents it. The duplicate detection mechanism uses a `startedBy` hash computed from `{cluster_id}:{investigation_id}` (user-agnostic). Before launching a task, the Lambda calls `ecs.list_tasks(startedBy=..., desiredStatus='RUNNING')`. If a task is already running for that investigation — regardless of which SRE started it — the Lambda returns HTTP 409 and the second request is rejected.

So under normal operation, only one task runs per investigation at a time. The SREs would need to take turns: one stops their task, the other starts a new one, and the new task mounts the same EFS directory with all prior work intact.

There is a narrow TOCTOU race: if two SREs invoke the Lambda at the exact same moment before either task reaches `RUNNING` state (visible in `list_tasks`), both could pass the duplicate check. In that unlikely case, yes — both containers would mount the same EFS directory as `/home/sre` with the same POSIX UID (1000), and concurrent writes could conflict. There is no distributed lock to prevent this.

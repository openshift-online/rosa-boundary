---
type: workflow
title: Investigation lifecycle
description: Traces investigation workspace creation, task launch and handover, operator connection, timeout enforcement, and cleanup across the CLI, Lambda, ECS, and EFS, including the reaper's active-session protection.
tags: [investigations, lifecycle, ecs, efs, workflow]
sources:
  - id: openwiki-source-84177eee21b0f3eb77df526a
    resource: repo://deploy/regional/iam.tf
  - id: openwiki-source-a7f1ddde1efa89d5bfad2d5c
    resource: repo://deploy/regional/lambda-reap-tasks.tf
  - id: openwiki-source-9c181bb7100aaf770ed7b6d2
    resource: repo://internal/aws/efs.go
  - id: openwiki-source-3eb89a64c83d3140ea6ba8c4
    resource: repo://internal/cmd/close_investigation.go
  - id: openwiki-source-afb513350372573f5c160a72
    resource: repo://internal/cmd/join_task.go
  - id: openwiki-source-4310358fd4831534f06796e2
    resource: repo://internal/cmd/list_investigations.go
  - id: openwiki-source-30a998731e96cfbdb6395fa3
    resource: repo://internal/cmd/stop_task.go
  - id: openwiki-source-253b57ec87256e726a724093
    resource: repo://lambda/create-investigation/handler.py
  - id: openwiki-source-dee88de5f65c3f85b9074174
    resource: repo://lambda/create-investigation/test_handler.py
  - id: openwiki-source-6e447421bb9d1456afb165d9
    resource: repo://lambda/reap-tasks/handler.py
  - id: openwiki-source-9c54377d52ae59aed2d249c7
    resource: repo://lambda/reap-tasks/test_handler.py
  - id: openwiki-source-30a9bbeef6a7c1bda59eab80
    resource: repo://tests/localstack/integration/test_full_workflow.py
generated: { by: "openwiki/0.7.1", at: "2026-10-09T17:04:25.482Z" }
verified:
  - by: openwiki/0.7.1
    at: 2026-10-09T17:04:25.482Z
---

# Investigation lifecycle

An investigation is durable EFS-backed workspace state identified by a ROSA cluster ID and investigation ID. An ECS task is a replaceable execution session using that workspace. Creating a workspace, launching/replacing a task, stopping a task, and closing the investigation are separate lifecycle operations; stopping a task alone does not remove the EFS access point or workspace data.

## Create workspace or start a task

`create-investigation` invokes the Lambda with `skip_task=true`. The Lambda validates the operator and request, finds an available access point with matching `ClusterID` and `InvestigationID` tags, and verifies that its root path is exactly `/<cluster-id>/<investigation-id>`. If none is found, it creates one with `sre` UID/GID ownership and investigation/owner tags. The skip-task path returns the access point without scanning for or launching ECS tasks, allowing a workspace to be prepared with no running task.

`start-task` invokes the same Lambda without `skip_task`. It may generate a three-word investigation ID, sends the target cluster, OC version, and task timeout, then assumes the shared SRE role and waits for the task to reach `RUNNING` unless `--no-wait` is set. The ROSA cluster ID scopes investigation state; the separately configured ECS cluster is where the task is launched and managed.

## Replace task safely

Before starting a replacement task, the Lambda finds running tasks by a deterministic `startedBy` value derived from both cluster ID and investigation ID. Before stopping any existing task, it calls `DescribeTasks`; an empty result or an ECS/SSM API error blocks handover. For returned tasks, it queries SSM for active sessions only when a container has a `runtimeId`. A detected active session blocks handover, and the full preflight runs before any task is stopped, so a detected session prevents partial stops of other tasks in the same handover. **Current behavior caveat:** if task details contain no containers, or a container has no `runtimeId`, that container is skipped without an SSM lookup and the handover can proceed to stop the task. The unit tests cover empty task details, active sessions, and SSM errors, but do not cover the missing-`runtimeId` case. If preflight passes, the Lambda stops existing tasks and waits for termination before proceeding; a stop or wait failure prevents the new task launch.

The Lambda then reuses the investigation access point or creates one. It registers a uniquely named task definition based on the base family plus cluster ID, investigation ID, and timestamp. This copy points `/home/sre` at the investigation access point, overlays task-scoped OCM/kubeconfig volumes, preserves unrelated mounts, and injects investigation-specific environment values. ECS `RunTask` starts Fargate with ECS Exec enabled, private-IP networking, a deterministic `startedBy`, and task tags for owner/ABAC, investigation, access point, creation time, and timeout. A deadline tag is added only when timeout is greater than zero. Tags are also applied explicitly after launch for timely IAM evaluation.

If task-definition registration or task launch fails, the Lambda cleans up a newly created access point and deregisters the new task definition where possible. If applying task tags fails after launch, it also stops the task. A reused access point is retained during rollback because it may hold existing investigation data.

## Connect and inspect

`join-task` describes the task, waits for `RUNNING` unless configured not to, then waits up to 30 seconds for the chosen container's ECS Exec agent before requesting a session and handing control to `session-manager-plugin`. `start-task --connect` uses the same connection path after optional credential setup succeeds. `list-tasks` queries ECS and presents task tags; `list-investigations` discovers workspaces from EFS access point tags, so a workspace remains listed even when no task is running.

## Stop, timeout, and close

`stop-task` requests ECS termination and can optionally wait for `STOPPED`. Container shutdown is handled by the entrypoint and attempts the S3 audit sync. The reaper Lambda provides independent timeout enforcement: EventBridge invokes it periodically, it paginates RUNNING tasks, describes them in batches of up to 100, and considers stopping tasks whose ISO-8601 `deadline` tag has passed. Tasks without deadlines, with future deadlines, or with malformed deadline values are skipped without any session check.

The reaper no longer stops every task past its deadline unconditionally. Before stopping an expired task it calls `has_active_ssm_session(cluster, task_id, task)`, which inspects the task's `enableExecuteCommand` flag and its containers' `lastStatus`/`runtimeId` (both already present in the `describe_tasks` response, so no extra ECS call is needed) to decide whether an SRE may still be attached:

- `enableExecuteCommand is False` (explicit) — the task is not exec-capable, so it is safe to reap without any SSM call.
- `enableExecuteCommand is True` — the reaper checks SSM. For each container whose `lastStatus` is `RUNNING` (or unspecified) it builds the ECS Exec target string `ecs:{cluster}_{task_id}_{runtime_id}` — the same convention `create-investigation` uses for handover — and calls `DescribeSessions` with `State='Active'` filtered on that target, paginating through `NextToken` until a session is found or the pages are exhausted. An `Active` session on any checked container means the task is protected: the reaper counts it in a `protected` result field and logs that the task was skipped this run, without calling `StopTask`.
- Any other situation — a missing or non-boolean `enableExecuteCommand`, no container detail in the task, a `RUNNING`-or-ambiguous-status container with no `runtimeId`, or exec enabled with no checkable `RUNNING` container at all — raises `SessionCheckError`. The reaper fails closed on this error: it logs an error, increments the `errors` counter, and continues to the next task rather than stopping the ambiguous one.

Only once `has_active_ssm_session` returns `False` does the reaper call `stop_task`; `ClientError`/`BotoCoreError`/`ConnectionError` from that call are caught and counted as `errors` without abandoning the rest of the batch. The Lambda's result/summary therefore reports `checked`, `stopped`, `skipped`, `protected`, and `errors` counts. This check requires the reaper's execution role to hold `ssm:DescribeSessions`, which (like `create-investigation`'s equivalent grant) cannot be scoped to a specific SSM resource ARN and is therefore granted with `Resource = "*"` alongside the existing cluster-scoped `ecs:ListTasks`, task-scoped `ecs:DescribeTasks`, and deadline-tag-conditioned `ecs:StopTask` grants.

`close-investigation` finds the access point by investigation tag and optional cluster tag; omitting cluster ID is rejected when that investigation ID matches multiple clusters. It refuses to continue if tasks are running unless `--force` is supplied. With force, it stops and waits for matching running tasks, then deregisters active task definitions with a family prefix scoped to the ECS cluster, cluster ID, and investigation ID. It prompts before deleting the access point unless `--yes` is set. Deleting the access point does not delete its underlying EFS directory contents.

## Failure boundaries and tests

Lambda unit tests cover skip-task behavior, access-point reuse, handover guards, task definition shaping, and rollback differences for newly created versus reused access points. For the handover guard, they cover empty task details and active-session/SSM-error failures, but not a task whose container lacks `runtimeId`.

The reaper's own unit tests (`lambda/reap-tasks/test_handler.py`) mock both `handler.ecs` and `handler.ssm` via `patch`, with a `_exec_task` helper that builds `describe_tasks`-shaped fixtures carrying `enableExecuteCommand` and a `containers` list with `lastStatus`/`runtimeId`. Beyond the pre-existing deadline-parsing (missing/future/malformed `deadline` tag), pagination (`list_tasks` over multiple pages, `describe_tasks` batches of up to 100), and non-session `stop_task` error-handling coverage, dedicated cases exercise the session-protection path: an expired task with an active session is protected and not stopped; an expired task with no active session is stopped as before; a future deadline never triggers a session lookup; an SSM `DescribeSessions` failure on one task fails closed (`errors` incremented) without blocking reaping of other expired tasks in the same batch; a session on any one of several containers protects the whole task; a `RUNNING` container missing `runtimeId`, or a missing/non-boolean `enableExecuteCommand`, fails closed without even attempting an SSM call; and an `Active` session reported only on a later `DescribeSessions` page is still detected. LocalStack integration tests check EFS/ECS relationships, close behavior and ambiguity, task-definition family scoping, and the end-to-end deadline-tag/reaper path. Slow cases that require a task to reach `RUNNING` are skipped with LocalStack's local ECS executor.

## Evidence-backed claims

- Workspace-only creation uses `skip_task` to make/reuse an EFS access point without launching a task; access-point reuse requires available state, matching cluster/investigation tags, and the expected root path. [skip-task branching](repo://lambda/create-investigation/handler.py#L676-L818) · [path/tag verification](repo://lambda/create-investigation/handler.py#L432-L466) · [unit tests](repo://lambda/create-investigation/test_handler.py#L704-L855)
- Task replacement uses deterministic `startedBy` discovery and checks SSM sessions only for containers with a `runtimeId`; empty task details, detected active sessions, and ECS/SSM API errors fail closed, but missing `runtimeId` skips that session lookup and can allow stopping. The handover tests cover the fail-closed cases but not missing `runtimeId`. [discovery](repo://lambda/create-investigation/handler.py#L31-L45) · [conditional session lookup and stop sequence](repo://lambda/create-investigation/handler.py#L691-L774) · [handover tests](repo://lambda/create-investigation/test_handler.py#L1242-L1517)
- The Lambda derives a per-investigation task definition with a unique family, investigation-specific EFS and task-scoped credential mounts, and launches Fargate with ECS Exec and investigation/deadline tags. [task definition registration](repo://lambda/create-investigation/handler.py#L469-L637) · [ECS launch and tags](repo://lambda/create-investigation/handler.py#L821-L949)
- Rollback removes newly created access points, and tag-application failure also stops an already launched task; reused access points are preserved. [registration and launch cleanup](repo://lambda/create-investigation/handler.py#L829-L861) · [tag-failure cleanup](repo://lambda/create-investigation/handler.py#L941-L992) · [reused access-point rollback test](repo://lambda/create-investigation/test_handler.py#L2091-L2157)
- The reaper periodically processes RUNNING tasks, identifying expired deadlines while skipping absent, future, or malformed values; the integration suite chains task tags into reaper enforcement. [reaper main loop](repo://lambda/reap-tasks/handler.py#L48-L206) · [schedule](repo://deploy/regional/lambda-reap-tasks.tf#L43-L57) · [deadline lifecycle integration](repo://tests/localstack/integration/test_full_workflow.py#L214-L287)
- Before stopping an expired task, the reaper calls `has_active_ssm_session`, which treats explicit `enableExecuteCommand=False` as safe-to-reap, queries SSM `DescribeSessions` (paginated, target `ecs:{cluster}_{task_id}_{runtime_id}`) only when it is explicitly `True`, and raises `SessionCheckError` for every other case (missing/non-boolean flag, no container detail, a RUNNING-or-ambiguous container with no `runtimeId`, or no checkable RUNNING container); a detected Active session increments a `protected` counter and skips the stop, while `SessionCheckError` increments `errors` and also skips the stop rather than reaping the task. [session-check fail-closed logic](repo://lambda/reap-tasks/handler.py#L246-L361) · [protect/skip call sites](repo://lambda/reap-tasks/handler.py#L135-L166) · [unit test coverage](repo://lambda/reap-tasks/test_handler.py#L336-L545)
- The reaper's execution role requires `ssm:DescribeSessions` (unscopable to a resource ARN, so granted with `Resource = "*"`) in addition to its existing cluster-scoped `ecs:ListTasks`, task-scoped `ecs:DescribeTasks`, and deadline-tag-conditioned `ecs:StopTask` grants. [reaper IAM policy](repo://deploy/regional/iam.tf#L262-L294)
- Close requires explicit force to stop running tasks, scopes task-definition cleanup by family prefix, confirms before access-point deletion by default, and leaves EFS data in place. [close workflow](repo://internal/cmd/close_investigation.go#L96-L186) · [tag-based AP lookup](repo://internal/aws/efs.go#L42-L100) · [family scoping and cleanup test](repo://tests/localstack/integration/test_close_investigation.py#L67-L143)
- Join waits for task and ECS Exec agent readiness before opening the SSM session; LocalStack tests cover task stop and cross-component lifecycle behavior, with actual task launch tests requiring a non-local executor. [join sequence](repo://internal/cmd/join_task.go#L57-L101) · [LocalStack executor gate](repo://tests/localstack/integration/test_task_timeout.py#L16-L78)

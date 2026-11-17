---
type: workflow
title: Investigation lifecycle
description: Traces investigation workspace creation, session launch/handover, operator connection, timeout enforcement, garbage collection, and closing across the CLI, Lambda, ECS, and EFS, including how the create-investigation Lambda's own ZIP/container-image packaging fits into the trigger path.
tags: [investigations, lifecycle, ecs, efs, workflow, garbage-collection, lambda, container-build]
verified:
  - by: openwiki/0.7.1
    at: 2026-11-17T16:03:58.857Z
sources:
  - id: openwiki-source-d26615a0354c146aa6f23c2c
    resource: repo://deploy/account/ecr-lambda.tf
  - id: openwiki-source-b84818c3b6429e491a77175c
    resource: repo://deploy/regional/ecr-lambda-destination.tf
  - id: openwiki-source-d176128a85129af793772942
    resource: repo://deploy/regional/lambda-create-investigation.tf
  - id: openwiki-source-81b84da9542934c33f2e42d7
    resource: repo://deploy/regional/lambda-reap-investigations.tf
  - id: openwiki-source-a7f1ddde1efa89d5bfad2d5c
    resource: repo://deploy/regional/lambda-reap-tasks.tf
  - id: openwiki-source-a055ff9a3fcbd2c0a0fc4ee2
    resource: repo://deploy/regional/variables.tf
  - id: openwiki-source-527b127f4d59725c0085dfbf
    resource: repo://docs/staging-deployment.md
  - id: openwiki-source-9c181bb7100aaf770ed7b6d2
    resource: repo://internal/aws/efs.go
  - id: openwiki-source-3eb89a64c83d3140ea6ba8c4
    resource: repo://internal/cmd/close_investigation.go
  - id: openwiki-source-d76b37adadbf60c56bb7ff4d
    resource: repo://internal/cmd/join_session.go
  - id: openwiki-source-4310358fd4831534f06796e2
    resource: repo://internal/cmd/list_investigations.go
  - id: openwiki-source-2452fe2ff931e1490d573519
    resource: repo://internal/cmd/start_session.go
  - id: openwiki-source-6bf774b758d1eaaf7cc21e94
    resource: repo://internal/cmd/stop_session.go
  - id: openwiki-source-ded7ace1e37f1ab771ccaf0b
    resource: repo://lambda/create-investigation/Containerfile
  - id: openwiki-source-253b57ec87256e726a724093
    resource: repo://lambda/create-investigation/handler.py
  - id: openwiki-source-ae0e11fbe7ed89eafcab9312
    resource: repo://lambda/create-investigation/Makefile
  - id: openwiki-source-a26915e357fc9eaad3cc4090
    resource: repo://lambda/create-investigation/pyproject.toml
  - id: openwiki-source-dee88de5f65c3f85b9074174
    resource: repo://lambda/create-investigation/test_handler.py
  - id: openwiki-source-d796a031add13f67891a2f24
    resource: repo://lambda/reap-investigations/handler.py
  - id: openwiki-source-bb51fbbb404e02867c4bd266
    resource: repo://lambda/reap-investigations/test_handler.py
  - id: openwiki-source-6e447421bb9d1456afb165d9
    resource: repo://lambda/reap-tasks/handler.py
  - id: openwiki-source-012f2c78e3b1446dfc35803f
    resource: repo://Makefile
  - id: openwiki-source-80fcaf58926aeda8dd2be405
    resource: repo://tests/unit/test_reap_investigations_staleness.py
generated: { by: "openwiki/0.7.1", at: "2026-11-17T16:03:58.857Z" }
---

# Investigation lifecycle

An investigation is durable EFS-backed workspace state identified by a ROSA cluster ID and investigation ID. An ECS task — exposed to CLI users as a **session** — is a replaceable execution inside that workspace. The CLI groups commands accordingly: `rosa-boundary investigation {create,list,close}` manages the durable workspace, and `rosa-boundary session {create,list,join,close}` manages the running ECS task inside it (`session start`/`session stop` are retired aliases that now fail with a pointer to `session create`/`session close`). Creating a workspace, launching/replacing a session, closing a session, closing the investigation, and garbage-collecting a stale investigation are separate lifecycle operations; closing a session alone does not remove the EFS access point or workspace data.

## Create workspace or create a session

`investigation create` (`runCreateInvestigation`) invokes the Lambda via `CreateInvestigationOnly`, which always sends `skip_task=true`. The Lambda validates the operator and request, finds an available access point with matching `ClusterID` and `InvestigationID` tags, and verifies that its root path is exactly `/<cluster-id>/<investigation-id>`. If none is found, it creates one with `sre` UID/GID ownership and investigation/owner tags. The skip-task path returns the access point without scanning for or launching ECS tasks, allowing a workspace to be prepared with no running session.

`session create` (`runStartSession`) invokes the same Lambda via `CreateInvestigation`, without `skip_task` (`TaskTimeoutSet: true` is always sent so an explicit `0` is distinguishable from "unset"). It may generate a three-word investigation ID, sends the target cluster, OC version, and `--session-timeout` (whole seconds, 0–24h, default 1h; carried to the Lambda as `TaskTimeout` and echoed back as both `session_timeout` and the legacy `task_timeout` JSON keys). The command derives the Boundary session ID directly from the Lambda's response — `sessionID := path.Base(lambdaResp.TaskARN)` — rather than from any dedicated identifier field, matching the convention ECS itself uses for task IDs; from that point on, any further failure in `runStartSession` is wrapped by `sessionCreationError`, which embeds the derived session ID, cluster/investigation IDs, and a ready-made `session close --yes <sessionID>` cleanup command, since a real ECS task already exists by then. The command then assumes the shared SRE role (falling back to the Lambda's own `role_arn` only when no `sre_role_arn` override is configured) and waits for the task to reach `RUNNING` unless `--no-wait` is set. The ROSA cluster ID scopes investigation state; the separately configured ECS cluster is where the task is launched and managed.

With `--no-wait`, optional OCM credential configuration is rejected outright, and `credentialWarning` is pre-populated with a reminder to configure credentials once the task is confirmed `RUNNING`. Otherwise, once the task is `RUNNING`, requested `--with-credentials ocm` setup runs; on failure `credentialWarning` is overwritten with a detailed recovery message (including a ready retry command) and `configureOCM` is forced to `false` so later step numbering reflects that credentials were not applied. Both outcomes — launched-without-credentials via `--no-wait`, and a failed or skipped OCM step — flow into `finishStartSession`, which performs the optional `--connect` handoff (see below) and assembles the final text or JSON result, folding a non-empty `credentialWarning` into a `"warnings"` JSON array or leaving it already printed as a text warning.

## Replace task safely

Before starting a replacement task, the Lambda finds running tasks by a deterministic `startedBy` value derived from both cluster ID and investigation ID. Before stopping any existing task, it calls `DescribeTasks`; an empty result or an ECS/SSM API error blocks handover. For returned tasks, it queries SSM for active sessions only when a container has a `runtimeId`. A detected active session blocks handover, and the full preflight runs before any task is stopped, so a detected session prevents partial stops of other tasks in the same handover. **Current behavior caveat:** if task details contain no containers, or a container has no `runtimeId`, that container is skipped without an SSM lookup and the handover can proceed to stop the task. The unit tests cover empty task details, active sessions, and SSM errors, but do not cover the missing-`runtimeId` case. If preflight passes, the Lambda stops existing tasks and waits for termination before proceeding; a stop or wait failure prevents the new task launch.

The Lambda then reuses the investigation access point or creates one. It registers a uniquely named task definition based on the base family plus cluster ID, investigation ID, and timestamp. This copy points `/home/sre` at the investigation access point, overlays task-scoped OCM/kubeconfig volumes, preserves unrelated mounts, and injects investigation-specific environment values. ECS `RunTask` starts Fargate with ECS Exec enabled, private-IP networking, a deterministic `startedBy`, and task tags for owner/ABAC, investigation, access point, creation time, and timeout. A deadline tag is added only when timeout is greater than zero. Tags are also applied explicitly after launch for timely IAM evaluation.

If task-definition registration or task launch fails, the Lambda cleans up a newly created access point and deregisters the new task definition where possible. If applying task tags fails after launch, it also stops the task. A reused access point is retained during rollback because it may hold existing investigation data.

```mermaid
sequenceDiagram
    participant CLI as session create
    participant Lambda as create-investigation Lambda
    participant ECS
    participant SSM
    participant EFS

    CLI->>Lambda: invoke (cluster_id, investigation_id, session_timeout)
    Lambda->>ECS: ListTasks (startedBy = hash(cluster_id:investigation_id))
    ECS-->>Lambda: running task ARNs
    alt running tasks found
        Lambda->>ECS: DescribeTasks(taskArns)
        ECS-->>Lambda: task + container details
        alt container has runtimeId
            Lambda->>SSM: DescribeSessions(State=Active, Target=task/container)
            SSM-->>Lambda: active sessions
        end
        alt active session detected or DescribeTasks empty/errored
            Lambda-->>CLI: HandoverFailedError (409/500)
        else preflight passes
            Lambda->>ECS: StopTask (each existing task)
            Lambda->>ECS: wait tasks_stopped
        end
    end
    Lambda->>EFS: DescribeAccessPoints (reuse) or CreateAccessPoint
    Lambda->>ECS: RegisterTaskDefinition (per-investigation family + timestamp)
    Lambda->>ECS: RunTask (FARGATE, ECS Exec, startedBy, tags)
    Lambda->>ECS: TagResource (explicit tag application)
    Lambda-->>CLI: task ARN, access point ID, task definition ARN
```
*Task handover: discover running tasks by `startedBy`, preflight for active sessions, stop and wait, then reuse/create the EFS access point and relaunch.*

## Connect and inspect

`session join <session-id>` (`runJoinSession`) builds an ECS client for the configured cluster and delegates to `connectToSession`, which describes the task, waits for `RUNNING` unless `--no-wait` is set, then polls up to 30 seconds for the chosen container's ECS Exec agent (the SSM data channel closes immediately if the agent has not registered yet) before calling `ExecuteCommand` and handing control to `session-manager-plugin`.

`session create --connect` reaches the identical `connectToSession` implementation through the package-level `openInteractiveSession` variable, invoked from `finishStartSession` after the RUNNING wait and the optional OCM credential step. Connecting proceeds whether or not that credential step was requested or succeeded — success only changes the printed step label from "Step 4: Connecting to session" to "Step 5: Connecting to session"; a skipped or failed credential step leaves the connect step numbered 4 and the task still reachable with a recorded `credentialWarning`. `--connect` requires a terminal and cannot combine with `--no-wait`. Disconnecting from either `session join` or `session create --connect` only ends the interactive shell; it does not stop the task or close the investigation.

`session list` queries ECS and presents task tags (status, owner, start time) under the `session_id`/`session_arn` names, while the underlying resource remains an ECS task; `investigation list` discovers workspaces from EFS access point tags, so a workspace remains listed even when no session is running.

## Close a session, then close an investigation

`session close <session-id>` (`runStopSession`) resolves the task, rejects a target that is already `STOPPED` (pointing the operator at `investigation close` instead), prints the target investigation/owner, and — unless `--yes` is given in an interactive terminal — prompts for confirmation before calling ECS `StopTask`. `--wait` blocks for `STOPPED`; without it the command reports how to poll `session list --status all`. Closing a session stops only its task and explicitly leaves the investigation workspace open. Container shutdown is handled by the entrypoint and attempts the S3 audit sync. The reaper Lambda (`reap-tasks`) provides independent timeout enforcement: EventBridge invokes it periodically, it paginates RUNNING tasks, describes them in batches of up to 100, and stops tasks whose ISO-8601 `deadline` has passed **unless an active ECS Exec/SSM session is detected**. Tasks without deadlines, with future deadlines, with malformed deadline values, or with active sessions are skipped; per-task stop/describe failures are counted without abandoning the rest of the batch.

`investigation close <cluster-id> <investigation-id>` (`runCloseInvestigation`) builds a `closePlan` via `resolveClosePlan` before touching any resource: it finds the access point by investigation tag and optional cluster tag (omitting cluster ID is rejected when that investigation ID matches multiple clusters), requires the `ManagedBy=rosa-boundary-lambda` tag, and requires the authenticated caller's token subject to match the access point's `oidc_sub` tag — only the investigation owner may close it. The plan separates sessions still to stop from sessions already shutting down (`DesiredStatus=STOPPED`, wait-only), and lists task definitions matching a family prefix scoped to the ECS cluster, cluster ID, and investigation ID, keeping only the ones whose mounted access point actually matches (`TaskDefinitionAccessPoint`) so a similarly prefixed, unrelated investigation's definitions are never touched. If any sessions remain active or shutting down, the command refuses to continue unless `--force` or `--dry-run` is given. The plan is always printed; `--dry-run` stops there without mutating anything. Without `--yes`, the CLI prompts interactively (both Cobra argument validation and the handler itself require a terminal or `--dry-run` otherwise), then **re-resolves the plan immediately before mutating** and aborts if it changed since the prompt, to avoid acting on resources that changed concurrently.

Execution is strictly sequential and fails closed at every step — this is not a partial-progress "warn and continue" cleanup:

1. Stop each session still marked active; a single `StopTask` failure aborts immediately, reporting how many of the total were stopped.
2. Wait for `STOPPED` on both the just-stopped and already-shutting-down sessions; a wait failure also aborts (task definitions and the access point are left untouched).
3. Re-list tasks for the investigation; a new or errored task here aborts, since a session may have started during the wait.
4. Deregister each verified task definition; any individual deregistration failure aborts, leaving the access point in place.
5. Re-list tasks once more before deletion; any task found aborts and the access point is preserved.
6. Delete the EFS access point.

Every abort message reports exact partial counts (e.g. "stopped N/M sessions") and points the operator at `session list --status all` or the deployment operator to reconcile before retrying. Deleting the access point never deletes its underlying EFS directory contents — the final summary explicitly states "EFS data remains; verify audit evidence separately" — so `investigation close` is not a transactional filesystem purge.

These cleanup paths have different triggers and scopes: `investigation close` is operator-initiated, ownership-checked, and acts on one named investigation; `reap-tasks` enforces per-task deadlines; and `reap-investigations` periodically reclaims eligible investigation state. They do not invoke one another, but they share ECS/EFS state. In particular, deleting the last matching access point through `investigation close` removes the discovery record that the investigation reaper needs to locate the retained directory. The reaper enumerates access points, not orphan directories, so do not assume that close arranges a later final backup or directory deletion.

## Investigation-level garbage collection (reap-investigations)

`reap-investigations` is the investigation-level complement to the task-level `reap-tasks` reaper. It reclaims a workspace that has no matching RUNNING task and is old enough **since creation**, with a legacy exception for missing `CreatedAt`. It runs on its own EventBridge schedule (`investigation_reaper_schedule_hours`, Terraform default every 8 hours); it does not use a task's deadline or measure how long the workspace has been idle.

Each run lists every EFS access point on the shared filesystem via `describe_access_points` (no server-side tag filter — filtering happens in the handler), then for each access point:

1. Rejects access points missing the `ManagedBy=rosa-boundary-lambda` tag or missing `ClusterID`/`InvestigationID` tags, as defense-in-depth alongside the IAM policy that already restricts `DeleteAccessPoint` to that tag value.
2. Validates `ClusterID` and `InvestigationID` against an allow-list pattern and rejects `.`, `..`, or embedded `/` — the same validation style used by `create-investigation` — before either is used to build a filesystem path.
3. Verifies the access point's `RootDirectory.Path` equals the expected `/<cluster-id>/<investigation-id>`, rejecting mismatches as errors rather than silently skipping.
4. Determines staleness using an initial cluster-wide RUNNING-task snapshot whose entries are matched by `cluster_id` and `investigation_id` **tags**. A matching task prevents staleness regardless of age. With no match:
   - A present, valid `CreatedAt` must satisfy `now - CreatedAt > GRACE_PERIOD_HOURS`; equality is not stale. Terraform defaults `investigation_grace_period_hours` to 168 hours (7 days) and passes it into the Lambda environment. The handler's 72-hour fallback applies only when that environment setting is absent.
   - Missing or empty `CreatedAt` is treated as legacy investigation state and is stale immediately when no task is running, regardless of the grace-period value. The implementation does not establish an idle-duration timer or require a new grace wait for legacy data.
   - A malformed or non-comparable present timestamp is counted as a staleness-check error and skipped, not treated as the missing-tag legacy branch.
5. Re-lists RUNNING tasks for this specific investigation immediately before cleanup using the same deterministic `startedBy = sha256(cluster_id:investigation_id)[:36]` scheme as `create-investigation`. A newly found task or an API error prevents cleanup for that investigation. This final check is distinct from the initial tag-based snapshot.

`create-investigation` writes `CreatedAt` when it creates an access point; reusing that point does not refresh or backfill the tag. Restarting a task therefore does not reset the age threshold. An already-old workspace, or a reused legacy workspace missing the tag, can qualify on the next reaper run after its running task stops, with no additional idle grace period.

Cleanup has ordered steps with explicit partial-progress rules:

- **Back up, then delete the EFS directory.** The handler mounts a dedicated root access point (`aws_efs_access_point.reaper`, UID/GID 0) at `/mnt/efs`, builds the investigation path, validates its resolved location stays inside the mount root, and requires EFS to be mounted. For an existing directory, a successful upload to `s3://<bucket>/<cluster_id>/<investigation_id>/reaper-final-backup/` is mandatory before `shutil.rmtree`. Missing `S3_AUDIT_BUCKET`, upload failure, or an exceeded backup deadline blocks directory deletion. The backup excludes `.config/ocm/*` and `.kube/*` and skips symlinks. An already-absent directory is treated as successfully cleaned without requiring another backup.
- **Delete the EFS access point**, only after directory deletion succeeds — directory deletion must happen first because the access point's tags are the only record of where the directory lives, so deleting the access point first would make an undeleted directory unreclaimable.
- **Deregister task definitions** whose family matches `{TASK_DEFINITION_FAMILY}-{cluster_id}-{investigation_id}-<timestamp>`, with an exact `YYYYMMDDTHHMMSS` suffix and numeric ARN revision, avoiding neighboring-investigation prefix collisions. This step runs even if directory cleanup failed or access-point deletion was skipped/failed; it is the partial-progress step, not permission to bypass the backup or access-point ordering guards.

The handler checks the remaining-time budget before each access point and during backup traversal/uploads, reserving roughly 30 seconds where possible and allowing partial progress across invocations. These checks reduce timeout exposure; they do not make upload/deletion atomic or guarantee that a long individual upload or filesystem operation finishes before Lambda termination. Likewise, the final running-task recheck narrows a race window but is not a lock against a task starting afterward. Note the asymmetry with the CLI's `investigation close`: that command aborts the whole operation on a single step's failure, while `reap-investigations` continues to the task-definition deregistration step even when directory or access-point cleanup failed or was skipped.

## How the Lambda itself reaches ECS: packaging and container build

`create-investigation` is the trigger for everything above — a Lambda Function URL invocation (SigV4-authenticated, OIDC token validated inside the handler) that the CLI and `--connect` wiring call for both `investigation create` and `session create`. How that Lambda's own code is packaged is independent of the ECS Fargate investigation container it launches (see [Container image and task runtime](../runtime/container-image.md) for that separate build), but `deploy/regional/lambda-create-investigation.tf` supports two different packaging modes for the Lambda's own deployable artifact, selected by the `lambda_package_type` Terraform variable (`"Zip"` default, or `"Image"`):

- **ZIP packaging (default).** `data.archive_file.create_investigation_lambda` zips `lambda/create-investigation/` excluding `Containerfile`, `pyproject.toml`, `uv.lock`, tests, and other non-runtime files, and `aws_lambda_function.create_investigation_zip` deploys it with the standard `python3.11` managed runtime.
- **Container image packaging.** `aws_lambda_function.create_investigation_image` deploys from an ordinary same-account regional ECR URI (`<account>.dkr.ecr.<region>.amazonaws.com/<project>/create-investigation-lambda:<lambda_image_tag>`). This mode supports HCP Terraform remote execution and requires a non-empty **40-character lowercase commit-SHA** tag. The account Terraform root owns the source ECR repository; the regional root may create a matching destination in another Region. Building in Konflux, releasing to ECR and replicating cross-Region are separate delivery steps: verify that the image exists in the Lambda's own Region before applying a pin. See `docs/runbooks/lambda-zip-to-image-migration.md`.

`lambda/create-investigation/Containerfile` builds that optional container image using AWS's "alternative base image" approach: Red Hat UBI9 Minimal instead of the AWS-provided Lambda base, because Konflux Enterprise Contract policy rejects non-Red Hat base images. It has two stages, both from the same digest-pinned `BASE_IMAGE` to keep glibc ABI compatible with compiled wheels:

1. **`builder`** installs Python 3.11 plus `gcc`/`libffi-devel`/dev headers, copies in a pinned `uv` binary, then runs `uv export --frozen --no-dev --no-emit-project` against `pyproject.toml`/`uv.lock` to produce a pip-compatible lockfile and `pip install`s those pinned wheels into `/deps`. Exporting from the lockfile (rather than installing from `pyproject.toml` directly) keeps the image's dependency set frozen to exactly what `uv.lock` records, including transitive pins.
2. **The final stage** installs only the bare Python 3.11 interpreter (no compiler, no `pip`), copies `/deps` and `handler.py` from the builder, sets `LAMBDA_TASK_ROOT=/var/task` and `PYTHONPATH`, and runs the handler through `awslambdaric` (`ENTRYPOINT ["python3.11", "-m", "awslambdaric"]`, `CMD ["handler.lambda_handler"]`) — the pip-installed AWS Lambda Runtime Interface Client that replaces the bootstrap the official AWS base image would otherwise supply. The Containerfile deliberately omits a `USER` directive: AWS Lambda overrides the container's runtime identity with its own non-root user regardless, so a `USER` instruction would have no effect; this is unrelated to the investigation container's own `sre`-user requirement.

`pyproject.toml` pins the Lambda's runtime dependencies — `PyJWT`, `cryptography`, `requests`, `boto3`, and `awslambdaric==4.2.3` — with a separate `dev` group (`moto[ecs,efs,iam,kms,s3,sts]`, `pytest`, `pytest-cov`, `pytest-mock`) that `--no-dev`/`--no-emit-project` excludes from both the ZIP package and the container image; only `handler.py` and its pinned runtime dependencies ship. The Lambda's own `Makefile` mirrors this for local work: `make deps`/`make build`/`make package` produce the ZIP artifact (installing dependencies inside the official `public.ecr.aws/lambda/python:3.11` image for Linux-compatible wheels), while `make build-image`/`make push-image` build and publish the optional container image from the same `Containerfile`. Both packaging paths ship identical handler logic — the ZIP/image choice affects only how the Lambda's code and dependencies are delivered to AWS Lambda, not the trigger, authentication, EFS access-point, or ECS task-launch behavior documented above.

## Failure boundaries and tests

Lambda unit tests cover skip-task behavior, access-point reuse, handover guards, task definition shaping, and rollback differences for newly created versus reused access points. For the handover guard, they cover empty task details and active-session/SSM-error failures, but not a task whose container lacks `runtimeId`. `close_investigation_test.go` covers owner-tag rejection and acceptance, malformed/missing ID-token subject claims, family-prefix scoping that excludes neighboring investigations, and `sameClosePlan` detecting both a newly appeared session and a session transitioning into the shutting-down state — the checks that gate the pre-mutation re-resolve. The `reap-investigations` unit tests cover the happy-path reap, running-task and grace-period skips, strict age boundaries, legacy missing timestamps at zero/nonzero grace values, tag/path validation failures, partial-failure cleanup rules, required S3 backup configuration and failure/exclusion behavior, and pagination. A separate pytest module under `tests/unit/` checks legacy eligibility and matching-task protection, 168-hour ages, and unrelated-task filtering; the Lambda Make targets do not discover that module. See [testing and verification](../testing/verification.md). LocalStack integration tests check EFS/ECS relationships, `investigation close` ownership/ambiguity/IAM-policy scoping, task-definition family scoping, and the end-to-end deadline-tag/reaper path. Slow cases that require a task to reach `RUNNING` are skipped with LocalStack's local ECS executor.

## Related pages

- [System overview and boundaries](../architecture/system-overview.md) places the Lambda-triggered creation flow within the CLI/Lambda/ECS request path as a whole.
- [Container image and task runtime](../runtime/container-image.md) covers the separate build and runtime behavior of the ECS Fargate investigation container that `create-investigation` launches — distinct from the Lambda's own packaging covered above.
- [ROSA Boundary auditing and logging flows](../operations/audit-and-logging.md) covers how investigation sessions (ECS Exec transcripts, container shutdown sync, Lambda logs, reaper backups) are audited across this lifecycle.

## Evidence-backed claims

- Workspace-only creation uses `skip_task` to make/reuse an EFS access point without launching a task; access-point reuse requires available state, matching cluster/investigation tags, and the expected root path. [skip-task branching and access-point reuse/creation](repo://lambda/create-investigation/handler.py#L728-L872) · [path/tag verification](repo://lambda/create-investigation/handler.py#L484-L518) · [unit tests](repo://lambda/create-investigation/test_handler.py#L880-L1031)
- Task replacement uses deterministic `startedBy` discovery and checks SSM sessions only for containers with a `runtimeId`; empty task details, detected active sessions, and ECS/SSM API errors fail closed, but missing `runtimeId` skips that session lookup and can allow stopping. The handover tests cover the fail-closed cases but not missing `runtimeId`. [discovery](repo://lambda/create-investigation/handler.py#L33-L47) · [conditional session lookup and stop sequence](repo://lambda/create-investigation/handler.py#L743-L826) · [handover tests](repo://lambda/create-investigation/test_handler.py#L1418-L1693)
- The Lambda derives a per-investigation task definition with a unique family, investigation-specific EFS and task-scoped credential mounts, and launches Fargate with ECS Exec and investigation/deadline tags. [task definition registration](repo://lambda/create-investigation/handler.py#L521-L690) · [ECS launch and tags](repo://lambda/create-investigation/handler.py#L874-L1002)
- Rollback removes newly created access points, and tag-application failure also stops an already launched task; reused access points are preserved. [registration-failure cleanup](repo://lambda/create-investigation/handler.py#L895-L914) · [tag-failure cleanup](repo://lambda/create-investigation/handler.py#L1003-L1045) · [reused access-point rollback test](repo://lambda/create-investigation/test_handler.py#L2277-L2343)
- The reaper processes RUNNING tasks, stopping expired deadlines only when no active Exec session is detected, and skipping absent, future, or malformed values. [schedule](repo://deploy/regional/lambda-reap-tasks.tf#L42-L66) · [reaper behavior](repo://lambda/reap-tasks/handler.py#L48-L175)
- `session join` and `session create --connect` share one connect implementation (`connectToSession`), which waits for task and ECS Exec agent readiness before opening the SSM session and handing off to `session-manager-plugin`; the `--connect` handoff in `finishStartSession` runs after the optional OCM credential step and proceeds regardless of whether that step succeeded, only changing the printed step number; `session close` only stops the task, never the investigation. [join entrypoint](repo://internal/cmd/join_session.go#L22-L44) · [shared wait/connect sequence](repo://internal/cmd/join_session.go#L56-L111) · [finishStartSession connect handoff and result assembly](repo://internal/cmd/start_session.go#L181-L208) · [session close leaves investigation open](repo://internal/cmd/stop_session.go#L23-L88)
- `session create`'s session ID is derived from `path.Base` of the Lambda's returned task ARN rather than a dedicated identifier field, and every failure from that point on is wrapped with a cleanup-command-bearing error so the operator is pointed at the already-created task. [sessionID derivation and deferred wrapping](repo://internal/cmd/start_session.go#L79-L86) · [sessionCreationError](repo://internal/cmd/start_session.go#L210-L213)
- `runStartSession` tracks a single `credentialWarning` string across `--no-wait` launches and failed OCM credential configuration, then `finishStartSession` folds a non-empty warning into the JSON result's `warnings` array (text mode prints it immediately via `output.Warning`). [credentialWarning assignment paths](repo://internal/cmd/start_session.go#L151-L176) · [JSON warnings assembly](repo://internal/cmd/start_session.go#L197-L203)
- `investigation close` requires the authenticated caller to be the investigation owner (`oidc_sub` tag match) and a Lambda-managed access point before planning any cleanup, verifies each candidate task definition's mounted access point before including it, and requires `--force` or `--dry-run` when sessions are active or shutting down. [owner/ManagedBy checks and verified task-definition plan](repo://internal/cmd/close_investigation.go#L48-L158)
- `investigation close` re-resolves its plan immediately before mutating and aborts if the plan changed since the confirmation prompt, then executes stop/wait/deregister/delete strictly sequentially, aborting the whole command on the first failed step rather than warning and continuing; only full success reaches the final `DeleteAccessPoint` call. [fail-fast stop/wait/recheck/deregister/delete sequence](repo://internal/cmd/close_investigation.go#L102-L140)
- Investigation listing enumerates tagged EFS access points independently of whether an ECS task is running, so a workspace with no running session still appears with its lifecycle state. [tag-based listing](repo://internal/aws/efs.go#L103-L141) · [close workflow](repo://internal/cmd/close_investigation.go#L102-L140) · [list command](repo://internal/cmd/list_investigations.go#L36-L53)
- Operator-initiated `investigation close`, scheduled per-task deadline reaping (`reap-tasks`), and scheduled investigation GC (`reap-investigations`) have distinct triggers and scopes and do not invoke one another, but they act on shared ECS/EFS resource state rather than being state-independent cleanup systems. [close workflow](repo://internal/cmd/close_investigation.go#L48-L158) · [reap-investigations](repo://lambda/reap-investigations/handler.py#L85-L223) · [reap-tasks](repo://lambda/reap-tasks/handler.py#L48-L175)
- Close-investigation preserves underlying EFS directory data while deleting its access point, whereas investigation GC discovers work solely by enumerating and filtering access points; once the last matching access point is gone, that retained directory is not discoverable by this reaper's current scan, so close does not arrange a later final backup or directory purge. [access-point deletion only](repo://internal/cmd/close_investigation.go#L138-L140) · [EFS data retained in summary](repo://internal/cmd/close_investigation.go#L263-L267) · [access-point-only discovery](repo://lambda/reap-investigations/handler.py#L119-L180) · [access-point listing](repo://lambda/reap-investigations/handler.py#L432-L461)
- Investigation GC is independently scheduled and filters tagged, path-verified access points. The initial task snapshot is tag-based; eligibility requires no match plus strict creation age or missing `CreatedAt`, followed by a final `startedBy` task recheck. [schedule](repo://deploy/regional/lambda-reap-investigations.tf#L216-L239) · [tag/path validation and eligibility](repo://lambda/reap-investigations/handler.py#L134-L223) · [age and legacy branch](repo://lambda/reap-investigations/handler.py#L252-L321) · [initial task snapshot](repo://lambda/reap-investigations/handler.py#L324-L367) · [final query](repo://lambda/reap-investigations/handler.py#L402-L429)
- Successful backup is required before deleting an existing directory; access-point deletion depends on directory cleanup, while exact-family task-definition deregistration is still attempted after earlier failures — unlike `investigation close`, which aborts the whole command on the first failed step. [ordered steps](repo://lambda/reap-investigations/handler.py#L464-L520) · [backup guard](repo://lambda/reap-investigations/handler.py#L542-L547) · [path validation and traversal](repo://lambda/reap-investigations/handler.py#L662-L712) · [exact-family filtering](repo://lambda/reap-investigations/handler.py#L739-L804)
- The access-point creation timestamp is written once on creation and is not refreshed/backfilled on reuse; it is not a last-task-stop timestamp, so restarting or stopping a task never resets the investigation's creation-age threshold. [reuse and creation tags](repo://lambda/create-investigation/handler.py#L828-L872) · [age and legacy branch](repo://lambda/reap-investigations/handler.py#L252-L321)
- The Lambda reaper unit-test suite covers strict grace-period boundaries, missing timestamps at zero/nonzero grace, and backup configuration/failure guards; a separate `tests/unit/` pytest module covers legacy eligibility, matching-task protection, 168-hour ages, and unrelated-task filtering, and is not discovered by the Lambda's own Make targets. [Make targets](repo://Makefile#L174-L189) · [reaper test coverage](repo://lambda/reap-investigations/test_handler.py#L1163-L1239) · [grace-period boundary tests](repo://lambda/reap-investigations/test_handler.py#L828-L845) · [legacy-timestamp tests](repo://lambda/reap-investigations/test_handler.py#L928-L962) · [separate pytest module](repo://tests/unit/test_reap_investigations_staleness.py#L58-L160)
- The investigation reaper uses remaining-time checks between access points and during backup traversal/uploads to permit partial progress, but these do not make individual uploads or filesystem deletion atomic; its final running-task query similarly narrows, but does not close, a race with a later task launch. [deadline checks](repo://lambda/reap-investigations/handler.py#L125-L144) · [per-access-point deadline check](repo://lambda/reap-investigations/handler.py#L204-L223) · [backup traversal budget](repo://lambda/reap-investigations/handler.py#L552-L632) · [path validation](repo://lambda/reap-investigations/handler.py#L698-L712)
- The create-investigation Lambda Terraform variable selects default ZIP (Python 3.11 managed runtime) or Image packaging. Image mode derives an ordinary ECR URI in the Lambda account and Region and requires an immutable lowercase 40-character commit-SHA tag. [packaging selection](repo://deploy/regional/lambda-create-investigation.tf#L11-L41) · [image deployment](repo://deploy/regional/lambda-create-investigation.tf#L83-L136) · [variable](repo://deploy/regional/variables.tf#L121-L141)
- The account Terraform root owns the source Lambda image ECR repository; the regional root optionally creates a matching destination repository in another Region, while image-mode Lambda uses the same-account regional ECR URI. Image build, release, cross-Region replication, and Terraform pinning are separate steps. [source repository](repo://deploy/account/ecr-lambda.tf) · [destination repository](repo://deploy/regional/ecr-lambda-destination.tf#L1-L41) · [Lambda ECR reference](repo://deploy/regional/lambda-create-investigation.tf#L11-L23) · [delivery steps](repo://docs/staging-deployment.md#L121-L148)
- The optional Lambda image Containerfile uses a digest-pinned UBI9 Minimal base in both builder and final stages; the builder exports frozen runtime dependencies from `uv.lock` and installs wheels into `/deps`, while the final stage ships a bare Python 3.11 interpreter with the copied handler/dependencies and uses `awslambdaric` as the Lambda Runtime Interface Client. [stage setup](repo://lambda/create-investigation/Containerfile#L1-L35) · [builder export/install](repo://lambda/create-investigation/Containerfile#L50-L87) · [final stage entrypoint](repo://lambda/create-investigation/Containerfile#L99-L139)
- The Containerfile intentionally omits a `USER` directive because AWS Lambda always overrides the container's runtime identity with its own non-root user regardless of what the image specifies, which is unrelated to the separate ECS Fargate investigation container's own `sre`-user privilege-drop requirement. [no USER directive](repo://lambda/create-investigation/Containerfile#L21-L26)
- `pyproject.toml` pins runtime dependencies (`PyJWT`, `cryptography`, `requests`, `boto3`, `awslambdaric==4.2.3`) separately from a `dev` dependency group (`moto[ecs,efs,iam,kms,s3,sts]`, `pytest`, `pytest-cov`, `pytest-mock`); both the ZIP export and the container-image builder stage use `--no-dev --no-emit-project` so only runtime dependencies and `handler.py` ship in either packaging mode. [ZIP exclusions](repo://deploy/regional/lambda-create-investigation.tf#L26-L51) · [builder export flags](repo://lambda/create-investigation/Containerfile#L82-L86) · [dependency groups](repo://lambda/create-investigation/pyproject.toml#L1-L18)
- The Lambda's own `Makefile` builds the ZIP artifact by installing dependencies inside the official `public.ecr.aws/lambda/python:3.11` image for Linux-compatible wheels (`make deps`/`build`/`package`), and separately builds and pushes the optional container image from the same `Containerfile` via `build-image`/`push-image`; both packaging paths ship identical `handler.py` logic, so the ZIP/image choice affects only delivery of the Lambda's code, not its trigger, authentication, EFS access-point, or ECS task-launch behavior. [image targets](repo://lambda/create-investigation/Makefile#L144-L162) · [ZIP build targets](repo://lambda/create-investigation/Makefile#L54-L120)

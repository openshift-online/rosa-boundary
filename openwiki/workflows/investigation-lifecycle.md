---
type: workflow
title: Investigation lifecycle
description: Traces investigation workspace creation, session launch/handover, operator connection, timeout enforcement, the close command's audit-receipt safety model, garbage collection, and closing across the CLI, Lambda, ECS, and EFS, including how the create-investigation Lambda's own ZIP/container-image packaging fits into the trigger path.
tags: [investigations, lifecycle, ecs, efs, workflow, garbage-collection, lambda, container-build, audit-escrow]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-25T19:00:35.491Z
sources:
  - id: openwiki-source-d26615a0354c146aa6f23c2c
    resource: repo://deploy/account/ecr-lambda.tf
  - id: openwiki-source-b84818c3b6429e491a77175c
    resource: repo://deploy/regional/ecr-lambda-destination.tf
  - id: openwiki-source-84177eee21b0f3eb77df526a
    resource: repo://deploy/regional/iam.tf
  - id: openwiki-source-d176128a85129af793772942
    resource: repo://deploy/regional/lambda-create-investigation.tf
  - id: openwiki-source-81b84da9542934c33f2e42d7
    resource: repo://deploy/regional/lambda-reap-investigations.tf
  - id: openwiki-source-527b127f4d59725c0085dfbf
    resource: repo://docs/staging-deployment.md
  - id: openwiki-source-d2f66eb6a0ccf1ed7a35e866
    resource: repo://internal/cmd/cli.go
  - id: openwiki-source-3eb89a64c83d3140ea6ba8c4
    resource: repo://internal/cmd/close_investigation.go
  - id: openwiki-source-d76b37adadbf60c56bb7ff4d
    resource: repo://internal/cmd/join_session.go
  - id: openwiki-source-2452fe2ff931e1490d573519
    resource: repo://internal/cmd/start_session.go
  - id: openwiki-source-ded7ace1e37f1ab771ccaf0b
    resource: repo://lambda/create-investigation/Containerfile
  - id: openwiki-source-253b57ec87256e726a724093
    resource: repo://lambda/create-investigation/handler.py
  - id: openwiki-source-ae0e11fbe7ed89eafcab9312
    resource: repo://lambda/create-investigation/Makefile
  - id: openwiki-source-a26915e357fc9eaad3cc4090
    resource: repo://lambda/create-investigation/pyproject.toml
  - id: openwiki-source-53ded000b5419d48efde6aba
    resource: repo://lambda/reap-investigations/close_finalization.py
  - id: openwiki-source-d796a031add13f67891a2f24
    resource: repo://lambda/reap-investigations/handler.py
  - id: openwiki-source-13a9df7e50feb98129809599
    resource: repo://lambda/reap-investigations/test_close_finalization.py
  - id: openwiki-source-6e447421bb9d1456afb165d9
    resource: repo://lambda/reap-tasks/handler.py
generated: { by: "pi", at: "2026-11-25T19:00:35.491Z" }
---

# Investigation lifecycle

## Create a workspace or a session

Workspace-only creation returns the access point without registering or launching a task. Access-point discovery scans all pages for admission blockers at the expected path and rejects ambiguous matches. Handover requires known different ownership and confirmed absence of attached shells before stopping an existing task. Same-owner tasks are not replaced. Task launch registers an investigation-specific definition and supplies ECS Exec, deterministic startedBy and ownership tags. Rollback attempts to stop a task after tagging failure and deregister its generated definition; cleanup distinguishes new access points from reused ones. The CLI takes the session ID from the task ARN and reports it for follow-up after launch.

## Connect and inspect

Session create and join share the connection path that checks admission and ECS Exec readiness. After task launch, optional OCM setup and Backplane login can report warnings. Backplane login failure does not mean the task vanished; JSON can carry the warning with the session result.

## Close a session versus an investigation

The session reaper applies an eight-hour cap to identified, dated investigation tasks. The configurable shorter timeout protects attached sessions; older tasks can use deadline tags. An investigation workspace can outlive its last task. Closing the investigation is a request to the close service, not direct CLI deletion. Scheduled discovery checks workspace identifiers and paths and distinguishes idle eligibility from expiry. Expiry closes admission, not a live shell. The finalizer copies and independently verifies workspace evidence before cleanup. A missing source is not evidence of an empty workspace. Operator close requests and scheduled investigation cleanup use the same finalizer; stopping a session task is a separate operation. CreatedAt belongs to the access point, not to a replacement session: reusing a workspace does not reset its creation time. Normal verified close retains the EFS directory. Only stale reclamation can remove it, subject to its own controls. The CLI previews and submits a close request. --status reads progress without requesting work; --wait observes completion and ending that wait does not cancel the request. Finalizer tests distinguish empty from missing workspaces, bind receipts to attempts, and block sealing while shells are attached. Finalization reserves Lambda time before mutation and checks the remaining budget during copy; exhausting the budget is not proof of verification. The service publishes an attempt-bound receipt only for verified evidence. The operator does not author this receipt. IAM distinguishes the shared role's verified-seal deletion condition from the reaper's separately scoped cleanup permissions. See [verified closure](verified-closure.md) for interpreting request status and cleanup.

## How the Lambda itself reaches ECS: packaging and container build

`create-investigation` is the trigger for everything above — a direct SDK invocation authenticated with invoker-role credentials and a separately validated OIDC token. How that Lambda's own code is packaged is independent of the ECS Fargate investigation container it launches (see [Container image and task runtime](../runtime/container-image.md) for that separate build), but `deploy/regional/lambda-create-investigation.tf` supports two different packaging modes for the Lambda's own deployable artifact, selected by the `lambda_package_type` Terraform variable (`"Zip"` default, or `"Image"`):

- **ZIP packaging (default).** `data.archive_file.create_investigation_lambda` zips `lambda/create-investigation/` excluding `Containerfile`, `pyproject.toml`, `uv.lock`, tests, and other non-runtime files, and `aws_lambda_function.create_investigation_zip` deploys it with the standard `python3.11` managed runtime.
- **Container image packaging.** `aws_lambda_function.create_investigation_image` deploys from an ordinary same-account regional ECR URI (`<account>.dkr.ecr.<region>.amazonaws.com/<project>/create-investigation-lambda:<lambda_image_tag>`). This mode supports HCP Terraform remote execution and requires a non-empty **40-character lowercase commit-SHA** tag. The account Terraform root owns the source ECR repository; the regional root may create a matching destination in another Region. Building in Konflux, releasing to ECR and replicating cross-Region are separate delivery steps: verify that the image exists in the Lambda's own Region before applying a pin. See `docs/runbooks/lambda-zip-to-image-migration.md`.

`lambda/create-investigation/Containerfile` builds that optional container image using AWS's "alternative base image" approach: Red Hat UBI9 Minimal instead of the AWS-provided Lambda base, because Konflux Enterprise Contract policy rejects non-Red Hat base images. It has two stages, both from the same digest-pinned `BASE_IMAGE` to keep glibc ABI compatible with compiled wheels:

1. **`builder`** installs Python 3.11 plus `gcc`/`libffi-devel`/dev headers, copies in a pinned `uv` binary, then runs `uv export --frozen --no-dev --no-emit-project` against `pyproject.toml`/`uv.lock` to produce a pip-compatible lockfile and `pip install`s those pinned wheels into `/deps`. Exporting from the lockfile (rather than installing from `pyproject.toml` directly) keeps the image's dependency set frozen to exactly what `uv.lock` records, including transitive pins.
2. **The final stage** installs only the bare Python 3.11 interpreter (no compiler, no `pip`), copies `/deps` and `handler.py` from the builder, sets `LAMBDA_TASK_ROOT=/var/task` and `PYTHONPATH`, and runs the handler through `awslambdaric` (`ENTRYPOINT ["python3.11", "-m", "awslambdaric"]`, `CMD ["handler.lambda_handler"]`) — the pip-installed AWS Lambda Runtime Interface Client that replaces the bootstrap the official AWS base image would otherwise supply. The Containerfile deliberately omits a `USER` directive: AWS Lambda overrides the container's runtime identity with its own non-root user regardless, so a `USER` instruction would have no effect; this is unrelated to the investigation container's own `sre`-user requirement.

`pyproject.toml` pins the Lambda's runtime dependencies — `PyJWT`, `cryptography`, `requests`, `boto3`, and `awslambdaric==4.2.3` — with a separate `dev` group (`moto[ecs,efs,iam,kms,s3,sts]`, `pytest`, `pytest-cov`, `pytest-mock`) that `--no-dev`/`--no-emit-project` excludes from both the ZIP package and the container image; only `handler.py` and its pinned runtime dependencies ship. The Lambda's own `Makefile` mirrors this for local work: `make deps`/`make build`/`make package` produce the ZIP artifact (installing dependencies inside the official `public.ecr.aws/lambda/python:3.11` image for Linux-compatible wheels), while `make build-image`/`make push-image` build and publish the optional container image from the same `Containerfile`. Both packaging paths ship identical handler logic — the ZIP/image choice affects only how the Lambda's code and dependencies are delivered to AWS Lambda, not the trigger, authentication, EFS access-point, or ECS task-launch behavior documented above.

Both packaging paths need the close-request helper alongside the handler. Development and test dependencies are separate from runtime dependencies.

## Related pages

- [System overview and boundaries](../architecture/system-overview.md) places the Lambda-triggered creation flow within the CLI/Lambda/ECS request path as a whole.
- [Identity and access](../architecture/identity-and-access.md) covers the shared SRE role, ABAC conditions, and the IAM policies (including the `AuditCloseSeal`/`AuditCloseVerified` conditions) referenced above.
- [Regional runtime infrastructure](../infrastructure/regional-runtime.md) details the EFS mounts, IAM conditions, and ordered reaping steps that back this page's GC description.
- [Container image and task runtime](../runtime/container-image.md) covers the separate build and runtime behavior of the ECS Fargate investigation container that `create-investigation` launches — distinct from the Lambda's own packaging covered above.
- [ROSA Boundary auditing and logging flows](../operations/audit-and-logging.md) covers how investigation sessions (ECS Exec transcripts, container shutdown sync, Lambda logs, reaper backups, and the close receipt) are audited across this lifecycle.
- [Testing and verification](../testing/verification.md) covers the unit, Make-target, and LocalStack integration coverage summarized above.

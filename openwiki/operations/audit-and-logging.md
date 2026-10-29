---
type: operational-reference
title: ROSA Boundary auditing and logging flows
description: Inventories the evidence produced by ROSA Boundary, explains its contents, access paths, retention and protection controls — including the Git-managed log_retention_days workspace variable — and identifies audit-coverage boundaries.
tags: [audit, logging, operations, cloudwatch, s3, cloudtrail, bedrock]
verified:
  - by: openwiki/0.7.1
    at: 2026-10-29T16:03:33.678Z
sources:
  - id: openwiki-source-6b03d2d17a5b9eb3f358798b
    resource: repo://deploy/account/modules/shared-iam/bedrock-logging.tf
  - id: openwiki-source-45393b666c4d8ce854ed025b
    resource: repo://deploy/account/README.md
  - id: openwiki-source-43a5f7fe8e3da821d41a4dba
    resource: repo://deploy/regional/bedrock-large-payloads.tf
  - id: openwiki-source-86eaa81471e45a1fc5290cf1
    resource: repo://deploy/regional/bedrock-logging.tf
  - id: openwiki-source-f1bd1e0a9201f149b775a09c
    resource: repo://deploy/regional/ecs.tf
  - id: openwiki-source-84177eee21b0f3eb77df526a
    resource: repo://deploy/regional/iam.tf
  - id: openwiki-source-d176128a85129af793772942
    resource: repo://deploy/regional/lambda-create-investigation.tf
  - id: openwiki-source-81b84da9542934c33f2e42d7
    resource: repo://deploy/regional/lambda-reap-investigations.tf
  - id: openwiki-source-a7f1ddde1efa89d5bfad2d5c
    resource: repo://deploy/regional/lambda-reap-tasks.tf
  - id: openwiki-source-a467cf2af07b3f58e60a50ab
    resource: repo://deploy/regional/main.tf
  - id: openwiki-source-dcec1f4680246d4606ff71f8
    resource: repo://deploy/regional/s3.tf
  - id: openwiki-source-a055ff9a3fcbd2c0a0fc4ee2
    resource: repo://deploy/regional/variables.tf
  - id: openwiki-source-906e68a1845a7f4a2e8058f4
    resource: repo://docs/configuration/aws-iam-policies.md
  - id: openwiki-source-96d2d2466918222634b57b14
    resource: repo://docs/runbooks/audit-log-access.md
  - id: openwiki-source-e9906b078522ed0a08c64ff1
    resource: repo://entrypoint.sh
  - id: openwiki-source-81722021d767635aca673ab8
    resource: repo://hcp-terraform/rosa-boundary/main.tf
  - id: openwiki-source-d796a031add13f67891a2f24
    resource: repo://lambda/reap-investigations/handler.py
  - id: openwiki-source-6e447421bb9d1456afb165d9
    resource: repo://lambda/reap-tasks/handler.py
  - id: openwiki-source-11b94eb82fd3f4795e9f0e3b
    resource: repo://tests/localstack/integration/test_s3_audit.py
  - id: openwiki-source-b696734e098932f3853bbb51
    resource: repo://tests/shell/entrypoint.bats
generated: { by: "openwiki/0.7.1", at: "2026-10-29T16:03:33.678Z" }
---

# ROSA Boundary auditing and logging flows

ROSA Boundary does not produce one complete audit record. Evidence is split between CloudWatch Logs, an S3 workspace escrow copy, AWS control-plane records, task tags, and (when Claude Code uses Bedrock) model-invocation payload logs. The streams have different contents, retention, and access paths. Use the AWS account and Region where the Boundary regional stack is deployed; substitute its actual project/stage names and configured retention overrides for the `rosa-boundary-dev` examples below.

Staging declares separate `us-east-1` and `us-west-2` regional workspaces. Log-group names such as `/ecs/rosa-boundary-stage/ssm-sessions` do not encode the Region and can be the same in both; select the correct AWS Region when querying. Audit-bucket names include the account and Region (`<account>-<project>-<stage>-<region>`). The [audit log access runbook](../../docs/runbooks/audit-log-access.md) provides the approved access-request and SAML-login procedure; it does not establish that a deployment or trail is live.

## Evidence inventory

| Evidence source | What it records | Where to find it |
|---|---|---|
| ECS Exec session transcript | Session input and output for interactive ECS Exec sessions. It can contain commands, terminal output, cluster/customer identifiers, and accidental secrets. | CloudWatch log group `/ecs/<project>-<stage>/ssm-sessions`; streams are created by ECS Exec. |
| Container and sidecar output | `stdout`/`stderr` emitted by the main container (entrypoint warnings/status and workload output) and optional `kube-proxy` sidecar. This is not a filesystem snapshot. | CloudWatch log group `/ecs/<project>-<stage>`; stream prefixes are `rosa-boundary` and `kube-proxy`. |
| Create-investigation Lambda | Request-header keys/values after redaction of `Authorization` and `X-OIDC-Token`, OIDC validation and group authorization outcomes, user/subject and investigation identifiers, resource/task lifecycle messages, and errors. The handler does not log the raw request body or OIDC token in its normal messages. | `/aws/lambda/<project>-<stage>-create-investigation`. |
| Task-timeout reaper Lambda (reap-tasks) | Scheduled checks, running-task counts, expired task IDs/deadlines, stop outcomes, skipped tasks, and errors; its result also summarizes checked/stopped/skipped/error counts. | `/aws/lambda/<project>-<stage>-reap-tasks`. |
| Investigation reaper Lambda (reap-investigations) | Eligibility checks, cleanup outcomes, and a checked/reaped/skipped/error summary. With no matching RUNNING task, creation age must exceed `GRACE_PERIOD_HOURS`, or `CreatedAt` must be missing (legacy cleanup without a grace wait). Terraform defaults to 168h/7 days; the handler falls back to 72h only if the environment setting is absent. Expected S3 upload-failure messages omit raw file paths and object keys, but normal backup/deletion messages and other error paths can contain directory paths, prefixes, and investigation identifiers. | `/aws/lambda/<project>-<stage>-reap-investigations`. |
| Investigation S3 escrow (shutdown sync) | A best-effort copy of eligible `/home/sre` files on container shutdown: e.g. shell history, notes, and downloaded/workspace files. It is a point-in-time shutdown sync, not a live filesystem journal. | The investigation audit bucket, under `<cluster-id>/<investigation-id>/<YYYYMMDD>/<task-id>/`. |
| Investigation S3 escrow (reaper final backup) | A best-effort full copy of the EFS investigation directory that the reap-investigations Lambda uploads immediately before deleting that directory, using the same `.config/ocm/*`/`.kube/*` exclusions as the shutdown sync and skipping symlinks. If the backup fails or times out, the Lambda refuses to delete the directory that cycle, leaving it for a later run. | The investigation audit bucket, under `<cluster-id>/<investigation-id>/reaper-final-backup/`. |
| Bedrock invocation payloads | Text model request/response payloads for Bedrock Runtime callers in the AWS account and Region—not only Boundary tasks. CloudWatch receives text payloads up to 100 KB; larger payloads go to a separate S3 bucket. Image, embedding, and video delivery are disabled by this configuration. | CloudWatch `/aws/bedrock/<project>-<stage>/model-invocations` and the separate `<audit-bucket>-bedrock-invocations` bucket under `large-data/`. |
| AWS control-plane activity | AWS API management events such as role assumptions, Lambda invocations, ECS task operations, and ECS Exec can be available through CloudTrail. S3 object-level reads/writes require data-event recording to be enabled for the relevant bucket. | AWS CloudTrail Event history or the organization/account's configured trail or CloudTrail Lake. The regional Terraform here does not establish that account-level CloudTrail configuration. |
| ECS task tags | Task metadata such as OIDC subject, ABAC identity, cluster/investigation IDs, selected `oc_version`, access-point ID, creation time, timeout, and deadline. Tags help correlate records; they are not a durable log stream. | `aws ecs describe-tasks ... --include TAGS` while ECS retains the task details; task tags are also part of relevant CloudTrail API event records when captured. |

## How to retrieve the records

CloudWatch access requires IAM permissions such as `logs:DescribeLogStreams` and `logs:GetLogEvents`/`logs:FilterLogEvents`; use an approved read role rather than broadening the task role. For example:

```bash
REGION=us-east-2
STAGE=dev

# Recent ECS Exec transcript streams
aws logs describe-log-streams \
  --log-group-name "/ecs/rosa-boundary-${STAGE}/ssm-sessions" \
  --order-by LastEventTime --descending --max-items 20 --region "${REGION}"

# Follow session records or inspect the container output
aws logs tail "/ecs/rosa-boundary-${STAGE}/ssm-sessions" --follow --region "${REGION}"
aws logs tail "/ecs/rosa-boundary-${STAGE}" --follow --region "${REGION}"

# Inspect a Lambda's logs (replace with the deployed function name)
aws logs tail "/aws/lambda/rosa-boundary-${STAGE}-create-investigation" \
  --since 1h --region "${REGION}"
```

The actual Lambda group name includes the configured `project` and `stage`. CloudWatch log streams can also be inspected in **CloudWatch → Logs → Log groups**. Treat session transcripts and Bedrock payload logs as sensitive content; access should be limited to operational/compliance readers with a need to investigate.

To inspect the S3 workspace snapshot, use a separate approved read-only compliance role and list the investigation prefix (the deployed bucket name is defined by the regional Terraform configuration):

```bash
aws s3 ls "s3://<audit-bucket>/<cluster-id>/<investigation-id>/" \
  --recursive --region "${REGION}"
aws s3 cp "s3://<audit-bucket>/<cluster-id>/<investigation-id>/<date>/<task-id>/<key>" - \
  --region "${REGION}"
```

The task role is designed for audit-bucket writes (`PutObject`, plus `ListBucket`); it is not the reader role. The [access runbook](../../docs/runbooks/audit-log-access.md#access-model) describes a separately managed `rosa-boundary-audit-reader` role for read-only S3 access, requested through an app-interface user-role assignment and used through SAML login. It warns not to use `--assume-uid` with the scoped role. This repository's account baseline does not create that reader role, and the runbook explicitly says it does **not** provide CloudWatch Logs read access: arrange that separately before using the log commands above. Do not broaden the investigation task role or use administrator credentials merely to read artifacts.

CloudTrail Event history can be searched by event name, user, and time; availability and S3 data-event coverage depend on the account/organization trail configuration. The runbook's access procedure and general CloudTrail wording are not evidence that object-level reads or writes are being captured in the selected account.

For Bedrock text payloads, query the dedicated CloudWatch log group with the same CloudWatch Logs tools above. Retrieve larger objects from the separate Bedrock payload bucket only through restricted read access. This bucket is distinct from the investigation escrow bucket and does not inherit the investigation bucket's Object Lock configuration.

Bedrock delivery also depends on shared account-role trust. Account Terraform retains `aws:SourceAccount` and permits only the `bedrock_logging_source_regions` list in `aws:SourceArn`; staging explicitly lists east and west. Each regional stack still defines its own encrypted CloudWatch destination, large-payload bucket and inline logging grant. A shared role does not combine regional logs, and adding a region to trust is not proof of successful delivery. Check the configured source Region and both destination types when investigating gaps.

The `rosa-boundary-prod-account` HCP Terraform workspace (`deploy/account`) already sets `bedrock_logging_source_regions = ["us-east-1", "us-west-2"]`, pre-authorizing both planned production source Regions in the shared Bedrock logging role's trust policy. As of this writing, the HCP Terraform configuration defines only `rosa-boundary-prod-account` and `rosa-boundary-prod-aws-creds` for the prod stage — no `rosa-boundary-prod-regional` (or similarly named regional) workspace exists yet. This means the trust-policy authorization is forward-looking account-level preparation, not evidence that a production regional stack, its CloudWatch destination, or its Bedrock payload pipeline is deployed or capturing data. Do not treat this entry as proof of a live production audit pipeline.

## Collection, retention, and protection

- ECS Exec logging is set to `OVERRIDE` at the cluster, sends transcripts to the dedicated session group, and enables CloudWatch encryption with the ECS Exec KMS key. That group uses `retention_days` (default 90 days). Its access is security-sensitive because session content can include anything typed or printed in the terminal.
- Container and Lambda log groups — including create-investigation, reap-tasks, and reap-investigations — use `log_retention_days`; the reap-investigations group is provisioned the same way as the other two Lambda groups and is not given any longer-lived override. Workspace escrow and Bedrock payload logging use the separate `retention_days` variable (default 90 days). HCP Terraform/workspace values can override `log_retention_days`; confirm the deployed value before relying on a retention period.
- `deploy/regional/variables.tf` defines `log_retention_days` with a Terraform-level default of **7 days**, independent of the 90-day default on `retention_days`. That 7-day default only governs a deployment if no HCP Terraform workspace overrides it. For the two deployed staging regional workspaces, it does not: the Git-managed HCP Terraform configuration sets `log_retention_days = 90` for both `rosa-boundary-stage-regional` (the `us-east-1` workspace) and `rosa-boundary-stage-regional-us-west-2` (the `us-west-2` workspace), so the `/ecs/<project>-<stage>` container group, the create-investigation Lambda group, and the reap-tasks Lambda group all actually retain 90 days of logs in staging — matching, not diverging from, the 90-day `retention_days` default used by the ECS Exec session group, the Bedrock invocation group, and the S3 Object Lock retention. Treat the workspace variable, not the Terraform variable default, as authoritative for any deployment driven by this HCP Terraform configuration; for a deployment without such an override (e.g. a bare `terraform apply` with no workspace variable set), the 7-day variable default governs instead.
- The investigation S3 bucket has versioning, default compliance-mode Object Lock retention, public-access blocking, AES-256 server-side encryption, and a bucket policy denying non-TLS requests. Optional cross-account replication is controlled by Terraform inputs. The Bedrock large-payload bucket is separate: it blocks public access, uses AES-256 encryption, denies non-TLS requests, and has lifecycle expiration, but does not configure versioning or Object Lock.
- On normal process exit or trapped `SIGTERM`, `SIGINT`, or `SIGHUP`, the entrypoint attempts `aws s3 sync /home/sre`. It auto-builds the prefix from `S3_AUDIT_BUCKET`, `CLUSTER_ID`, `INVESTIGATION_ID`, the date, and ECS task ID unless `S3_AUDIT_ESCROW` is supplied directly. Missing configuration, a failed sync, or a timeout produces a warning; the container can still exit. The sync is therefore best-effort, not a guaranteed finalization transaction. Terraform gives the ECS container a 120-second stop timeout while `SYNC_TIMEOUT` defaults to 300 seconds, so do not assume a shutdown sync always finishes before ECS terminates the container.
- The sync excludes `.config/ocm/*` and `.kube/*` and uses `--no-follow-symlinks`, so credential-bearing OCM/kubeconfig trees and symlink targets are not copied into workspace escrow. Those directories are also task-scoped mounts that disappear with the task. This exclusion does not remove those credentials from an interactive transcript or Bedrock payload if a user/tool prints or submits them there; avoid entering secrets into logged sessions and model prompts.

## Coverage boundaries and operating cautions

- The S3 snapshots (both the container's shutdown sync and the investigation reaper's pre-deletion backup) record eligible workspace files only at those two specific moments. Neither records every file operation, provides continuous backup, or establishes who read an object. Use CloudTrail S3 data events if object-level access auditing is required.
- Reaper cleanup uses investigation **creation age**, not time since the last task stopped. An already-old workspace, or an idle legacy workspace missing `CreatedAt`, can be eligible on the next scheduled run immediately after a task stops. A malformed timestamp is a staleness-check error, not the legacy missing-tag branch. Backup failure or missing S3 backup configuration blocks deletion of an existing directory, but stopping or closing a task is not by itself proof that a snapshot was captured. See [investigation lifecycle](../workflows/investigation-lifecycle.md#investigation-level-garbage-collection-reap-investigations).
- EFS is persistent investigation workspace storage, not an audit log or file-change journal. ECS task tags are useful correlation metadata but are not a substitute for retained CloudWatch/CloudTrail records.
- This repository provisions CloudWatch groups for ECS, Lambda, and Bedrock, but does not provision an AWS CloudTrail trail/event data store. Confirm account-level CloudTrail coverage with the AWS account owner rather than assuming every API call or S3 object access is recorded.
- The repository deploys Keycloak on OpenShift, but does not configure a central Keycloak authentication-event export in this AWS logging stack. The docs' operator-log command (`oc logs -n keycloak deployment/rhbk-operator`) is for troubleshooting the operator, not a complete end-user login audit history.
- The Go CLI's OIDC token cache is operational credential state, not an audit trail. Similarly, Container Insights provides ECS telemetry/metrics and should not be mistaken for terminal or API audit records.
- LocalStack integration tests exercise the S3 audit bucket controls and sync exclusion behavior. They do not verify real ECS Exec transcript delivery, production CloudTrail configuration, or Bedrock account-wide payload capture; those require deployed-environment checks.
- The `rosa-boundary-prod-account` workspace pre-authorizes `us-east-1` and `us-west-2` as Bedrock logging source Regions before any prod regional workspace exists. Treat this strictly as advance account-level preparation; it is not evidence of a running prod ECS/Lambda/Bedrock audit pipeline, which this page otherwise documents only for staging and dev-style regional deployments.

## Evidence-backed claims

- ECS Exec output is overridden to a dedicated CloudWatch group with encryption enabled and the session group uses the configured retention period; container stdout/stderr uses a separate group with `rosa-boundary` and `kube-proxy` stream prefixes. [ECS cluster and groups](repo://deploy/regional/ecs.tf#L1-L40) · [container log drivers](repo://deploy/regional/ecs.tf#L103-L168)
- Create-investigation and reaper Lambdas each have named CloudWatch groups using `log_retention_days`; the handlers emit identity/authorization/resource lifecycle and reaper task/deadline outcome messages, including deferred stops for active Exec sessions. [create-investigation group](repo://deploy/regional/lambda-create-investigation.tf#L1-L9) · [create-investigation logging](repo://lambda/create-investigation/handler.py#L88-L94) · [reaper group](repo://deploy/regional/lambda-reap-tasks.tf#L1-L9) · [reaper outcomes](repo://lambda/reap-tasks/handler.py#L110-L175)
- Entry-point shutdown sync builds a task-specific audit prefix or accepts an explicit URI, excludes OCM/kubeconfig state, avoids following symlinks, and warns rather than blocking indefinitely when sync fails. [sync implementation](repo://entrypoint.sh#L3-L34) · [signals and normal exit](repo://entrypoint.sh#L167-L183) · [task stop timeout](repo://deploy/regional/ecs.tf#L103-L110)
- The investigation audit bucket combines versioning and compliance Object Lock with public-access blocking, AES-256 encryption, TLS-only access, and optional cross-account replication; task IAM permits writes rather than providing the compliance read path. [bucket controls](repo://deploy/regional/s3.tf#L1-L73) · [replication](repo://deploy/regional/s3.tf#L75-L120) · [task S3 policy](repo://deploy/regional/iam.tf#L42-L58)
- Bedrock invocation logging sends text payloads account/Region-wide to encrypted CloudWatch Logs and larger text payloads to a separate S3 bucket; other modalities are disabled. [invocation configuration](repo://deploy/regional/bedrock-logging.tf#L56-L85) · [large-payload bucket controls](repo://deploy/regional/bedrock-large-payloads.tf#L1-L51)
- S3 sync tests verify that nested OCM and kubeconfig files are excluded while ordinary workspace controls remain eligible, including checks for token/account-response canaries. [shell sync tests](repo://tests/shell/entrypoint.bats#L88-L174) · [LocalStack audit sync test](repo://tests/localstack/integration/test_s3_audit.py#L114-L177)
- The investigation reaper logs eligibility reasons, directory/access-point cleanup, task-definition deregistration counts, and summary counters. Expected S3 upload-error messages avoid raw paths/keys, but other normal/error messages retain operational identifiers and paths. [log group](repo://deploy/regional/lambda-reap-investigations.tf#L1-L9) · [staleness and summary logging](repo://lambda/reap-investigations/handler.py#L104-L249) · [upload failure messages](repo://lambda/reap-investigations/handler.py#L641-L659) · [directory messages](repo://lambda/reap-investigations/handler.py#L687-L712)
- Matching running tasks block GC; otherwise timestamped workspaces use strict creation age and missing timestamps take the legacy branch. Handler fallback and Terraform defaults are distinct. [eligibility](repo://lambda/reap-investigations/handler.py#L179-L223) · [age and legacy logic](repo://lambda/reap-investigations/handler.py#L252-L321) · [environment wiring](repo://deploy/regional/lambda-reap-investigations.tf#L184-L192) · [Terraform default](repo://deploy/regional/variables.tf#L413-L422)
- Bedrock's shared delivery-role trust explicitly restricts source account/regions, while destinations remain regional. [service trust](repo://deploy/account/modules/shared-iam/bedrock-logging.tf#L1-L28) · [staging approvals](repo://hcp-terraform/rosa-boundary/main.tf#L197-L207) · [regional destinations](repo://deploy/regional/bedrock-logging.tf#L48-L85)
- Before deleting a stale investigation's EFS directory, the reap-investigations Lambda uploads a best-effort backup of that directory to the audit bucket under `<cluster-id>/<investigation-id>/reaper-final-backup/`, reusing the `.config/ocm/*`/`.kube/*` exclusions and symlink-skipping behavior of the container's shutdown sync, and it refuses to delete the directory if the backup fails or times out. [backup-then-delete ordering](repo://lambda/reap-investigations/handler.py#L660-L710) · [exclusions and symlink handling](repo://lambda/reap-investigations/handler.py#L580-L637) · [scoped S3 IAM grant](repo://deploy/regional/lambda-reap-investigations.tf#L96-L125)
- `deploy/regional/variables.tf` defaults `log_retention_days` to 7 days, but the Git-managed HCP Terraform configuration overrides it to 90 days for both staging regional workspaces (`rosa-boundary-stage-regional` in `us-east-1` and `rosa-boundary-stage-regional-us-west-2` in `us-west-2`), so the deployed container, create-investigation, and reap-tasks CloudWatch log groups in staging retain 90 days of logs — matching the separate `retention_days` variable's 90-day default rather than the 7-day `log_retention_days` default. [variable default](repo://deploy/regional/variables.tf#L195-L204) · [east workspace override](repo://hcp-terraform/rosa-boundary/main.tf#L322-L352) · [west workspace override](repo://hcp-terraform/rosa-boundary/main.tf#L515-L556) · [west log_retention_days value](repo://hcp-terraform/rosa-boundary/main.tf#L686-L690) · [log groups consuming the variable](repo://deploy/regional/ecs.tf#L25-L31) · [create-investigation group](repo://deploy/regional/lambda-create-investigation.tf#L1-L9) · [reap-tasks group](repo://deploy/regional/lambda-reap-tasks.tf#L1-L9)
- The `rosa-boundary-prod-account` HCP Terraform workspace pre-authorizes `bedrock_logging_source_regions = ["us-east-1", "us-west-2"]` in the account-level shared Bedrock logging trust policy, while the HCP Terraform configuration defines no prod regional workspace yet; this is forward-looking authorization rather than a live production logging pipeline. [prod account Bedrock regions](repo://hcp-terraform/rosa-boundary/main.tf#L712-L876)

---
type: operational-reference
title: ROSA Boundary auditing and logging flows
description: Inventories the evidence produced by ROSA Boundary, explains its contents, access paths, retention and protection controls, and identifies audit-coverage boundaries.
tags: [audit, logging, operations, cloudwatch, s3, cloudtrail, bedrock]
sources:
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
  - id: openwiki-source-a7f1ddde1efa89d5bfad2d5c
    resource: repo://deploy/regional/lambda-reap-tasks.tf
  - id: openwiki-source-dcec1f4680246d4606ff71f8
    resource: repo://deploy/regional/s3.tf
  - id: openwiki-source-906e68a1845a7f4a2e8058f4
    resource: repo://docs/configuration/aws-iam-policies.md
  - id: openwiki-source-e9906b078522ed0a08c64ff1
    resource: repo://entrypoint.sh
  - id: openwiki-source-6e447421bb9d1456afb165d9
    resource: repo://lambda/reap-tasks/handler.py
  - id: openwiki-source-11b94eb82fd3f4795e9f0e3b
    resource: repo://tests/localstack/integration/test_s3_audit.py
  - id: openwiki-source-b696734e098932f3853bbb51
    resource: repo://tests/shell/entrypoint.bats
generated: { by: "opencode", at: "2026-10-09T17:13:47.426Z" }
verified:
  - by: openwiki/0.7.0
    at: 2026-10-09T17:13:47.426Z
---

# ROSA Boundary auditing and logging flows

ROSA Boundary does not produce one complete audit record. Evidence is split between CloudWatch Logs, an S3 workspace escrow copy, AWS control-plane records, task tags, and (when Claude Code uses Bedrock) model-invocation payload logs. The streams have different contents, retention, and access paths. Use the AWS account and Region where the Boundary regional stack is deployed; substitute its actual project/stage names and configured retention overrides for the `rosa-boundary-dev` examples below.

## Evidence inventory

| Evidence source | What it records | Where to find it |
|---|---|---|
| ECS Exec session transcript | Session input and output for interactive ECS Exec sessions. It can contain commands, terminal output, cluster/customer identifiers, and accidental secrets. | CloudWatch log group `/ecs/<project>-<stage>/ssm-sessions`; streams are created by ECS Exec. |
| Container and sidecar output | `stdout`/`stderr` emitted by the main container (entrypoint warnings/status and workload output) and optional `kube-proxy` sidecar. This is not a filesystem snapshot. | CloudWatch log group `/ecs/<project>-<stage>`; stream prefixes are `rosa-boundary` and `kube-proxy`. |
| Create-investigation Lambda | Request-header keys/values after redaction of `Authorization` and `X-OIDC-Token`, OIDC validation and group authorization outcomes, user/subject and investigation identifiers, resource/task lifecycle messages, and errors. The handler does not log the raw request body or OIDC token in its normal messages. | `/aws/lambda/<project>-<stage>-create-investigation`. |
| Reaper Lambda | Scheduled checks, running-task counts, expired task IDs/deadlines, stop outcomes, skipped tasks, and errors; its result also summarizes checked/stopped/skipped/error counts. | `/aws/lambda/<project>-<stage>-reap-tasks`. |
| Investigation S3 escrow | A best-effort copy of eligible `/home/sre` files on container shutdown: e.g. shell history, notes, and downloaded/workspace files. It is a point-in-time shutdown sync, not a live filesystem journal. | The investigation audit bucket, under `<cluster-id>/<investigation-id>/<YYYYMMDD>/<task-id>/`. |
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

The task role is designed for audit-bucket writes (`PutObject`, plus `ListBucket`); it is not the reader role. The operations guidance says SREs should not receive direct bucket access and that retrieval should use a separately managed read-only compliance role. CloudTrail Event history can be searched by event name, user, and time; availability and S3 data-event coverage depend on the account/organization trail configuration.

For Bedrock text payloads, query the dedicated CloudWatch log group with the same CloudWatch Logs tools above. Retrieve larger objects from the separate Bedrock payload bucket only through restricted read access. This bucket is distinct from the investigation escrow bucket and does not inherit the investigation bucket's Object Lock configuration.

## Collection, retention, and protection

- ECS Exec logging is set to `OVERRIDE` at the cluster, sends transcripts to the dedicated session group, and enables CloudWatch encryption with the ECS Exec KMS key. That group uses `retention_days` (default 90 days). Its access is security-sensitive because session content can include anything typed or printed in the terminal.
- Container and Lambda log groups use `log_retention_days` (default 7 days). Workspace escrow and Bedrock payload logging use `retention_days` (default 90 days). HCP Terraform/workspace values can override these defaults; confirm the deployed values before relying on a retention period.
- The investigation S3 bucket has versioning, default compliance-mode Object Lock retention, public-access blocking, AES-256 server-side encryption, and a bucket policy denying non-TLS requests. Optional cross-account replication is controlled by Terraform inputs. The Bedrock large-payload bucket is separate: it blocks public access, uses AES-256 encryption, denies non-TLS requests, and has lifecycle expiration, but does not configure versioning or Object Lock.
- On normal process exit or trapped `SIGTERM`, `SIGINT`, or `SIGHUP`, the entrypoint attempts `aws s3 sync /home/sre`. It auto-builds the prefix from `S3_AUDIT_BUCKET`, `CLUSTER_ID`, `INVESTIGATION_ID`, the date, and ECS task ID unless `S3_AUDIT_ESCROW` is supplied directly. Missing configuration, a failed sync, or a timeout produces a warning; the container can still exit. The sync is therefore best-effort, not a guaranteed finalization transaction. Terraform gives the ECS container a 120-second stop timeout while `SYNC_TIMEOUT` defaults to 300 seconds, so do not assume a shutdown sync always finishes before ECS terminates the container.
- The sync excludes `.config/ocm/*` and `.kube/*` and uses `--no-follow-symlinks`, so credential-bearing OCM/kubeconfig trees and symlink targets are not copied into workspace escrow. Those directories are also task-scoped mounts that disappear with the task. This exclusion does not remove those credentials from an interactive transcript or Bedrock payload if a user/tool prints or submits them there; avoid entering secrets into logged sessions and model prompts.

## Coverage boundaries and operating cautions

- The S3 snapshot records eligible workspace files only when shutdown cleanup runs. It does not record every file operation, provide continuous backup, or establish who read an object. Use CloudTrail S3 data events if object-level access auditing is required.
- EFS is persistent investigation workspace storage, not an audit log or file-change journal. ECS task tags are useful correlation metadata but are not a substitute for retained CloudWatch/CloudTrail records.
- This repository provisions CloudWatch groups for ECS, Lambda, and Bedrock, but does not provision an AWS CloudTrail trail/event data store. Confirm account-level CloudTrail coverage with the AWS account owner rather than assuming every API call or S3 object access is recorded.
- The repository deploys Keycloak on OpenShift, but does not configure a central Keycloak authentication-event export in this AWS logging stack. The docs' operator-log command (`oc logs -n keycloak deployment/rhbk-operator`) is for troubleshooting the operator, not a complete end-user login audit history.
- The Go CLI's OIDC token cache is operational credential state, not an audit trail. Similarly, Container Insights provides ECS telemetry/metrics and should not be mistaken for terminal or API audit records.
- LocalStack integration tests exercise the S3 audit bucket controls and sync exclusion behavior. They do not verify real ECS Exec transcript delivery, production CloudTrail configuration, or Bedrock account-wide payload capture; those require deployed-environment checks.

## Evidence-backed claims

- ECS Exec output is overridden to a dedicated CloudWatch group with encryption enabled and the session group uses the configured retention period; container stdout/stderr uses a separate group with `rosa-boundary` and `kube-proxy` stream prefixes. [ECS cluster and groups](repo://deploy/regional/ecs.tf#L1-L40) · [container log drivers](repo://deploy/regional/ecs.tf#L103-L168)
- Create-investigation and reaper Lambdas each have named CloudWatch groups using `log_retention_days`; the handlers emit identity/authorization/resource lifecycle and reaper task/deadline outcome messages, including deferred stops for active Exec sessions. [create-investigation group](repo://deploy/regional/lambda-create-investigation.tf#L1-L9) · [create-investigation logging](repo://lambda/create-investigation/handler.py#L88-L94) · [reaper group](repo://deploy/regional/lambda-reap-tasks.tf#L1-L9) · [reaper outcomes](repo://lambda/reap-tasks/handler.py#L110-L175)
- Entry-point shutdown sync builds a task-specific audit prefix or accepts an explicit URI, excludes OCM/kubeconfig state, avoids following symlinks, and warns rather than blocking indefinitely when sync fails. [sync implementation](repo://entrypoint.sh#L3-L34) · [signals and normal exit](repo://entrypoint.sh#L167-L183) · [task stop timeout](repo://deploy/regional/ecs.tf#L103-L110)
- The investigation audit bucket combines versioning and compliance Object Lock with public-access blocking, AES-256 encryption, TLS-only access, and optional cross-account replication; task IAM permits writes rather than providing the compliance read path. [bucket controls](repo://deploy/regional/s3.tf#L1-L73) · [replication](repo://deploy/regional/s3.tf#L75-L120) · [task S3 policy](repo://deploy/regional/iam.tf#L42-L58)
- Bedrock invocation logging sends text payloads account/Region-wide to encrypted CloudWatch Logs and larger text payloads to a separate S3 bucket; other modalities are disabled. [invocation configuration](repo://deploy/regional/bedrock-logging.tf#L56-L85) · [large-payload bucket controls](repo://deploy/regional/bedrock-large-payloads.tf#L1-L51)
- S3 sync tests verify that nested OCM and kubeconfig files are excluded while ordinary workspace controls remain eligible, including checks for token/account-response canaries. [shell sync tests](repo://tests/shell/entrypoint.bats#L88-L174) · [LocalStack audit sync test](repo://tests/localstack/integration/test_s3_audit.py#L114-L177)

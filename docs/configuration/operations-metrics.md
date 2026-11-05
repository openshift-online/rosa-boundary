# Boundary operations metrics

The first metric for [ROSAENG-68823](https://redhat.atlassian.net/browse/ROSAENG-68823)
measures task-creation workflow outcomes. Exporter onboarding and Grafana delivery
are separate changes; emitting this metric does not prove Prometheus ingestion.

## Task-creation contract

The create-investigation Lambda emits `TaskCreationRequests` in CloudWatch
namespace `ROSABoundary`, with unit `Count` and standard (60-second) resolution.
Every completed, authorized task-creation attempt emits a value of `1` with
exactly two dimensions:

| Dimension | Values |
|-----------|--------|
| `ECSCluster` | Deployment's configured `ECS_CLUSTER`, not the requested ROSA cluster ID |
| `Outcome` | `success`, `failure`, or `blocked` |

`success` means `create_investigation_task` returned after access-point setup,
task-definition registration, ECS RunTask, and task tagging. It does not mean
the task reached RUNNING, became ready for ECS Exec, or completed audit sync.
`failure` means that workflow raised an exception, including AWS errors during
handover, setup, launch, or tagging. `blocked` means handover was rejected with
HTTP 409 because an existing task has an active session.

Configuration discovery (`get_config`), requests rejected before creation
(including invalid input, authentication, authorization, or configuration), and
`skip_task` investigation-only requests emit no task-creation metric. Calls to
the internal helper outside the Lambda handler are not instrumented. Counts
represent attempts, including caller retries, rather than unique tasks or
investigations. A Lambda timeout or process crash can prevent outcome emission.

The EMF event contains only the metric, its dimensions, and CloudWatch metadata.
It contains no username, subject, token, request ID, investigation ID, requested
cluster ID, task ARN, or error text. AWS account and region are selected by the
CloudWatch reader and can be attached as scrape labels.

## Publication and cost

The handler writes one standalone JSON event to stdout using CloudWatch
[Embedded Metric Format (EMF)](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html).
CloudWatch Logs extracts the metric asynchronously from the Lambda log stream.
The JSON must reach Logs unchanged, without a logging prefix or an outer JSON
wrapper. Keep this requirement when changing runtime logging configuration.
This uses existing Lambda logging permissions; no `cloudwatch:PutMetricData`
permission, new AWS client, or package dependency is required. An emission error
is logged with a fixed message and does not change the creation response.

There are at most three custom metric identities per ECS cluster, account, and
region, plus one small log event per completed attempt. No additional dimension
rollups are emitted. Custom metric storage, Logs ingestion, and exporter polling
costs still require review. EMF delivery can duplicate samples and is not an
exact accounting or audit source.

## Exporter and dashboard semantics

Configure the exporter to read namespace `ROSABoundary`, metric
`TaskCreationRequests`, dimensions **exactly** `ECSCluster` and `Outcome`, and
statistic `Sum` over 60-second periods. Select the intended ECS cluster and
region explicitly. Confirm the actual exported Prometheus name and dimension
labels for the chosen exporter version before writing dashboard queries.

This is a CloudWatch period count, not a process-lifetime Prometheus counter;
do not apply `rate()` or `increase()` to it. Summing repeated scrapes of the same
CloudWatch period will also overcount. Choose timestamp, lookback, delay, and
scrape settings together and verify them against known attempts.

A candidate workflow-success ratio is `success / (success + failure)`, excluding
`blocked`. Report blocked attempts separately. An absent outcome series may mean
that outcome has never occurred. Only treat absent failures as zero when other
samples and collector health establish that data is available. Idle periods,
zero denominators, and missing telemetry must not become 100% availability.
This ratio excludes pre-creation failures and timeouts and is not an end-to-end
availability SLI.

## Remaining dashboard signals

| Requested signal | Current evidence / remaining work |
|------------------|-----------------------------------|
| Lambda failures | Native `AWS/Lambda` Errors, Invocations, Duration; handled HTTP errors can return normally and are not necessarily Lambda Errors |
| Task-creation outcomes | This metric; stage CloudWatch extraction and Prometheus ingestion remain unverified |
| ECS launch failures | This metric includes broader setup/handover failures; add a separate launch-specific signal and account for asynchronous ECS startup failures |
| Task lifetime | Needs actual lifecycle timestamps and coverage of all stop paths; configured timeout is not observed lifetime |
| Investigation creation | Needs a signal at newly created access points; access-point reuse and `skip_task` must be distinguished |
| Task-creation availability | Define the SLI boundary and timeout/missing-data treatment before presenting an availability claim |
| Actor-level views | Require an approved, access-controlled source; do not add identity metric labels |

## Stage validation evidence

After the approved deployment, record the deployed revision/artifact, account,
region, ECS cluster, exporter configuration/owner, and query timestamps. For an
approved task-creation attempt, verify the raw EMF log and CloudWatch
`TaskCreationRequests` Sum with the expected dimensions. Verify a native Lambda
metric and this custom metric at the exporter and through
`aws-resources-exporter-stage`. Record the actual series names and account/region
labels. Confirm no request/actor labels are exported and capture collector health
and missing-data behavior. Resource creation and cleanup follow the approved
staging workflow; local unit tests cannot establish this evidence.

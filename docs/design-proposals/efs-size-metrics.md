# EFS size metrics: export and monitoring plan

Status: proposed follow-up to [ROSAENG-68823](https://redhat.atlassian.net/browse/ROSAENG-68823).
This document plans collection, dashboard changes, and alerting; those changes
are not implemented by the dashboard PR.

## Recommendation and current state

Add native CloudWatch `AWS/EFS` `StorageBytes` to the existing Prometheus
CloudWatch exporter, starting with `StorageClass=Total` for each deployed
Boundary filesystem. Add filesystem size, sample age, and daily net change to
the shared ROSA Boundary operations dashboard. Stage collection first, then
onboard production separately for each deployed region.

Source reviewed on 24 November 2026:

- [Regional EFS configuration](../../deploy/regional/efs.tf) creates one shared
  filesystem per deployed regional root, uses bursting throughput, and moves
  eligible files to IA after 30 days. It configures no Archive transition.
  [Regional outputs](../../deploy/regional/outputs.tf) expose `efs_filesystem_id`.
  An actual deployment inventory is still needed; supported regions and
  workspace definitions do not establish which filesystems exist.
- App-interface exporter onboarding [!220268](https://gitlab.cee.redhat.com/service/app-interface/-/merge_requests/220268)
  collects Boundary task-creation and Lambda metrics in `rosa-boundary-stage`
  (`150100906299`), `us-east-1`. Its exporter runs in
  `app-sre-observability-stage` on **appsres11ue1** and is scraped every 120 seconds.
  EFS size is not included. See the [delivery guide](../configuration/operations-dashboard.md)
  for the reviewed configuration revisions, datasource, and ownership.
- Production collection is disabled in the reviewed account configuration.
  Selecting `aws-resources-exporter-production` on the dashboard does not
  enable it.

AWS already publishes this metric. Collection needs CloudWatch reads through
the existing exporter identity, currently configured with
`CloudWatchReadOnlyAccess`; verify its effective permissions during rollout.
No application instrumentation or filesystem scan is required.

## Metric contract

The [AWS EFS metric reference](https://docs.aws.amazon.com/efs/latest/ug/efs-metrics.html)
defines `StorageBytes` as a byte gauge published **every 15 minutes**, with
valid statistics `Average`, `Minimum`, and `Maximum`. Start with `Average`;
`Sum`, `rate`, and `increase` are inappropriate for filesystem size.

Request dimensions exactly `FileSystemId` and `StorageClass`; confirm the
available identities using CloudWatch `ListMetrics` in each target account and
region. Allowlist filesystem IDs from the deployed regional outputs, checked
against EFS identity/tags. This excludes unrelated filesystems and avoids
introducing tag-discovery permissions. Update the allowlist when a filesystem
is replaced or a region is onboarded.

| StorageClass | Meaning and planned use |
|--------------|-------------------------|
| `Total` | Metered bytes across all classes; initial size and net-growth panels |
| `Standard` | Metered Standard bytes; optional class breakdown |
| `IA` | Actual IA bytes; optional class breakdown |
| `IASizeOverhead` | IA minimum-file-size rounding overhead; include when reconciling class totals |
| `Archive`, `ArchiveSizeOverhead` | Actual Archive bytes and rounding overhead; add if Archive is used |

For IA and Archive, AWS rounds files smaller than 128 KiB to 128 KiB for
metering. `Total` can therefore exceed `Standard + IA + Archive`; include the
overhead series to reconcile them. Never add `Total` to its components. Label
the initial panel **EFS metered storage**, using Grafana's IEC byte units.
This is filesystem-level usage, not per-user or per-investigation usage, and
is not a dollar cost estimate or a provisioned-capacity percentage.

## Changes and ownership

| Repository / location | Change and reviewer |
|-----------------------|---------------------|
| app-interface: `resources/observability/cloudwatch-exporter/rosa-boundary-stage/cloudwatch-exporter-config.configmap.yaml` | Append the EFS metric to the existing config; Boundary supplies the verified IDs and App-SRE reviews collection, API usage, and credentials. The resource is already registered under App-SRE ownership. |
| Boundary: `dashboards/rosa-boundary.json` | Boundary adds EFS panels and a filesystem filter; keep the existing environment-neutral title, UID, and datasource selector. |
| Boundary: `scripts/generate_dashboard_manifest.py` | Run the existing generator after editing JSON, committing the resulting `dashboards/manifests/grafana-dashboard-rosa-boundary.configmap.yaml`. |
| app-interface: `resources/observability/cloudwatch-exporter/rosa-boundary-stage/` | Proposed home for a service-specific PrometheusRule and rule-test fixture; App-SRE must register their delivery and ownership using current conventions before activation. |
| app-interface: `data/services/observability/cicd/saas/saas-cloudwatch-exporter.yaml` and account configuration | Additional exporter targets/configuration for production and additional regions, with App-SRE review. |

The current exporter target can collect staging EFS in `us-east-1` without
another exporter. Its AWS region is configured globally: collecting an actual
filesystem in another region requires a region-specific target/configuration
and correct scrape labels. A Grafana region filter alone cannot collect it.

Dashboard ConfigMaps continue to follow the existing delivery proposal to
Grafana stage on appsres09ue1 and subsequently production Grafana on appsrep09ue1.
Exporter placement on appsres11ue1 is compatible with those Grafana instances
through their existing datasource connections.

## Proposed exporter configuration

Append this entry under the existing `metrics` list, replacing the placeholder
with the verified staging filesystem ID. These are **per-metric** overrides;
retain existing Lambda and task-creation collection settings.

```yaml
- aws_namespace: AWS/EFS
  aws_metric_name: StorageBytes
  aws_dimensions: [FileSystemId, StorageClass]
  aws_dimension_select:
    FileSystemId: ["<verified-boundary-filesystem-id>"]
    StorageClass: [Total]
  aws_statistics: [Average]
  period_seconds: 900
  range_seconds: 3600
  delay_seconds: 600
  set_timestamp: true
```

The [exporter configuration reference](https://github.com/prometheus/cloudwatch_exporter/blob/v0.19.0/README.md#configuration)
supports these overrides and exports only the latest point in the requested
window. A one-hour retrieval window accommodates sparse publication; the
ten-minute delay follows the current exporter convention. Validate both against
actual publication lag. Keep original timestamps so repeated scrapes cannot
make an old CloudWatch observation appear fresh. Verify ingestion accepts those
timestamps; if it does not, resolve timestamp handling with App-SRE before
rollout rather than silently replacing source timestamps with scrape time.

Expected series and dimension labels, to confirm from the running exporter:
`aws_efs_storage_bytes_average`, `file_system_id`, and `storage_class`, plus
the existing `job`, `account`, and `region` scrape labels.

With the current GetMetricStatistics path and 120-second scrape, expect about
21,600 metric retrieval requests per filesystem/class combination per 30 days,
before retries. Start with one class/statistic, check actual exporter request
counts and scrape duration, and review API charges with App-SRE. No custom
CloudWatch metric publication is needed.

## Dashboard queries and missing data

Add a filesystem query variable scoped to the selected datasource and region;
refresh it when either changes and default to All. Keep account, region, and
filesystem ID in legends so multiple filesystems remain distinguishable.

The existing `offset 10m` alone is insufficient: a five-minute instant-vector
lookback leaves gaps between fifteen-minute observations. Proposed size query:

```promql
last_over_time(
  aws_efs_storage_bytes_average{
    job=~"cloudwatch-exporter-rosa-boundary-.*",
    account=~"rosa-boundary-(stage|prod)",
    region=~"${region:regex}",
    file_system_id=~"${filesystem:regex}",
    storage_class="Total"
  }[30m] offset 10m
)
```

This holds the last observation within a bounded window, showing data roughly
10–40 minutes old. Label the cadence and delay, preserve missing values, and
show actual CloudWatch sample age alongside collection health. An age query
must extract timestamps **before** aggregation, for example:

```promql
time() - max_over_time(
  timestamp(aws_efs_storage_bytes_average{
    job=~"cloudwatch-exporter-rosa-boundary-.*",
    account=~"rosa-boundary-(stage|prod)",
    region=~"${region:regex}",
    file_system_id=~"${filesystem:regex}",
    storage_class="Total"
  } offset 10m)[30m:1m]
)
```

`timestamp(last_over_time(...))` would report the evaluation timestamp, masking
staleness. Validate the proposed expressions against the receiving query engine.
For daily **net change**, subtract the same latest-value expression with
`offset 24h10m` from the current expression with `offset 10m`. Both observations
must exist and be fresh relative to their respective evaluation windows; a
missing baseline stays missing. Negative change is valid after cleanup. This
does not measure bytes written or exact change at midnight.

## Alerting decisions

Boundary owns the storage/retention response and runbook; agree notification
routing and rule delivery with App-SRE. Before activating rules, choose an
absolute metered-storage budget, a sustained net-growth threshold/window, and
severity for each environment. EFS grows elastically, so a disk-full percentage
is not the appropriate signal. Alert response must respect investigation
retention and audit requirements; automatic deletion is a separate change.

Add a missing/stale `Total` signal for each explicitly expected, enabled
filesystem, independent of size/growth comparisons. A starting candidate is
`absent_over_time` over one hour with exact account/region/filesystem labels;
validate the window against cadence, delay, and ingestion before enabling it.
Generate an expectation for each filesystem so disappearance of one is not
hidden by another. Unused IA/Archive classes are not expected-series failures.
Use the existing generic exporter scrape-error and duration alerts rather than
duplicating them. Verify their deployment and routing as part of acceptance.

## Implementation sequence and acceptance

1. **Inventory and confirm identities.** Boundary records actual filesystem IDs,
   accounts, regions, regional output provenance, and expected class values.
   Inspect existing CloudWatch samples read-only; record their timestamps and
   statistics. Actual IDs, budgets, and alert routing remain open inputs.
2. **Stage exporter MR.** App-SRE reviews the per-metric addition, validates
   app-interface schemas/bundle using its repository instructions, and deploys
   through the existing SaaS. Record the deployed exporter/configuration
   revision and image. Confirm effective CloudWatch reads and no scrape errors.
3. **Validate sparse ingestion.** Over at least three consecutive 15-minute
   publication intervals, compare CloudWatch and exporter values/timestamps
   with Prometheus through `aws-resources-exporter-stage`. Include quiet periods;
   no synthetic task or filesystem writes are needed. Check original timestamps,
   repeated scrapes, correct account/region/filesystem labels, sample age,
   query gaps, and behavior when observations stop. Use local query fixtures
   for missing/old data rather than disrupting staging telemetry.
4. **Dashboard PR.** Add the three EFS views after metric identities are
   confirmed, regenerate the ConfigMap, and run generator `--check`, scoped
   pre-commit, and PromQL parsing. Preview in Grafana stage; check datasource,
   region/filesystem filter refresh, multiple-region legends, byte units,
   sample age, absent values, and negative net change. Record evidence.
5. **Alert MR and runbook.** Once budgets and routing are agreed, add and
   register service rules with app-interface rule tests covering normal size,
   sustained growth, cleanup, absent baseline, stale/missing filesystem, and
   unrelated account/region series. Validate rendering and notification routing
   through the supported alert-testing process before activation.
6. **Production onboarding.** Inventory real production regional deployments;
   enable collection through reviewed account/config/target changes. Validate
   each region's data and ownership before enabling its alerts. Use the same
   dashboard by selecting `aws-resources-exporter-production`; promote its
   reviewed dashboard revision through the existing SaaS.

Acceptance requires visible metered bytes and source age per expected
filesystem, agreement with CloudWatch over several updates, continuous useful
display between updates, explicit missing-data behavior, and tested routing
before alerts are considered operational. Local configuration/query checks
alone do not prove deployed collection or notification delivery.

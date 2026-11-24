# Operations dashboard: delivery and ownership

The shared [dashboard JSON](../../dashboards/rosa-boundary.json) covers
the metrics enabled by
[app-interface !220268](https://gitlab.cee.redhat.com/service/app-interface/-/merge_requests/220268).
Keep the JSON and its [deployment ConfigMap](../../dashboards/manifests/grafana-dashboard-rosa-boundary.configmap.yaml)
in `openshift-online/rosa-boundary`. App-SRE's current
[dashboard guidance](https://gitlab.cee.redhat.com/service/app-interface/-/blob/master/docs/platform-users/monitoring/grafana-visualization.md#adding-dashboards)
recommends an upstream service repository and a service-owned SaaS tracking file.

## Configuration reviewed on 24 November 2026

Boundary revision: `6ba8b17dbda2c7f5e7222da27c84aa78003d87a3`.
App-interface revision: `6f57d8409c584e0b42f0699e2728da97f884358f`.
These establish Git configuration, not deployed artifact identity or live data.

| Item | Current configuration |
|------|-----------------------|
| Account / region | `rosa-boundary-stage` / `150100906299` / `us-east-1` |
| Collector | Existing Prometheus CloudWatch exporter; the YACE proposal was superseded |
| Exporter configuration | `resources/observability/cloudwatch-exporter/rosa-boundary-stage/cloudwatch-exporter-config.configmap.yaml` in app-interface |
| Exporter deployment | Target `rosa-boundary-stage` in `data/services/observability/cicd/saas/saas-cloudwatch-exporter.yaml` |
| Exporter namespace / cluster | `app-sre-observability-stage` / `appsres11ue1` |
| Scrape labels | `job=cloudwatch-exporter-rosa-boundary-stage`, `account=rosa-boundary-stage`, `region=us-east-1` |
| Grafana datasource | `aws-resources-exporter-stage` → `https://prometheus.external-resources.stage.devshift.net` |
| Thanos diagnostic endpoint | `https://thanos-querier.appsres11ue1.devshift.net`, supplied in ROSAENG-68823 |
| Exporter configuration owner | App-SRE: resource registered in `data/teams/app-sre/roles/app-sre.yml` |

The datasource is defined in
[grafana-datasources.secret.yaml](https://gitlab.cee.redhat.com/service/app-interface/-/blob/master/resources/observability/grafana/grafana-datasources.secret.yaml),
shared by the central Grafana instances. No new datasource or RHOBS forwarding is
needed for this dashboard. The Thanos diagnostic URL is not a datasource name.

The dashboard name, UID (`rosa-boundary`), and artifacts are shared across
environments. Choose `aws-resources-exporter-stage` or
`aws-resources-exporter-production` in its datasource selector. The latter is
configured at `https://prometheus.external-resources.prod.devshift.net`.
Queries match Boundary accounts `rosa-boundary-(stage|prod)` and exporter jobs
`cloudwatch-exporter-rosa-boundary-.*` within the selected datasource. Region
options come from its Boundary exporter targets, and function options refresh
from its Lambda metrics. Both default to All, so changing the datasource is
enough to change environments. Legends include region to distinguish deployments.

The table above records the initial staging collection. Production's account
exists as `rosa-boundary-prod`, but its CloudWatch exporter feature is disabled
in the reviewed collection configuration. Production metric onboarding and
validation are still required; the datasource selector does not enable collection.

## Metric and query details

| CloudWatch metric / statistic | Expected Prometheus metric | Dimension labels |
|------------------------------|----------------------------|------------------|
| ROSABoundary TaskCreationRequests / Sum | `rosaboundary_task_creation_requests_sum` | `ecscluster`, `outcome` |
| AWS/Lambda Invocations / Sum | `aws_lambda_invocations_sum` | `function_name` |
| AWS/Lambda Errors / Sum | `aws_lambda_errors_sum` | `function_name` |
| AWS/Lambda Duration / Average | `aws_lambda_duration_average` | `function_name` |
| AWS/Lambda Duration / Maximum | `aws_lambda_duration_maximum` | `function_name` |

The onboarding MR's sample `aws_rosaboundary_taskcreationrequests_sum` does not
match the upstream exporter's naming algorithm. Its
[released source](https://github.com/prometheus/cloudwatch_exporter/blob/v0.19.0/src/main/java/io/prometheus/cloudwatch/CloudWatchCollector.java)
lowercases the namespace and converts lower-to-upper transitions in metric and
dimension names to underscores. It adds no `aws_` prefix to custom namespaces;
`ECSCluster` becomes `ecscluster`. App-interface identifies the App-SRE image as
a mirror of `prom/cloudwatch-exporter`. Verify the running image and actual series
before treating these source-derived names as live evidence.

The dedicated staging config requests `period_seconds: 60`; its ServiceMonitor requests
`interval: 120s`. It does not override upstream defaults of `delay_seconds: 600`,
`range_seconds: 600`, and `set_timestamp: true`. CloudWatch panels use
`offset 10m` to expose delayed samples within Prometheus's normal lookback. This
plots a bucket ten minutes later than its original CloudWatch timestamp; account
for this when comparing logs. Exporter health panels query current time.
Production must use compatible period and delay settings when collection is
enabled, or the shared graph descriptions and offset must be adjusted.

The exporter returns the latest datapoint in its requested window. With this
cadence, busy periods can lose intervening one-minute buckets, while sparse
buckets can reappear across query steps. These graphs show observed period
values, not exact counts over the selected time range. Do not use `rate`,
`increase`, `sum_over_time`, or Grafana total reducers on them. Before adding
whole-range counts or ratios, agree a collection cadence with App-SRE and verify
bucket coverage, timestamps, and deduplication against CloudWatch.

Lambda discovery is limited to `rosa-boundary-.*`. Terraform currently
defines `create-investigation`, `reap-tasks`, and `reap-investigations` with that
prefix, with the environment in each name. The function selector only affects
Lambda panels. Task outcomes match ECS clusters `rosa-boundary-.*` in the selected
datasource and regions; retries count as attempts. See the
[metric contract](operations-metrics.md) for exclusions and success semantics.

## App-interface changes to propose

There is currently no `data/services/rosa-boundary/app.yml` or Boundary pipelines
provider. A small initial proposal can use the existing observability app and
pipeline as the hosting service, with a separate Boundary dashboard SaaS file.
App-SRE must agree to that hosting arrangement; it is a proposal, not an existing
ownership assignment. Boundary maintains dashboard content, while App-SRE
maintains Grafana, datasources, and the exporter. A future Boundary app onboarding
can move the SaaS app/pipeline references to Boundary without moving the JSON.

1. Add a file at the proposed path
   `data/services/observability/cicd/saas/saas-rosa-boundary-dashboards.yaml`:

   ```yaml
   ---
   $schema: /app-sre/saas-file-2.yml
   labels:
     service: app-sre-observability
   name: saas-rosa-boundary-dashboards
   displayName: rosa-boundary-dashboards
   description: ROSA Boundary operations dashboard
   app:
     $ref: /services/observability/app.yml
   pipelinesProvider:
     $ref: /services/observability/pipelines/tekton-app-sre-observability-pipelines.appsrep09ue1.yaml
   slack:
     workspace:
       $ref: /dependencies/slack/redhat-internal.yml
     channel: sd-app-sre-info
   managedResourceTypes:
   - ConfigMap
   imagePatterns: []
   resourceTemplates:
   - name: rosa-boundary-dashboards
     url: https://github.com/openshift-online/rosa-boundary
     path: /dashboards/manifests
     provider: directory
     targets:
     - namespace:
         $ref: /services/observability/namespaces/app-sre-observability-stage-int.appsres09ue1.yml
       ref: main
   ```

   Merge the upstream dashboard first, so the path exists. This SaaS target
   deploys to **Grafana stage on appsres09ue1**, independently of the exporter
   running on appsres11ue1. Existing refs and the notification channel above
   follow `saas-app-sre-observability-dashboards.yaml`; retain them only if
   App-SRE accepts hosting this deployment.

2. Register the ConfigMap's new folder, `ROSA Boundary`, by adding a provider to
   `data.dashboards.yaml.providers` inside
   `resources/observability/grafana/grafana-dashboards.configmap.yaml`:

   ```json
   {
     "folder": "ROSA Boundary",
     "name": "ROSA Boundary",
     "options": {"path": "/grafana-dashboard-definitions/ROSA Boundary"},
     "orgId": 1,
     "type": "file"
   }
   ```

   This file is included through
   `data/services/observability/shared-resources/grafana.yml`. App-SRE owns this
   shared provisioning change and should confirm its rollout/reload. The
   ConfigMap annotation alone does not register a provider.

3. Grant the Boundary maintainers SaaS self-service in the existing
   `data/teams/sd-sre/roles/rosa-boundary.yaml` role, appending to `self_service`:

   ```yaml
   - change_type:
       $ref: /app-interface/changetype/saas-file-self-service.yml
     datafiles:
     - $ref: /services/observability/cicd/saas/saas-rosa-boundary-dashboards.yaml
   ```

   Review role membership with the Boundary team; having the role's name in Git
   does not give every Boundary contributor access. App-SRE reviews the initial
   SaaS file, hosting references, targets, and shared folder configuration.
   Dashboard content remains reviewed through this repository's `OWNERS`.

4. After validation in Grafana stage, add a second target with namespace
   `/services/observability/namespaces/app-sre-observability-production-int.appsrep09ue1.yml`
   and `ref` set to the exact reviewed Boundary commit containing the dashboard.
   This publishes the same dashboard at
   `https://grafana.app-sre.devshift.net/d/rosa-boundary`. Its datasource selector
   chooses staging or production data independently of which Grafana instance
   hosts it. The preview URL is
   `https://grafana.stage.devshift.net/d/rosa-boundary`.

Do not add this dashboard to the deprecated `saas-grafana.yaml`, or to the
legacy shared-resources dashboard list. No change to the
`service/app-sre-observability` template repository is needed for this approach.
Additional exported metrics belong in the existing dedicated exporter ConfigMap
in app-interface. It is currently owned by App-SRE; Boundary self-approval of
metric changes would need an explicit `resource-owner` grant for that path.

When implementing the app-interface MR, follow its repository checks:
`make schemas` before edits, then `make bundle validate` and
`./hack/run-prometheus-tests.py`. The SaaS YAML above is a proposal; those checks
have not been run against an applied app-interface change.

## Live validation still required

An unauthenticated request to Thanos returned HTTP 403, and the local OpenShift
login was expired during this review. Dashboard rendering and live ingestion
were therefore not verified. Use authenticated Grafana Explore with datasource
`aws-resources-exporter-stage` and retain query results, labels, and UTC times in
[ROSAENG-68823](https://redhat.atlassian.net/browse/ROSAENG-68823)
or [APPSRE-15799](https://redhat.atlassian.net/browse/APPSRE-15799).

The following queries are staging validation examples; dashboard queries use
the selected datasource and region filters. First discover recent custom series
without assuming their exact spelling:

```promql
count_over_time({__name__=~".*rosaboundary.*",account="rosa-boundary-stage",region="us-east-1"}[24h])
```

This counts stored samples for discovery, **not task attempts**. Then check:

```promql
up{job="cloudwatch-exporter-rosa-boundary-stage",account="rosa-boundary-stage",region="us-east-1"}
cloudwatch_exporter_scrape_error{job="cloudwatch-exporter-rosa-boundary-stage",account="rosa-boundary-stage",region="us-east-1"}
rosaboundary_task_creation_requests_sum{job="cloudwatch-exporter-rosa-boundary-stage",account="rosa-boundary-stage",region="us-east-1",ecscluster="rosa-boundary-stage"} offset 10m
aws_lambda_invocations_sum{job="cloudwatch-exporter-rosa-boundary-stage",account="rosa-boundary-stage",region="us-east-1",function_name=~"rosa-boundary-stage-.*"} offset 10m
```

Check both duration statistics and Errors as well. An outcome or Errors series
can be absent if it has never been emitted; do not substitute a healthy zero.
Use a time range containing known existing activity and compare observed buckets
with CloudWatch. Record deployed exporter image, timestamp age, cadence,
account/region labels, and absence of identity labels. Import the JSON in Grafana
stage and check datasource selection, function filtering, sparse data, health
panels, folder provisioning, and both Git-managed targets before closing out.

EFS `StorageBytes`, ECS startup failures, actual task lifetimes, investigation
creation, and an end-to-end availability SLI are not exported by the current
config and have no panels here. The [EFS size metrics plan](../design-proposals/efs-size-metrics.md)
covers the exporter, dashboard, and alerting follow-up requested in the Jira discussion.
Actor-level views require an approved
log datasource; do not introduce actor or username metric labels.

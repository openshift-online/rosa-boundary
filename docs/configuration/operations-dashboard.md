# Operations dashboard

The ROSA Boundary dashboard shows task-creation outcomes, Lambda invocations,
errors and duration, and exporter health.

## View the dashboard

Open [ROSA Boundary in Grafana stage](https://grafana.stage.devshift.net/d/rosa-boundary).
Choose `aws-resources-exporter-stage` or `aws-resources-exporter-production` in
**Datasource** to select an environment. **Region** and **Lambda function** refresh
with the datasource and default to All. Function filters apply to Lambda panels.
Production metrics require production exporter onboarding.

## Read the charts

CloudWatch charts use a ten-minute offset to accommodate collection delay.
A point shown at 12:10 represents the CloudWatch bucket at 12:00. Exporter
health panels show current scrape and collection status.

The exporter requests 60-second buckets and is scraped every 120 seconds, so
buckets can be missed or repeated. Charts show sampled bucket values; summing
them does not give an accurate total for the selected time range. Missing data
remains empty.

Task-creation outcomes count attempts, including retries. Success means the
creation workflow returned, rather than that the task is ready. Lambda errors
count failed invocations; handled application errors may return successfully.
See the [metric contract](operations-metrics.md) for outcome definitions.

## Update the dashboard

Edit [rosa-boundary.json](../../dashboards/rosa-boundary.json), then regenerate
its deployment ConfigMap:

```sh
python3 scripts/generate_dashboard_manifest.py
```

Commit both files. CI can check that the manifest matches the JSON with:

```sh
python3 scripts/generate_dashboard_manifest.py --check
```

The check also runs through pre-commit when dashboard files or the generator
change. To preview changes, import the JSON into Grafana stage. Keep changes in
Git; provisioned dashboards can overwrite UI edits.

## Delivery and ownership

Boundary maintains the dashboard JSON, generated ConfigMap, and dashboard SaaS
targets. App-SRE maintains Grafana, datasources, and metric collection.
App-interface deploys `/dashboards/manifests` into the `ROSA Boundary` folder.
Its configuration lives in:

| Configuration | app-interface file |
|---------------|--------------------|
| Dashboard deployment | [saas-rosa-boundary-dashboards.yaml](https://gitlab.cee.redhat.com/service/app-interface/-/blob/master/data/services/observability/cicd/saas/saas-rosa-boundary-dashboards.yaml) |
| Grafana folder provisioning | [grafana-dashboards.configmap.yaml](https://gitlab.cee.redhat.com/service/app-interface/-/blob/master/resources/observability/grafana/grafana-dashboards.configmap.yaml) |
| Staging metric collection | [cloudwatch-exporter-config.configmap.yaml](https://gitlab.cee.redhat.com/service/app-interface/-/blob/master/resources/observability/cloudwatch-exporter/rosa-boundary-stage/cloudwatch-exporter-config.configmap.yaml) |

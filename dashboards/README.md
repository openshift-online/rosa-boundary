# ROSA Boundary staging dashboard

Import [rosa-boundary-stage.json](rosa-boundary-stage.json) into
[Grafana stage](https://grafana.stage.devshift.net) to preview it. Select
`aws-resources-exporter-stage` as the datasource. The dashboard shows task-creation
outcomes and Lambda invocations, invocation errors, average duration, and maximum
duration, with two collection-health panels. Its UID is `rosa-boundary-stage`.

The source JSON and its matching
[ConfigMap](manifests/grafana-dashboard-rosa-boundary-stage.configmap.yaml) belong
in this repository, under Boundary's existing `OWNERS`. The ConfigMap's folder
provider must be registered before Git-managed provisioning will work. See the
[deployment and ownership guide](../docs/configuration/operations-dashboard.md)
for the app-interface changes and live validation steps.

CloudWatch panels show sampled **60-second period values**, shifted forward ten
minutes to accommodate the exporter's default delay. Prometheus scrapes every
120 seconds, so some buckets can be omitted and others repeated. Do not derive
whole-range counts using `sum_over_time`, or apply `rate`/`increase`. Missing
samples stay missing. This dashboard makes no availability claim.

Metric naming follows upstream CloudWatch exporter source, rather than the
custom metric spelling in the onboarding MR. Live metric names, labels, and
rendering still need verification through an authenticated datasource.

After editing the JSON, regenerate the ConfigMap from the repository root:

```sh
python3 scripts/generate_dashboard_manifest.py
```

The [generator](../scripts/generate_dashboard_manifest.py) uses only the Python
standard library and resolves paths relative to the repository, so it also works
from another working directory. For a read-only CI check:

```sh
python3 scripts/generate_dashboard_manifest.py --check
```

Check mode exits with status 1 if the source JSON is invalid or the manifest is
missing or stale. The repository's pre-commit configuration runs this check when
dashboard files or the generator change.

The SaaS directory provider should point at `/dashboards/manifests`, which
contains only deployable ConfigMaps. The JSON can also be imported directly in
the stage UI; UI saves there are temporary and can be overwritten by Git.

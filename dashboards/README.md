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
python3 - <<'PY'
from pathlib import Path

source = Path('dashboards/rosa-boundary-stage.json')
target = Path('dashboards/manifests/grafana-dashboard-rosa-boundary-stage.configmap.yaml')
header = '''# Generated from dashboards/rosa-boundary-stage.json; see dashboards/README.md.
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-dashboard-rosa-boundary-stage
  labels:
    grafana_dashboard: "true"
  annotations:
    grafana-folder: /grafana-dashboard-definitions/ROSA Boundary
data:
  rosa-boundary-stage.json: |-
'''
target.write_text(header + ''.join('    ' + line + '\n' for line in source.read_text().splitlines()))
PY
```

The SaaS directory provider should point at `/dashboards/manifests`, which
contains only deployable ConfigMaps. The JSON can also be imported directly in
the stage UI; UI saves there are temporary and can be overwritten by Git.

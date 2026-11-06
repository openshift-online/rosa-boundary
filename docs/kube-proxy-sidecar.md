# Optional kube-proxy sidecar

The kube-proxy implementation remains available as an **opt-in** path. It is
disabled by default in both `deploy/regional/variables.tf` and the local-dev
`deploy/regional/Makefile`. The staging workspace does not set
`enable_kube_proxy`, so it inherits the Terraform default. Do not assume a
previously deployed stack changes until its configuration has been applied and
the effective task definition inspected.

## How it works

When `enable_kube_proxy = true`, `deploy/regional/ecs.tf` adds an essential
`kube-proxy` container and an ephemeral `proxy-tmp` volume to the ECS base task
definition. The SRE container waits for the sidecar's `oc proxy` health check.
The per-investigation task definition registered by
`lambda/create-investigation/handler.py` injects a Secrets Manager reference
for `rosa-boundary/clusters/{cluster_id}/kubeconfig` as `KUBECONFIG_DATA` in
the sidecar only. ECS fetches that secret with the **task execution role**.
The sidecar writes it to its private `/tmp/kubeconfig` and listens on
`127.0.0.1` at `kube_proxy_port` (default `8001`). The SRE container's entrypoint
writes a credential-free kubeconfig pointing to that port, allowing `oc` to
connect through the proxy. The SRE container does not mount `proxy-tmp`.

With the feature disabled, neither the sidecar nor its working volume or
`KUBE_PROXY_PORT` is configured in the base task definition. The entrypoint
therefore does not write a proxy kubeconfig. The Lambda preserves this setting
when registering per-investigation task definitions; it does not select the
sidecar on a per-cluster or per-user basis. Other supported credential flows
remain available; see [investigation workflow](runbooks/investigation-workflow.md).

The task's `/home/sre/.kube` and `/home/sre/.config/ocm` paths are task-scoped
overlays, not part of the persistent EFS home. The exit audit sync excludes
both paths as defense in depth; see `entrypoint.sh`. A new task does not inherit
the previous task's kubeconfig.

## Before enabling

This opt-in is **not a validated production authentication path**. The present
code does not create, rotate, or delete cluster kubeconfig secrets. Do not
provision long-lived or shared cluster credentials to make this work; Boundary
requires short-lived, identity-scoped task credentials. An operator must first
design and review a compliant secret lifecycle, its authorization/isolation
model, expiry behavior, and audit coverage. A missing secret will prevent the
sidecar from starting and, because the main container depends on its health,
prevent the investigation task from becoming usable.

After security review, enable it explicitly through the approved delivery
path: local dev via `TF_VAR_enable_kube_proxy=true` in the root `.env` (the
regional Makefile exports this value and overrides `terraform.tfvars`), or
staging via a PR to the Git-managed workspace definition in
`hcp-terraform/rosa-boundary/main.tf`. Verify the effective plan and base and
per-investigation task definitions, then validate task startup, proxy access,
failure handling, CloudWatch logs, S3 audit evidence, and cleanup against an
approved test cluster. No such live validation is implied by the current
Terraform, Lambda unit tests, or LocalStack task-definition tests.

The implementation is retained so it can be evaluated; disabling it does not
remove `oc proxy`, the Terraform resources, or the Lambda secret injection
path. Do not enable it merely by adding a permanent kubeconfig secret.

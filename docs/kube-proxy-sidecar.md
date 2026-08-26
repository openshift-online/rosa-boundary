# Kube-Proxy Sidecar

*This document authored exclusively by Claude Opus 4.6 - assume inaccuracies.* 

## Intent

The kube-proxy sidecar is an **optional second container** in the ECS task definition that
provides the main `rosa-boundary` SRE container with authenticated access to a ROSA cluster's
Kubernetes API, without exposing cluster credentials to the SRE user.

The design separates the **credential holder** (kube-proxy sidecar) from the
**credential consumer** (main SRE container):

```
┌─────────────────────────────────────────────────────────────────────┐
│ ECS Fargate Task                                                   │
│                                                                    │
│  ┌──────────────────────┐        ┌──────────────────────────────┐  │
│  │ kube-proxy sidecar   │        │ rosa-boundary (SRE container)│  │
│  │                      │        │                              │  │
│  │  KUBECONFIG_DATA ────┐        │  ~/.kube/config              │  │
│  │  (from Secrets Mgr)  │        │  server: localhost:8001 ─────┼──┤
│  │         │            │        │                              │  │
│  │         ▼            │ :8001  │  oc get pods                 │  │
│  │  /tmp/kubeconfig     │◄───────┤  kubectl get nodes           │  │
│  │         │            │        │  (no cluster credentials     │  │
│  │         ▼            │        │   visible to sre user)       │  │
│  │  oc proxy            │        │                              │  │
│  │  --address=127.0.0.1 ├────────►  Cluster API                │  │
│  │  --port=8001         │        │                              │  │
│  │                      │        │                              │  │
│  │  Volume: proxy-tmp   │        │  Volume: sre-home (EFS)      │  │
│  │  Mount: /tmp         │        │  Mount: /home/sre            │  │
│  │  readonlyRootFS: yes │        │                              │  │
│  └──────────────────────┘        └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

**Goal**: The SRE runs `oc` / `kubectl` commands against the cluster without ever seeing or
handling the cluster kubeconfig. The kubeconfig lives only inside the sidecar's ephemeral
`/tmp` volume.

## Current State

**The kube-proxy sidecar is defined in Terraform and the Lambda but has not been deployed
or validated end-to-end in a live environment.** The feature is gated by
`enable_kube_proxy` (default: `false`).

### What Exists

| Component | Status | Location |
|-----------|--------|----------|
| Terraform task definition (sidecar container + volume) | Implemented | `deploy/regional/ecs.tf:84-191` |
| Terraform variables (`enable_kube_proxy`, `kube_proxy_port`) | Implemented | `deploy/regional/variables.tf:56-66` |
| Lambda task def registration (Secrets Manager injection) | Implemented | `lambda/create-investigation/handler.py:534-555` |
| Entrypoint kubeconfig generation (`~/.kube/config`) | Implemented | `entrypoint.sh:63-81` |
| IAM execution role (Secrets Manager read) | Implemented | `deploy/regional/iam.tf:87-102` |
| Unit tests (Lambda sidecar logic) | Implemented | `lambda/create-investigation/test_handler.py:1564-1704` |
| Integration tests (task def structure) | Implemented | `tests/localstack/integration/test_kube_proxy_sidecar.py` |

### What Does NOT Exist

| Component | Status | Notes |
|-----------|--------|-------|
| Actual Secrets Manager secret for any cluster | Missing | No secret at `rosa-boundary/clusters/{cluster_id}/kubeconfig` has been created |
| Bats tests for entrypoint kubeconfig block | Missing | The `KUBE_PROXY_PORT` block in `entrypoint.sh:63-81` has zero bats-core tests (violates AGENTS.md requirement) |
| `CLUSTER_AUTH_METHOD` env var handling | Missing | Documented in AGENTS.md but not implemented anywhere |
| Go CLI awareness of kube-proxy | Missing | No references to kube-proxy in `cmd/` or `internal/` |
| End-to-end validation | Missing | Never deployed with `enable_kube_proxy = true` against a real cluster |
| Secret provisioning automation | Missing | No tooling to create/rotate the kubeconfig secret in Secrets Manager |

## Architecture Detail

### Container Definition (Terraform)

The sidecar is conditionally included in the task definition based on `enable_kube_proxy`.

**File**: `deploy/regional/ecs.tf:142-191`

```hcl
var.enable_kube_proxy ? [
{
  name      = "kube-proxy"
  image     = var.container_image     # Same image as the SRE container
  essential = true

  command = [
    "sh", "-c",
    "printf '%s' \"$KUBECONFIG_DATA\" > /tmp/kubeconfig && exec oc proxy --address=127.0.0.1 --port=${var.kube_proxy_port} --kubeconfig=/tmp/kubeconfig"
  ]

  environment = [
    { name = "HOME", value = "/tmp" }
  ]

  healthCheck = {
    command     = ["CMD-SHELL", "curl -sf http://127.0.0.1:${var.kube_proxy_port}/version || exit 1"]
    interval    = 10
    timeout     = 5
    retries     = 3
    startPeriod = 30
  }

  mountPoints = [
    { sourceVolume = "proxy-tmp", containerPath = "/tmp", readOnly = false }
  ]

  readonlyRootFilesystem = true

  logConfiguration = {
    logDriver = "awslogs"
    options   = { ... "awslogs-stream-prefix" = "kube-proxy" }
  }

  linuxParameters = { initProcessEnabled = true }
}
] : []
```

Key details:

- **Same image**: Reuses the `rosa-boundary` container image (which contains `oc`). This
  avoids maintaining a separate image but means the sidecar is much larger than necessary.
- **`essential = true`**: If the sidecar crashes, the entire task stops.
- **`readonlyRootFilesystem = true`**: The sidecar cannot write to its root filesystem.
  All writes go to the `proxy-tmp` ephemeral volume mounted at `/tmp`.
- **Health check**: Curls `localhost:8001/version` to verify the proxy is serving the
  cluster API. The SRE container's `dependsOn` waits for this health check to pass before
  starting.

### Startup Command

```sh
printf '%s' "$KUBECONFIG_DATA" > /tmp/kubeconfig && exec oc proxy --address=127.0.0.1 --port=8001 --kubeconfig=/tmp/kubeconfig
```

1. `KUBECONFIG_DATA` is an environment variable injected by ECS from Secrets Manager (via
   the `secrets` / `valueFrom` mechanism in the container definition).
2. The kubeconfig content is written to `/tmp/kubeconfig` (on the `proxy-tmp` ephemeral
   volume).
3. `oc proxy` starts, listening on `127.0.0.1:8001`, proxying requests to the cluster API
   defined in the kubeconfig.
4. `exec` replaces the shell so `oc proxy` becomes PID 1 (via `initProcessEnabled`).

### Secrets Manager Integration

The kubeconfig is stored in AWS Secrets Manager at a conventional path:

```
rosa-boundary/clusters/{cluster_id}/kubeconfig
```

The Lambda's `register_investigation_task_definition()` constructs the partial ARN and
injects it into the kube-proxy container definition as a `secrets` entry:

**File**: `lambda/create-investigation/handler.py:534-555`

```python
kubeconfig_secret_arn = (
    f'arn:aws:secretsmanager:{aws_region}:{aws_account_id}:'
    f'secret:rosa-boundary/clusters/{cluster_id}/kubeconfig'
)

# Injected into the kube-proxy container:
existing_secrets.append({
    'name': 'KUBECONFIG_DATA',
    'valueFrom': kubeconfig_secret_arn
})
```

ECS resolves `valueFrom` at task launch time using the **execution role** (not the task
role). The execution role has `secretsmanager:GetSecretValue` scoped to
`arn:...:secret:rosa-boundary/*` (`deploy/regional/iam.tf:87-102`).

**Important**: The secret is a partial ARN (no random suffix). ECS accepts partial ARNs
for Secrets Manager `valueFrom` references. If the secret does not exist, the task will
fail to start with a Secrets Manager error.

### Volume Configuration

Two volumes are defined in the task definition:

| Volume | Type | Used By | Mount Path | Purpose |
|--------|------|---------|------------|---------|
| `sre-home` | EFS (per-investigation access point) | `rosa-boundary` | `/home/sre` | Persistent SRE home directory |
| `proxy-tmp` | Ephemeral bind mount | `kube-proxy` | `/tmp` | Writable directory for kubeconfig file (sidecar has `readonlyRootFilesystem`) |

The `proxy-tmp` volume has **no `efsVolumeConfiguration`** — it is a plain Docker bind
mount (ephemeral storage on Fargate's 20GB writable layer). It is not shared with the
SRE container.

**Note**: The `proxy-tmp` volume is conditionally created in Terraform (`dynamic "volume"`
with `for_each = var.enable_kube_proxy ? [1] : []`), but the Lambda
**unconditionally includes it** in registered per-investigation task definitions
(`handler.py:521-523`). This is a discrepancy: the Lambda always adds `proxy-tmp` even if
the base task definition was created without it.

### Container Dependency

**File**: `deploy/regional/ecs.tf:100-105`

```hcl
dependsOn = var.enable_kube_proxy ? [
  {
    containerName = "kube-proxy"
    condition     = "HEALTHY"
  }
] : []
```

The SRE container will not start until the kube-proxy sidecar passes its health check.
The health check (`curl -sf http://127.0.0.1:8001/version || exit 1`) retries 3 times at
10-second intervals with a 30-second start period, giving the proxy up to 60 seconds to
become healthy.

If the sidecar never becomes healthy (e.g., invalid kubeconfig, Secrets Manager error),
the entire task fails to start.

### Entrypoint Kubeconfig Generation

**File**: `entrypoint.sh:63-81`

When the SRE container starts, the entrypoint checks for `KUBE_PROXY_PORT` and writes a
minimal kubeconfig pointing `oc` / `kubectl` at the local proxy:

```bash
if [ -n "${KUBE_PROXY_PORT}" ]; then
    mkdir -p /home/sre/.kube
    cat >/home/sre/.kube/config <<KUBECONFIG
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: http://localhost:${KUBE_PROXY_PORT}
  name: investigation
contexts:
- context:
    cluster: investigation
  name: investigation
current-context: investigation
KUBECONFIG
    chown sre:sre /home/sre/.kube /home/sre/.kube/config
fi
```

This kubeconfig contains **no credentials** — it simply points to `http://localhost:8001`.
The proxy handles authentication transparently.

## Configuration Parameters

### Terraform Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `enable_kube_proxy` | `bool` | `false` | Include the kube-proxy sidecar in the base task definition. When `false`, only the `rosa-boundary` container is defined. |
| `kube_proxy_port` | `number` | `8001` | Port the kube-proxy sidecar listens on (localhost only). Must match the port referenced in the health check and the SRE container's kubeconfig. |

### Environment Variables

| Variable | Set On | Source | Description |
|----------|--------|--------|-------------|
| `KUBE_PROXY_PORT` | `rosa-boundary` container | Terraform (`ecs.tf:117-118`) | Port number for kubeconfig generation. Consumed by `entrypoint.sh` to write `~/.kube/config`. |
| `KUBECONFIG_DATA` | `kube-proxy` container | Secrets Manager (`valueFrom`) | Full kubeconfig file content. Injected by ECS at task launch from `rosa-boundary/clusters/{cluster_id}/kubeconfig`. |
| `HOME` | `kube-proxy` container | Terraform (`ecs.tf:155-156`) | Set to `/tmp` so `oc proxy` writes its state to the writable `proxy-tmp` volume instead of the read-only root filesystem. |
| `CLUSTER_AUTH_METHOD` | Documented only | AGENTS.md | Described as `backplane` or `proxy` but **not implemented** anywhere in the codebase. |

### Secrets Manager

| Secret Path | Format | Created By |
|-------------|--------|------------|
| `rosa-boundary/clusters/{cluster_id}/kubeconfig` | Full kubeconfig YAML content (as a plaintext string secret) | Manual / not automated |

### Makefile Default Override

The `deploy/regional/Makefile` defaults `TF_VAR_enable_kube_proxy` to `true` when sourced
from `.env` (line 27):

```makefile
export TF_VAR_enable_kube_proxy := $(shell source $(ENV_FILE) 2>/dev/null && echo $${TF_VAR_enable_kube_proxy:-true})
```

This conflicts with the Terraform variable default of `false`. The Makefile default takes
precedence when deploying via `make plan` / `make apply`, meaning **the sidecar is enabled
by default in Makefile-driven deployments** unless explicitly overridden in `.env`.

## IAM Permissions

### Execution Role (pulls secret at task launch)

**File**: `deploy/regional/iam.tf:87-102`

```hcl
Action = [
  "secretsmanager:GetSecretValue",
  "secretsmanager:DescribeSecret"
]
Resource = "arn:...:secret:rosa-boundary/*"
```

Scoped to secrets under the `rosa-boundary/` prefix. This is the role ECS uses to resolve
`valueFrom` references before starting the container.

### Task Role (runtime — no Secrets Manager access)

The task role does **not** have `secretsmanager:GetSecretValue`. The SRE user cannot read
the kubeconfig from Secrets Manager at runtime. Credential isolation is enforced by
architecture: the sidecar holds the credentials, the SRE container only sees
`localhost:8001`.

## Known Issues and Gaps

### 1. `KUBE_PROXY_PORT` is always set (even when sidecar is disabled)

**File**: `deploy/regional/ecs.tf:116-119`

The `KUBE_PROXY_PORT` environment variable is unconditionally included in the
`rosa-boundary` container's environment, regardless of `enable_kube_proxy`. This means
`entrypoint.sh` will always write `~/.kube/config` pointing to `localhost:8001`, even when
there is no kube-proxy sidecar running.

**Impact**: Without the sidecar, `oc` commands will attempt to connect to
`localhost:8001` and fail with a connection refused error. This is confusing — the SRE sees
a connection error rather than a "not configured" message.

**Fix**: The `KUBE_PROXY_PORT` environment variable should be conditionally included,
matching the `enable_kube_proxy` gate:

```hcl
environment = concat([
  { name = "CLAUDE_CODE_USE_BEDROCK", value = "1" },
  { name = "TASK_TIMEOUT", value = tostring(var.task_timeout_default) },
], var.enable_kube_proxy ? [
  { name = "KUBE_PROXY_PORT", value = tostring(var.kube_proxy_port) }
] : [])
```

### 2. Lambda unconditionally includes `proxy-tmp` volume

**File**: `lambda/create-investigation/handler.py:521-523`

The Lambda's `register_investigation_task_definition()` hardcodes the `proxy-tmp` volume
in every registered task definition:

```python
volumes = [
    { 'name': 'sre-home', 'efsVolumeConfiguration': { ... } },
    { 'name': 'proxy-tmp' }  # Always included
]
```

When `enable_kube_proxy = false`, the base task definition has no `kube-proxy` container
and no `proxy-tmp` volume. The Lambda then adds a volume that no container references. This
is harmless but inconsistent.

**Fix**: The Lambda should only include `proxy-tmp` if the base task definition contains a
`kube-proxy` container:

```python
if any(cd['name'] == 'kube-proxy' for cd in base_td.get('containerDefinitions', [])):
    volumes.append({'name': 'proxy-tmp'})
```

### 3. No bats tests for entrypoint kubeconfig block

The `KUBE_PROXY_PORT` block in `entrypoint.sh:63-81` (creating `~/.kube/config`, setting
ownership) has no corresponding bats-core tests. This violates the repository's hard
requirement that all bash functions have bats tests.

Tests should cover:
- Kubeconfig is created when `KUBE_PROXY_PORT` is set
- Kubeconfig is not created when `KUBE_PROXY_PORT` is unset
- Kubeconfig contains the correct server URL
- File ownership is `sre:sre`
- Directory `~/.kube` is created if missing

### 4. No secret provisioning tooling

There is no automation or CLI command to create the Secrets Manager secret
(`rosa-boundary/clusters/{cluster_id}/kubeconfig`). The expected workflow for provisioning
the kubeconfig is undocumented.

Questions:
- Who creates the kubeconfig? (Human operator? CI pipeline? backplane tooling?)
- What format is expected? (Full kubeconfig YAML? Just the server + token?)
- How is the kubeconfig rotated when cluster credentials expire?
- What happens when a cluster is decommissioned? (Secret cleanup?)

### 5. Kubeconfig written to EFS

**File**: `entrypoint.sh:65-79`

The entrypoint writes `~/.kube/config` to `/home/sre/.kube/config`, which is on the EFS
volume. This means:

- The kubeconfig is **shared** across all SREs in the same investigation (EFS is
  per-investigation, not per-task).
- The kubeconfig is **synced to S3** on container exit (via `sync_to_s3()`).

The kubeconfig itself contains no credentials (just `server: http://localhost:8001`), so
this is not a credential leak. However, it could cause confusion if multiple SREs in the
same investigation have different proxy configurations, or if the kubeconfig is modified by
one SRE and affects another.

### 6. Security finding: kubeconfig readable by SRE in sidecar

**File**: `docs/adversary-findings_20260702.json` (finding M12)

The adversary agent flagged that the sidecar writes the cluster kubeconfig to
`/tmp/kubeconfig` inside the `proxy-tmp` volume. While this volume is not mounted in the
SRE container (isolation is correct), the kubeconfig inside the sidecar is readable by the
process running `oc proxy`.

The finding recommends:
1. Set the kubeconfig file to read-only after creation (`chmod 400`)
2. Consider using a named pipe or env-var injection instead of a file
3. Restrict S3 sync from syncing `.kube/` contents

Items 1 and 2 are sidecar-internal improvements. Item 3 is addressed by the fact that
`~/.kube/config` contains only `localhost:8001` (no credentials), though excluding it from
sync would still be good hygiene.

### 7. Default conflict between Terraform and Makefile

`variables.tf` defaults `enable_kube_proxy` to `false`. The `deploy/regional/Makefile`
defaults it to `true`. Deployments via `make apply` vs. direct `terraform apply` will
produce different task definitions unless the `.env` file explicitly sets the value.

## Prerequisite: Creating the Kubeconfig Secret

Before enabling the kube-proxy sidecar, a Secrets Manager secret must exist for each
cluster that will be investigated. The secret must be a valid kubeconfig that can
authenticate to the cluster's API server.

```bash
# Example: store a kubeconfig for cluster "my-cluster-id"
aws secretsmanager create-secret \
  --name "rosa-boundary/clusters/my-cluster-id/kubeconfig" \
  --secret-string "$(cat /path/to/kubeconfig.yaml)" \
  --region us-east-2
```

The kubeconfig must contain:
- A cluster entry with the API server URL and CA certificate
- A user entry with valid credentials (token, client cert, or exec-based auth)
- A context binding the cluster and user

**If the secret does not exist when a task is launched for that cluster, the task will fail
to start.** ECS cannot resolve the `valueFrom` reference and will report a Secrets Manager
error in the task's stopped reason.

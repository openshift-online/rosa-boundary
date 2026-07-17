# AGENTS.md

This file provides guidance to AI agents (Claude Code, etc.) when working with code in this repository. It also documents hard requirements, coding standards, and pre-PR quality gates that all contributors (human and AI) must follow.

---

## Repository Purpose

Multi-architecture container for AWS Fargate that provides tools for managing AWS and OpenShift (ROSA) clusters. Part of an **access control pattern** that combines:

- **Identity**: Keycloak (Red Hat build) for OIDC authentication
- **Infrastructure**: ECS Fargate with SSM for ephemeral SRE containers

Designed for ephemeral SRE use with ECS Exec access as the `sre` user. The entrypoint script supports dynamic version selection via environment variables, signal handling for graceful shutdown with S3 backup, and defaults to `sleep infinity`.

**For complete architecture and integration details**, see [`docs/`](docs/README.md).

## Development Workflow

### Tool Usage Guidelines

**IMPORTANT**: Always use Makefiles and Terraform for builds and deployments:
- **Container builds**: Use `make` commands (never `podman build` directly)
- **Go CLI builds**: Use `make build-cli`, `make test-cli`, etc. (root Makefile)
- **Lambda builds**: Use root `make test-lambda-*` targets (only `create-investigation` has its own Makefile for bundling deps)
- **Infrastructure**: Use `make` targets in `deploy/regional/` (`make init`, `make plan`, `make apply`) — never run `terraform` directly. `make apply` automatically builds Lambda deps via `build-lambda` before running Terraform.

### Environment Configuration

**Required variables** without Terraform defaults must be supplied in `.env` at the project root:
- If a Terraform variable lacks a default value, check `.env` first
- If missing from `.env`, prompt the user to add it
- Never hardcode environment-specific values in tool commands

**Example**: `keycloak_issuer_url` has no default in `variables.tf`, so it must be in `.env` as `KEYCLOAK_ISSUER_URL`.

## Building

```bash
# Build both architectures and create manifest list
make all

# Build single architecture
make build-amd64
make build-arm64

# Create manifest list from existing builds
make manifest

# Remove all images and manifests
make clean
```

The `make manifest` target creates an OCI image index containing both architectures; Podman/Docker automatically selects the correct platform when pulling `rosa-boundary:latest`.

## Go CLI

The `rosa-boundary` Go CLI (`cmd/rosa-boundary/`) replaces the former shell scripts in `tools/`.

### Build

```bash
make build-cli      # Build Go CLI to ./bin/rosa-boundary
make install-cli    # Install CLI to GOBIN (~/go/bin)
make test-cli       # Run Go unit tests
make fmt            # Format Go + shell code
make lint           # Lint Go + shell code
make staticcheck    # Static analysis
```

### Subcommands

| Command | Description |
|---------|-------------|
| `login` | Authenticate via Keycloak OIDC (PKCE browser flow), cache token |
| `create-investigation` | Create EFS access point only (no task); OIDC-authenticated via Lambda |
| `start-task` | Invoke Lambda to create an investigation task (reuses existing access point if present) |
| `join-task` | Connect to a running investigation via ECS Exec |
| `list-tasks` | List running investigation tasks |
| `stop-task` | Stop a running investigation task |
| `close-investigation` | Stop tasks, deregister task defs, delete EFS access point |
| `configure` | Interactively write `~/.config/rosa-boundary/config.yaml` |
| `version` | Print CLI version |

### Configuration

Configuration is resolved in priority order: flags > env vars > config file > defaults.

- **Config file**: `~/.config/rosa-boundary/config.yaml` (XDG: `$XDG_CONFIG_HOME/rosa-boundary/config.yaml`)
- **Env vars**: `ROSA_BOUNDARY_<KEY>` (e.g., `ROSA_BOUNDARY_LAMBDA_FUNCTION_NAME`); legacy un-prefixed names also accepted as fallback
- **Cache**: `~/.cache/rosa-boundary/` (XDG: `$XDG_CACHE_HOME/rosa-boundary/`)

Key config fields:

| Field | Env var | Flag | Description |
|-------|---------|------|-------------|
| `lambda_function_name` | `ROSA_BOUNDARY_LAMBDA_FUNCTION_NAME` | `--lambda-function-name` | Lambda function name or ARN |
| `invoker_role_arn` | `ROSA_BOUNDARY_INVOKER_ROLE_ARN` | `--invoker-role-arn` | Lambda invoker role ARN |
| `sre_role_arn` | `ROSA_BOUNDARY_SRE_ROLE_ARN` | `--role-arn` | Shared SRE ABAC role ARN |
| `efs_filesystem_id` | `ROSA_BOUNDARY_EFS_FILESYSTEM_ID` | `--efs-filesystem-id` | EFS filesystem ID (required for `close-investigation`) |
| `ecs_cluster_name` | `ROSA_BOUNDARY_ECS_CLUSTER_NAME` | `--ecs-cluster` | ECS cluster name |
| `aws_region` | `ROSA_BOUNDARY_AWS_REGION` | `--region` | AWS region |

### Key Design Notes

- **Direct Lambda SDK invocation**: The CLI calls Lambda directly (no shell curl) to stay SCP-compliant
- **Two-step role assumption**: Assumes the invoker role first, then the shared SRE ABAC role
- **`join-task` process replacement**: `exec`s `session-manager-plugin` for a seamless terminal handoff
- **Prerequisite**: `session-manager-plugin` must be installed and in `PATH`

## Testing Containers Locally

```bash
# Run interactively with default versions
podman run -it rosa-boundary:latest /bin/bash

# Test a specific OC version
podman run --rm -e OC_VERSION=4.18 rosa-boundary:latest oc version --client

# Test S3 sync on exit (warns without credentials)
podman run --rm -e S3_AUDIT_ESCROW=s3://test-bucket/test/ \
  rosa-boundary:latest sh -c "echo 'test' > /home/sre/test.txt && exit"

# Check alternatives configuration
podman run --rm rosa-boundary:latest alternatives --display oc
```

## Container Architecture

### Multi-Architecture Build

The Containerfile uses multi-stage builds with `platform_convert` to detect architecture at build time. When podman builds with `--platform linux/arm64`, RUN commands execute in QEMU emulation where `uname -m` returns `aarch64`. For `--platform linux/amd64`, it returns `x86_64`.

### Tool Installation

**backplane-tools** (via builder stage with authenticated GitHub API calls):
- `oc`, `ocm`, `ocm-backplane`, `osdctl`, `ocm-addons`, `yq`, `aws` CLI v2

**OpenShift CLI** (via builder stage with checksum verification):
- Versions 4.14–4.20 installed to `/opt/openshift/{version}/oc`
- Managed via `alternatives` system with priority-based default (4.20 = priority 100)

**Claude Code** (via builder stage from GitHub Releases with SHA256 verification):
- Downloaded from `anthropics/claude-code` GitHub Releases
- Verified against `SHASUMS256.txt`
- Installed to `/usr/local/lib/claude-code`

**fzf** (via builder stage with checksum verification):
- Downloaded from `junegunn/fzf` GitHub Releases
- Shell integration scripts installed to `/usr/share/fzf/shell/`

### Entrypoint Behavior

`entrypoint.sh` runs at container start and:

1. **Traps signals** (SIGTERM, SIGINT, SIGHUP) so `cleanup()` can sync data before exit
2. **Switches OC version** via `alternatives --set` if `OC_VERSION` is set
3. **Configures kube-proxy** kubeconfig if `KUBE_PROXY_PORT` is set
4. **Copies skeleton config** from `/etc/skel-sre/` to `/home/sre/` on first run only (preserves user customizations on subsequent runs)
5. **Configures Bedrock**: enables `CLAUDE_CODE_USE_BEDROCK=1`, auto-detects `AWS_REGION` from ECS task metadata, falls back to `us-east-1`
6. **Handles cluster command mode**: if CMD is not interactive and `CLUSTER_ID` is set, performs cluster login first
7. **Runs the command** in background with `&` (cannot use `exec` — it replaces the shell and traps won't fire)
8. **On exit or signal**: `sync_to_s3()` runs `aws s3 sync /home/sre` to the configured S3 URI

### Shell Environment (bashrc.d)

Modular shell configuration via `~/.bashrc.d/*.bashrc` sourced in numeric order:

| File | Purpose |
|------|---------|
| `00-history.bashrc` | Shell history configuration |
| `04-kube-ps1-libs.bashrc` | Vendored kube-ps1 library |
| `06-sre-login-libs.bashrc` | `cluster_function()` for kube-ps1 display |
| `08-vim.bashrc` | Vim alias |
| `10-completions.bashrc` | Tab completion for all CLIs |
| `10-fzf.bashrc` | fzf key bindings and completion |
| `14-kube-ps1.bashrc` | PS1 prompt with environment and kube context |
| `26-sre-login.bashrc` | Auto cluster login on entry |
| `50-tmux.bashrc` | tmux auto-start (ENV-gated) |
| `99-cluster-context.bashrc` | Cluster context display on login |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OC_VERSION` | 4.20 via alternatives | Select OC CLI version: 4.14–4.20 |
| `KUBE_PROXY_PORT` | — | Configure oc to use kube-proxy sidecar |
| `S3_AUDIT_ESCROW` | — | S3 URI for /home/sre sync on exit |
| `S3_AUDIT_BUCKET` | — | Bucket for auto-generated S3 path |
| `CLUSTER_ID` | — | Cluster ID for investigation |
| `INVESTIGATION_ID` | — | Investigation ID |
| `OCM_ENVIRONMENT` | — | OCM environment name for PS1 display |
| `CLUSTER_AUTH_METHOD` | `backplane` | Auth method: `backplane` or `proxy` |
| `TMUX_AUTOSTART` | `0` | Set to `1` to auto-start tmux |
| `SHOW_CLUSTER_CONTEXT` | `1` | Set to `0` to skip cluster context display |
| `TASK_TIMEOUT` | 3600 | Timeout in seconds; enforced by reaper Lambda |
| `SYNC_TIMEOUT` | 300 | Max seconds for `aws s3 sync` on exit |
| `CLAUDE_CODE_USE_BEDROCK` | `1` | Enable Claude Code Bedrock mode |
| `AWS_REGION` | auto-detected | Bedrock region |
| `ANTHROPIC_MODEL` | — | Override Claude model ID |

### Claude Code Integration

- Installed from GitHub Releases with SHA256 verification to `/usr/local/lib/claude-code`
- Auto-updates disabled in `skel/sre/.claude/settings.json`
- Skeleton config (`skel/sre/.claude/`) is copied to `/etc/skel-sre/` at build time and initialized to `/home/sre/.claude/` at first runtime
- For Bedrock IAM requirements, see [`docs/configuration/aws-iam-policies.md`](docs/configuration/aws-iam-policies.md)

## Adding New OpenShift Versions

1. Add the version to the download loop in the `oc-versions` builder stage
2. Add an `alternatives --install` line in the alternatives registration block with priority equal to the minor version number
3. If the new version should be the default, change its priority to `100` and lower the previous default
4. Update `OC_VERSION` documentation in `README.md` and the validation logic in `entrypoint.sh`

## Repository Layout

```
rosa-boundary/
├── AGENTS.md                  # This file — agent guidance, requirements, quality gates
├── CLAUDE.md                  # References AGENTS.md
├── Containerfile              # Multi-stage multi-arch container build
├── entrypoint.sh              # Runtime init: version selection, S3 sync, Bedrock setup
├── Makefile                   # Build targets: container, CLI, tests, fmt, lint, SARIF
├── .containerignore           # Build context exclusions
├── .shellcheckrc              # Shellcheck configuration
├── adversary-findings.json    # Security findings (source of truth for SARIF)
├── go.mod / go.sum            # Go module files
├── cmd/rosa-boundary/         # Go CLI entry point (main.go)
├── internal/
│   ├── cmd/                   # Cobra subcommand implementations
│   ├── auth/                  # OIDC PKCE flow and token caching
│   ├── aws/                   # ECS, STS, and session-manager-plugin helpers
│   ├── config/                # XDG config/cache paths, viper wiring
│   ├── lambda/                # Lambda invocation client
│   └── output/                # Terminal output helpers
├── skel/sre/                  # Skeleton user config (copied to /home/sre at runtime)
│   ├── .bashrc                # bashrc.d sourcing loop
│   ├── .bash_profile          # Profile sourcing
│   ├── .inputrc               # Bracketed paste
│   ├── .bashrc.d/             # Modular shell configuration
│   ├── .claude/               # Claude Code config (CLAUDE.md, settings.json)
│   └── .local/bin/            # User-local scripts (sre-login, etc.)
├── build/                     # Containerfile build helpers (platform_convert, github_dl)
│                              # Per Go standard project layout: packaging and CI
├── deploy/
│   ├── keycloak/              # Kustomize config for Keycloak (RHBK) on OpenShift
│   └── regional/              # Terraform for AWS Fargate deployment
├── lambda/
│   ├── create-investigation/  # OIDC-authenticated investigation creation
│   └── reap-tasks/            # Periodic task timeout enforcement
├── scripts/
│   └── findings-to-sarif.py   # Converts adversary-findings.json → SARIF 2.1.0
├── tests/
│   ├── shell/                 # bats-core tests for shell scripts and bashrc.d
│   └── localstack/            # LocalStack integration tests
└── docs/
    ├── architecture/overview.md
    ├── configuration/aws-iam-policies.md
    ├── configuration/keycloak-realm-setup.md
    └── runbooks/
```

## Reaper Lambda (Task Timeout Enforcement)

**Location**: `lambda/reap-tasks/`

The reaper Lambda provides tamper-proof task timeout enforcement via periodic checks of task deadline tags:

**Architecture**:
1. **Periodic Trigger**: EventBridge rule invokes Lambda every 15 minutes (configurable via `reaper_schedule_minutes`)
2. **Task Discovery**: Lists all RUNNING tasks in the ECS cluster
3. **Deadline Check**: Parses `deadline` tag (ISO 8601 format) and compares to current time
4. **Task Termination**: Calls `ecs:StopTask` for tasks where `now > deadline`
5. **Graceful Handling**: Per-task error handling; invalid deadline formats are skipped

**Deadline Tag Flow**:
1. Create-investigation Lambda computes: `deadline = created_at + task_timeout`
2. Deadline stored as ISO 8601 string in task tags: `{'key': 'deadline', 'value': '2026-02-16T12:34:56'}`
3. Reaper parses deadline: `datetime.fromisoformat(deadline_str)`
4. If `now > deadline`: calls `ecs.stop_task(reason='Task deadline exceeded (deadline: {deadline_str})')`

**Security Properties**:
- **Tamper-proof**: Task tags only modifiable via ECS API (requires IAM permissions not available in container)
- **Deterministic**: Deadline computed at task creation, immutable after launch
- **Fail-safe**: Tasks without deadline tag are skipped (optional enforcement)

**Terraform**: `deploy/regional/lambda-reap-tasks.tf`; `reaper_schedule_minutes` variable (default: 15, range: 1-1440)

**IAM Permissions Required**: `ecs:ListTasks`, `ecs:DescribeTasks` (conditioned on cluster ARN), `ecs:StopTask` (scoped to `task/{cluster}/*`)

**Tests**: `make test-lambda-reap-tasks` (unit), `tests/localstack/integration/test_task_timeout.py` (integration)

## Investigation Isolation Model

Each investigation gets:
- **Unique EFS access point**: `/$cluster_id/$investigation_id/` mounted to `/home/sre`
- **Unique task definition**: `rosa-boundary-dev-$cluster_id-$investigation_id-TIMESTAMP` with locked OC version and pre-configured env vars
- **Unique S3 paths per task**: `s3://bucket/$cluster_id/$investigation_id/$date/$task_id/`

**EFS Access Point Limit**: 10,000 per filesystem.

Two creation workflows: **Lambda-based** (recommended, OIDC-authenticated, `sre-team` group checked) via `rosa-boundary start-task`, and **manual lifecycle scripts** via `deploy/regional/examples/`. See [`docs/runbooks/investigation-workflow.md`](docs/runbooks/investigation-workflow.md).

**Shared ABAC SRE Role**: All SREs assume a single shared role (`sre_role_arn`). Access is scoped at runtime by ABAC conditions — the role can only exec into tasks whose `username` tag matches the caller's `aws:PrincipalTag/username` session tag (propagated from the Keycloak JWT via STS `TagSession`).

## Keycloak on OpenShift

`deploy/keycloak/` is a **Kustomize** configuration (not Terraform) for deploying Keycloak (RHBK operator) on an OpenShift cluster:

- **CloudNativePG** (PostgreSQL 18.1) for Keycloak state
- **ExternalSecrets** pulls DB credentials from AWS SSM Parameter Store (`/keycloak/db/*`)
- **Edge TLS**: OpenShift Router terminates TLS; Keycloak serves HTTP
- Overlay (`overlays/dev/`) adds ClusterSecretStore, ExternalSecret-based service account, and IRSA-based secret access

```bash
oc apply -k deploy/keycloak/overlays/dev
```

For realm and OIDC client configuration, see [`docs/configuration/keycloak-realm-setup.md`](docs/configuration/keycloak-realm-setup.md).

## LocalStack Integration Testing

35 integration tests in `tests/localstack/integration/` cover S3, IAM, Lambda, KMS, EFS, ECS, SSM, and CloudWatch Logs.

### Running Tests

```bash
make localstack-up           # Start LocalStack Pro + mock OIDC
make test-localstack-fast    # Skip slow ECS task launches
make test-localstack         # Full test suite
make localstack-down
```

### Prerequisites

**macOS**: Podman machine running + `brew install podman-compose` + LocalStack Pro token in `tests/localstack/.env`
```bash
uv venv && source .venv/bin/activate && uv pip install pytest boto3 requests
```

**Linux**: `systemctl --user enable --now podman.socket` + `uv pip install --system podman-compose pytest boto3 requests`

### Key Notes

- **macOS**: `compose.yml` uses `local` executors (not `docker`/`podman`) to avoid socket issues — tests validate AWS API compliance, not container execution. Prow CI uses `compose.ci.yml` with `LAMBDA_EXECUTOR=local` (no Docker socket required).
- **Service names**: LocalStack uses `efs` (not `elasticfilesystem`), `ssm` (not `systems-manager`)
- **Version**: LocalStack Pro ≥ 4.4.0 required; use `latest` tag in compose files
- **Test markers**: `@pytest.mark.integration` (all), `@pytest.mark.slow` (ECS task launches), `@pytest.mark.e2e` (end-to-end)

See `tests/localstack/README.md` for full documentation including troubleshooting and adding tests.

## Prow CI

**Triggers**: PRs and merges to `main` touching `lambda/`, `deploy/regional/`, or `tests/localstack/`.

**Required secret**: `LOCALSTACK_AUTH_TOKEN` stored in Vault at `selfservice/rosa-boundary/ci` (key: `localstack-token`); synced to CI cluster secret `localstack-token` in namespace `ci`.

**Jobs** (defined in `openshift/release` at `ci-operator/jobs/openshift-online/rosa-boundary/`):
1. **pull-ci-openshift-online-rosa-boundary-main-localstack-integration-tests** — presubmit; integration tests

**Architecture**: CI entrypoint is `tests/localstack/ci-run.sh`. It starts LocalStack Pro in a podman container, mounts `init-aws.sh` as an init hook (auto-runs on ready), waits for the ECS service, then runs `pytest integration/ -v --tb=short` against the full suite.

**Lambda tests**: Auto-skipped under `LAMBDA_EXECUTOR=local`; covered by moto unit tests (`make test-lambda-create-investigation`).

## Security Findings

The adversary agent (`/adversary`) writes security findings to `adversary-findings.json` at the repo root. A deterministic Python converter (`scripts/findings-to-sarif.py`) transforms findings to SARIF 2.1.0 format for GitHub code scanning.

### Workflow

1. Run the adversary agent to scan for vulnerabilities — it reads/writes `adversary-findings.json`
2. Convert to SARIF: `make convert-sarif`
3. Upload to GitHub: `make upload-sarif` (requires `gh` CLI)

### Make Targets

| Target | Description |
|--------|-------------|
| `make validate-findings` | Validate `adversary-findings.json` structure |
| `make convert-sarif` | Convert findings JSON to SARIF format |
| `make upload-sarif` | Convert and upload SARIF to GitHub code scanning |

---

## Hard Requirements for Container Image

These are non-negotiable standards for all changes to the container image, Containerfile, shell scripts, and entrypoint. Violations must be fixed before merge.

### Build Standards

1. **Multi-stage builds only** — all downloads and compilation happen in builder stages. Only final artifacts are COPY'd into the shipped image. No build tools, tarballs, or installer artifacts in the final image.
2. **Multi-arch support** — amd64 and arm64. Use `platform_convert` for architecture-dependent URLs. Test both architectures.
3. **NO `curl | bash`** — every binary must be downloaded explicitly with a known URL and verified checksum. No piping remote scripts into a shell interpreter.
4. **NO npm installs** — npm is not a trusted delivery mechanism for this project. Binaries come from GitHub Releases, RPM repos, or backplane-tools.
5. **Checksum verification required** — all binaries not installed via `dnf` or `backplane-tools` must be verified against a published checksum file (SHA256 minimum). Use the `github_dl` helper or equivalent.
6. **All GitHub API calls must be authenticated** — use `--mount=type=secret,id=GITHUB_TOKEN` in builder stages. The `github_dl` helper resolves tokens from build secret mounts. Unauthenticated GitHub API calls are not permitted (rate limiting).
7. **Pinned versions** — all externally downloaded tools must have a pinned version ARG in the Containerfile. backplane-tools is the exception (it manages its own versions). Renovate updates version pins via PR.
8. **Single image** — no tiered builds (micro/minimal/full). One image, one target.
9. **UBI9 base** — `registry.access.redhat.com/ubi9/ubi` with a pinned digest. Do not change the base image without explicit approval.

### Shell Script Standards

1. **All bash scripts must have bats-core unit tests** — every function in `entrypoint.sh`, every `bashrc.d/*.bashrc` file, and every utility script in `utils/` must have corresponding tests in `tests/shell/`.
2. **Shellcheck clean** — all shell scripts must pass `shellcheck` with zero warnings. The `.shellcheckrc` at the repo root defines project-wide exceptions.
3. **Testability guard** — scripts that contain executable code must use `if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then main "$@"; fi` so they can be sourced by bats tests without triggering execution.
4. **bashrc.d numeric ordering** — files are sourced in lexicographic order. Use `NN-category.bashrc` naming. Group related functionality under the same prefix.
5. **Well-commented** — every function must have a comment explaining its purpose. Every ENV-gated feature must document the variable name, default, and behavior.
6. **ENV-gated features** — optional behaviors (tmux auto-start, cluster context display, auth method) must be controlled via environment variables with documented defaults. Features must degrade gracefully when the ENV is unset.
7. **Long-form flags only** — always use full double-dash flags in shell scripts (e.g., `grep --only-matching` not `grep -o`, `mkdir --parents` not `mkdir -p`, `curl --silent` not `curl -s`). Humans must be able to read and approve shell code at a glance. The only exceptions are: (a) builtins with no long form (`set -e`, `[ -n`, `[ -f`), (b) tools that genuinely have no long-form equivalent (`unzip -q`, POSIX `awk -F`), and (c) command examples in documentation aimed at interactive use.

### Containerfile Standards

1. **Well-commented** — every stage must have a block comment explaining what it does, why it exists, and what it produces. Every non-obvious RUN instruction must have an inline comment.
2. **OCI labels** — use `org.opencontainers.image.*` labels.
3. **Layer optimization** — merge related RUN instructions. Use `COPY --chmod` instead of separate chmod layers. Order layers by change frequency (least-changing first).
4. **Clean cache** — every `dnf install` must end with `dnf clean all && rm -rf /var/cache/yum`.
5. **No secrets in layers** — use `--mount=type=secret` for tokens. Never `COPY` or `ARG` a secret value.
6. **Long-form flags only** — all commands in `RUN` instructions must use long-form flags where available (e.g., `dnf install --assumeyes` not `-y`, `tar --extract --gzip --file=- --directory=` not `-xzf - -C`, `mkdir --parents` not `-p`, `rm --force` not `-f`, `useradd --create-home --shell` not `-m -s`). Same exceptions as the shell script standard.

### Security Standards

1. **Non-root user** — the `sre` user (UID 1000) is the runtime user for ECS Exec sessions. The entrypoint runs as root only for `alternatives --set` operations.
2. **S3 audit sync** — every container exit must attempt to sync `/home/sre` to S3. The `sync_to_s3()` function must not be removed or bypassed.
3. **Signal handling** — SIGTERM, SIGINT, SIGHUP must be trapped and routed through `cleanup()` which calls `sync_to_s3()` before exit.
4. **No symlink following** — S3 sync uses `--no-follow-symlinks` to prevent symlink-based exfiltration.
5. **Tamper-proof timeouts** — task deadlines are enforced by the reaper Lambda, not by the container. `TASK_TIMEOUT` is informational inside the container.

---

## Pre-PR Quality Gates

All of the following must pass locally before creating a pull request. CI will also enforce these, but catching failures locally saves review cycles.

### Shell Tests (required for any shell/bashrc.d/entrypoint changes)

```bash
# Run all bats-core tests
make test-shell

# Run shellcheck on all shell scripts (must be zero warnings)
make lint-shell
```

### Go Tests (required for any Go code changes)

```bash
# Run Go unit tests
make test-cli

# Format check (must produce no diff)
make fmt

# Lint (must pass)
make lint

# Static analysis
make staticcheck
```

### Lambda Tests (required for any Lambda code changes)

```bash
# Unit tests for create-investigation Lambda
make test-lambda-create-investigation

# Unit tests for reap-tasks Lambda
make test-lambda-reap-tasks

# Full Lambda unit test suite
make test-lambda
```

### Integration Tests (required for Lambda, Terraform, or ECS changes)

```bash
# Start LocalStack
make localstack-up

# Run fast tests (skip slow ECS task launches)
make test-localstack-fast

# Run full suite
make test-localstack

# Cleanup
make localstack-down
```

### Container Build (required for Containerfile, entrypoint, or skel changes)

```bash
# Build the image (requires GITHUB_TOKEN for authenticated GitHub API calls)
make build

# Verify tools are installed and working
podman run --rm rosa-boundary:amd64 oc version --client
podman run --rm rosa-boundary:amd64 ocm version
podman run --rm rosa-boundary:amd64 aws --version
podman run --rm rosa-boundary:amd64 claude --version
podman run --rm rosa-boundary:amd64 fzf --version
podman run --rm rosa-boundary:amd64 osdctl --help

# Verify alternatives
podman run --rm rosa-boundary:amd64 alternatives --display oc

# Verify tab completions exist
podman run --rm rosa-boundary:amd64 ls /etc/bash_completion.d/

# Test interactive session
podman run -it --rm rosa-boundary:amd64 /bin/bash
# Verify: PS1 shows environment context
# Verify: Ctrl-R triggers fzf history search
# Verify: bashrc.d scripts sourced (check with `declare -F`)
```

### Security Findings (required when adversary findings change)

```bash
# Validate findings structure
make validate-findings

# Convert to SARIF
make convert-sarif
```

### Pre-commit Hooks

```bash
# Run all pre-commit hooks
pre-commit run --all-files
```

### Summary Checklist

Before opening a PR, confirm:

- [ ] `make test-shell` passes (if shell changes)
- [ ] `make lint-shell` passes with zero warnings (if shell changes)
- [ ] `make test-cli` passes (if Go changes)
- [ ] `make fmt` produces no diff (if Go changes)
- [ ] `make lint` passes (if Go changes)
- [ ] `make test-lambda` passes (if Lambda changes)
- [ ] `make test-localstack-fast` passes (if infrastructure changes)
- [ ] `make build` succeeds for at least one architecture (if Containerfile changes)
- [ ] Container tools verified interactively (if Containerfile changes)
- [ ] `pre-commit run --all-files` passes
- [ ] No secrets, tokens, or credentials in committed code
- [ ] Comments explain WHY, not WHAT
- [ ] New ENV variables are documented in this file

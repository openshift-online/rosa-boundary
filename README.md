# ROSA Boundary

Multi-architecture container and CLI for managing ephemeral SRE investigations on AWS Fargate with OIDC-authenticated access control.

## Features

- **Go CLI**: `rosa-boundary` — authenticate, start, join, list, and stop investigations
- **SRE Toolchain**: OCM, backplane, osdctl, ocm-addons, yq via backplane-tools
- **AWS CLI**: Official AWS CLI v2 (via backplane-tools)
- **OpenShift CLI**: Versions 4.14 through 4.20 with runtime switching
- **Claude Code**: AI-powered CLI assistant with Amazon Bedrock integration
- **Shell Environment**: Modular bashrc.d configuration with kube-ps1, auto-login, completions, fzf
- **Multi-architecture**: Supports both x86_64 (amd64) and ARM64 (aarch64)
- **Containerized CI**: All quality checks run in containers — only podman required
- **OIDC Authentication**: Keycloak integration with Lambda-based authorization
- **Tag-Based Isolation**: Shared SRE role with task-level ABAC access control

## Getting Started

### Prerequisites

- Go 1.24+ (to build the CLI from source)
- Terraform (infrastructure deployment)
- Keycloak with OIDC configured (see [OIDC Identity Requirements](#oidc-identity-requirements))
- [`session-manager-plugin`](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) — required for `join-task` and `start-task --connect`

The `session-manager-plugin` is an AWS-provided binary that handles the WebSocket session protocol used by ECS Exec. The `rosa-boundary` CLI calls the ECS `ExecuteCommand` API to obtain session credentials, then hands off to this plugin to establish the interactive session. It must be installed separately on each machine running the CLI.

**macOS:**
```bash
brew install --cask session-manager-plugin
```

**Linux (x86_64):**
```bash
curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/linux_64bit/session-manager-plugin.rpm" -o /tmp/session-manager-plugin.rpm
sudo yum install -y /tmp/session-manager-plugin.rpm
```

**Verify:**
```bash
session-manager-plugin --version
```

See the [AWS documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) for other platforms and package managers.

### Deploy Infrastructure

1. Copy the example environment file and fill in values:

   ```bash
   cp .env.example .env
   ```

2. Required Terraform variables (no defaults):

   | Variable | Description |
   |---|---|
   | `container_image` | Container image URI |
   | `vpc_id` | VPC for Fargate tasks |
   | `subnet_ids` | 2+ subnets in the same VPC |
   | `keycloak_issuer_url` | OIDC issuer URL (e.g., `https://keycloak.example.com/realms/sre-ops`) |
   | `keycloak_thumbprint` | SHA1 thumbprint of the Keycloak TLS certificate |

3. Deploy:

   ```bash
   cd deploy/regional && terraform init && terraform apply
   ```

See [`deploy/regional/README.md`](deploy/regional/README.md) for the complete deployment guide.

### OIDC Identity Requirements

Keycloak must issue tokens with these claims:

| Claim | Purpose |
|---|---|
| `sub` | Stored as `oidc_sub` tag (audit trail) |
| `preferred_username` | Used as `username` tag (ABAC key) |
| `email` | Logged |
| `groups` | Must contain `sre-team` |
| `aud` | Must match `aws-sre-access` |
| `https://aws.amazon.com/tags` | Session tags with `principal_tags.username` for ABAC |

Required Keycloak mappers:
- Groups (flat names), email, audience (`aws-sre-access`)
- AWS session tags: map `preferred_username` → `principal_tags.username`

Client settings: public client, standard flow + PKCE, redirect URI `http://localhost:8400/callback`.

See [`docs/configuration/keycloak-realm-setup.md`](docs/configuration/keycloak-realm-setup.md) for step-by-step setup.

### Install and Use the CLI

```bash
make build-cli && make install-cli
```

Create `~/.rosa-boundary/config.yaml` with the values specific to your deployment:

```yaml
keycloak_url: https://keycloak.example.com
lambda_function_name: rosa-boundary-dev-create-investigation
invoker_role_arn: arn:aws:iam::123456789012:role/rosa-boundary-dev-lambda-invoker
```

Core workflow:

```bash
# Start an investigation (authenticates, creates task, waits for RUNNING)
rosa-boundary start-task --cluster-id my-cluster --connect

# List running tasks
rosa-boundary list-tasks

# Connect to an existing task
rosa-boundary join-task <task-id>

# Stop a task (triggers S3 sync)
rosa-boundary stop-task <task-id>
```

## Building

### Container Image

The Containerfile uses a multi-stage build with 6 stages. Builder stages run in parallel. All downloads are checksum-verified and GitHub API calls are authenticated.

```bash
# Build both architectures and create manifest
# Requires GITHUB_TOKEN for authenticated GitHub API calls during build
make all

# Build single architecture
make build-amd64
make build-arm64
```

### CLI

```bash
make build-cli       # Build to ./bin/rosa-boundary
make install-cli     # Install to $GOBIN
make test-cli        # Run Go unit tests
```

## Testing and CI

### Containerized CI (recommended — only podman required)

All quality checks run inside a CI container image (`build/Containerfile.test`). No Go, bats, shellcheck, or other tooling needs to be installed locally.

```bash
# Run ALL CI checks (one command)
make ci-all

# Individual checks
make ci-test-shell      # bats-core shell unit tests (57 tests)
make ci-lint-shell      # shellcheck on all shell scripts
make ci-build-cli       # go build
make ci-test-cli        # go test
make ci-lint            # golangci-lint
make ci-staticcheck     # staticcheck
make ci-fmt             # check formatting (fails on diff)
make ci-fmt-fix         # fix formatting (writes to files)
make build-ci-image     # build the CI runner container (cached)
```

### Host-based (require tools installed locally)

```bash
make test-shell     # bats-core tests
make lint-shell     # shellcheck
make fmt            # gofmt + shfmt (write mode)
make lint           # golangci-lint
make staticcheck    # staticcheck
```

### Lambda Unit Tests

```bash
make test-lambda                      # All Lambda tests
make test-lambda-create-investigation # create-investigation tests
make test-lambda-reap-tasks           # reap-tasks tests
```

### LocalStack Integration Tests

```bash
make localstack-up          # Start LocalStack Pro
make test-localstack-fast   # Fast tests (~2-3 min)
make test-localstack        # Full suite (~5-7 min)
make localstack-down        # Stop LocalStack
```

See [`tests/localstack/README.md`](tests/localstack/README.md) for documentation.

### Prow CI

Prow presubmit jobs run all `ci-*` checks in parallel on PRs. Config is in the [openshift/release](https://github.com/openshift/release) repo.

## Container Tools

Tools installed in the container image:

| Tool | Source | Purpose |
|---|---|---|
| `oc` (4.14-4.20) | mirror.openshift.com | OpenShift CLI with runtime version switching |
| `ocm` | backplane-tools | OpenShift Cluster Manager CLI |
| `ocm-backplane` | backplane-tools | Cluster login via backplane |
| `osdctl` | backplane-tools | OSD control utility |
| `ocm-addons` | backplane-tools | OCM addons plugin |
| `yq` | backplane-tools | YAML processor |
| `aws` | backplane-tools | AWS CLI v2 |
| `claude` | GitHub Releases | AI-assisted investigation |
| `fzf` | GitHub Releases | Interactive fuzzy finder |
| `jq` | dnf | JSON processor |
| `tmux` | dnf | Terminal multiplexer |
| `vim` | dnf | Text editor |
| `git` | dnf | Version control |
| `session-manager-plugin` | AWS RPM | SSM session support |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OC_VERSION` | `4.20` | OpenShift CLI version (4.14-4.20) |
| `OCM_ENVIRONMENT` | — | OCM environment for PS1 display |
| `CLUSTER_AUTH_METHOD` | `backplane` | Auth method: `backplane` or `proxy` |
| `CLUSTER_ID` | — | Cluster ID for investigation |
| `INVESTIGATION_ID` | — | Investigation ID |
| `TMUX_AUTOSTART` | `0` | Set to `1` to auto-start tmux |
| `SHOW_CLUSTER_CONTEXT` | `1` | Set to `0` to skip cluster context display |
| `S3_AUDIT_ESCROW` | — | S3 URI for /home/sre sync on exit |
| `TASK_TIMEOUT` | `3600` | Timeout in seconds (enforced by reaper Lambda) |
| `CLAUDE_CODE_USE_BEDROCK` | `1` | Enable Claude Code via Amazon Bedrock |
| `AWS_REGION` | auto-detected | AWS region for Bedrock |

## Repository Structure

```
rosa-boundary/
├── AGENTS.md              # Project guidance, hard requirements, pre-PR gates
├── Containerfile          # Multi-stage multi-arch container build (6 stages)
├── entrypoint.sh          # Runtime init: version switching, S3 sync, Bedrock
├── Makefile               # Host + containerized CI targets
├── build/                 # Container build helpers and CI runner
│   ├── Containerfile.test # CI runner image (Go + bats + shellcheck + shfmt)
│   ├── platforms.sh       # Architecture detection for multi-arch builds
│   └── github_dl.py       # Authenticated GitHub Release downloader
├── skel/sre/              # Skeleton config (copied to /home/sre at runtime)
│   ├── .bashrc            # bashrc.d sourcing loop
│   ├── .bashrc.d/         # Modular shell config (10 files)
│   ├── .inputrc           # Bracketed paste
│   ├── .claude/           # Claude Code config
│   └── .local/bin/        # User scripts (sre-login)
├── cmd/rosa-boundary/     # Go CLI entrypoint
├── internal/              # Go packages (auth, aws, cmd, config, lambda, output)
├── deploy/
│   ├── regional/          # Terraform: ECS, EFS, S3, Lambda, OIDC
│   └── keycloak/          # Kustomize: Keycloak on OpenShift
├── lambda/                # Lambda functions (create-investigation, reap-tasks)
├── tests/
│   ├── shell/             # bats-core tests for shell scripts (57 tests)
│   └── localstack/        # LocalStack integration tests (35 tests)
└── docs/                  # Architecture, configuration, runbooks
```

## Documentation

- [`AGENTS.md`](AGENTS.md) — Full project guidance, coding standards, and pre-PR quality gates
- [`docs/architecture/overview.md`](docs/architecture/overview.md) — System architecture
- [`docs/configuration/`](docs/configuration/) — Setup guides for Keycloak and AWS IAM
- [`docs/runbooks/`](docs/runbooks/) — Investigation workflows and troubleshooting
- [`deploy/regional/README.md`](deploy/regional/README.md) — Terraform deployment guide
- [`tests/localstack/README.md`](tests/localstack/README.md) — Integration test documentation

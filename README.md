# ROSA Boundary

Multi-architecture container and CLI for managing ephemeral SRE investigations on AWS Fargate with OIDC-authenticated access control.

Trusted Actions source is also available in [components/trusted-actions/](components/trusted-actions/README.md).
It remains a separate Go module, container image, and Terraform deployment;
see [source co-location and cutover](docs/trusted-actions-source-colocation.md).
Boundary's Lambda applications still live in [`lambda/`](lambda/) for now; they
likely belong under `components/boundary/` in a separately validated layout refactor.

## Features

- **Go CLI**: `rosa-boundary` — authenticate, start, join, list, and stop investigations
- **AWS CLI**: Official AWS CLI v2
- **OpenShift CLI**: Versions 4.14 through 4.20 from stable channels
- **Claude Code**: AI-powered CLI assistant with Amazon Bedrock integration
- **Dynamic Version Selection**: Switch tool versions via environment variables at runtime
- **ECS Exec Ready**: Designed for AWS Fargate with ECS Exec support
- **Multi-architecture**: Supports both x86_64 (amd64) and ARM64 (aarch64)
- **OIDC Authentication**: Keycloak integration with Lambda-based authorization
- **Tag-Based Isolation**: Shared SRE role with task-level ABAC access control

## Getting Started

Contributors: start with [CONTRIBUTING.md](CONTRIBUTING.md) for mise setup,
LocalStack access, and the complete local test command.

### Prerequisites

- Go 1.27.3 (the version selected by `go.mod` to build the CLI from source)
- Terraform (infrastructure deployment)
- Keycloak with OIDC configured (see [OIDC Identity Requirements](#oidc-identity-requirements))
- [`session-manager-plugin`](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) — required for interactive access and credential configuration

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
   | `keycloak_issuer_url` | OIDC issuer URL (e.g., `https://keycloak.example.com/realms/EmployeeIDP`) |
   | `keycloak_thumbprint` | SHA1 thumbprint of the Keycloak TLS certificate |

3. Deploy:

   ```bash
   cd deploy/regional && make init && make plan && make apply
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
| `aud` | Must match `rosa-boundary-sre` |
| `https://aws.amazon.com/tags` | Session tags with `principal_tags.username` for ABAC |

Required Keycloak mappers:
- Groups (flat names), email, audience (`rosa-boundary-sre`)
- AWS session tags: map `preferred_username` → `principal_tags.username`

Client settings: public client, standard flow + PKCE, redirect URI `http://localhost:8400/callback`.

See [`docs/configuration/keycloak-realm-setup.md`](docs/configuration/keycloak-realm-setup.md) for step-by-step setup.

### Install and Use the CLI

```bash
make build-cli && make install-cli
```

The CLI uses **named deployment profiles** in
`${XDG_CONFIG_HOME:-$HOME/.config}/rosa-boundary/config.yaml`. Ask your operator
for the Boundary account, region, and identity provider, then initialize one:

```bash
rosa-boundary config init --name stage-east --account-id 123456789012 \
  --region us-east-1 --environment stage
rosa-boundary config list-profiles
```

`config init` discovers the other settings after OIDC approval. Use
`--auto-discover=false` to enter all settings manually, or `--use-device-code`
for human-approved login without a local browser. If you have an old flat
`config.yaml`, delete or move it before running `config init` to create fresh
named profiles. There is no migration. Confirm the selected
profile's account and region before starting any investigation. See the
[user access guide](docs/runbooks/user-access-guide.md#3-configure-cli).

Core workflow:

```bash
# Start a session (creates the investigation if needed; waits for RUNNING)
rosa-boundary session create my-cluster --investigation-id incident-42

# List running sessions and investigation workspaces
rosa-boundary session list
rosa-boundary investigation list

# Join an existing session in a terminal
rosa-boundary session join <session-id>

# Configure or clear fresh, task-scoped OCM access
rosa-boundary session credentials configure ocm <session-id> --ocm-url production
rosa-boundary session credentials clear ocm <session-id>

# Stop a session, check CloudWatch and S3 audit evidence, then close its workspace
rosa-boundary session close <session-id> --wait
rosa-boundary investigation close my-cluster incident-42 --dry-run
rosa-boundary investigation close my-cluster incident-42
```

## Repository Structure

Boundary still builds from the repository root. Trusted Actions is a separate
Go module and image under `components/`; its Terraform roots remain separate
from Boundary's. The copied Trusted Actions HCP definitions have **not** been
switched to this repository as their deployment source (see
[source co-location and cutover](docs/trusted-actions-source-colocation.md)).

```
rosa-boundary/
├── go.mod, Makefile, Containerfile  # Boundary CLI and multi-arch image
├── entrypoint.sh, skel/     # Boundary container runtime and user setup
├── cmd/rosa-boundary/       # Boundary CLI entrypoint
├── internal/                # Boundary CLI implementation
├── lambda/                  # Boundary Lambda applications (not moved yet)
│   ├── create-investigation/
│   ├── reap-investigations/
│   └── reap-tasks/
├── components/
│   └── trusted-actions/    # Independent Go module, server, CLI, image
│       ├── go.mod, Makefile, Containerfile
│       ├── cmd/, internal/, openapi/, config/
│       ├── tests/, integration/, docs/, openwiki/
│       └── terraform/
│           ├── global/     # Trusted Actions account-wide state
│           └── regional/   # Trusted Actions regional state
├── deploy/
│   ├── account/            # Boundary account-wide Terraform state
│   ├── network/            # Boundary VPC and network Terraform state
│   ├── regional/           # Boundary per-region Terraform state
│   └── keycloak/           # Keycloak realm and client configuration
├── hcp-terraform/
│   ├── rosa-boundary/      # Boundary HCP workspace definitions
│   ├── aws-creds/          # Stage and production AWS dynamic credentials
│   └── rosa-trusted-actions/ # Trusted Actions HCP definitions (separate)
├── .tekton/                # Separate Boundary, Lambda, and TA image pipelines
├── tests/                  # Boundary tests, including LocalStack
└── docs/                   # Boundary architecture, runbooks, cutover guide
```

## CLI Reference

### Subcommands

| Command | Description |
|---|---|
| `login` | Authenticate with Keycloak and cache the OIDC token |
| `config init`, `config list-profiles`, `config use-profile`, `config get` | Manage named Boundary deployment profiles |
| `investigation create <cluster-id>` | Create a workspace without a session |
| `investigation list`, `investigation close <cluster-id> <investigation-id>` | Inspect and close workspaces |
| `session create <cluster-id>` | Create or reuse an investigation and start an ECS task |
| `session credentials configure ocm <session-id>` | Issue and configure fresh OCM access |
| `session credentials clear ocm <session-id>` | Clear OCM and derived kubeconfig state |
| `session join <session-id>` | Connect to a running task via ECS Exec |
| `session list` | List sessions in the Boundary ECS cluster |
| `session close <session-id>` | Stop a session task (does not close its investigation workspace) |
| `version` | Print the rosa-boundary version |

The former `session start` and `session stop` verbs are not aliases: use
`session create` and `session close` instead. The CLI rejects the old verbs and
suggests the replacement; `session close` stops only the task, leaving the
investigation and its reusable workspace open until `investigation close`.

### Notable Flags

**`session create <cluster-id>`**:
- `--investigation-id` — auto-generated if omitted (e.g., `swift-dance-party`)
- `--oc-version` — OpenShift CLI version (default: `4.20`)
- `--session-timeout` — session lifetime (default: `1h`); the deployment's Lambda enforces its own minimum and maximum
- `--connect` — automatically join the task after it reaches RUNNING
- `--no-wait` — return immediately without waiting for RUNNING
- `--with-credentials ocm` — configure OCM before returning or connecting; incompatible with `--no-wait`
- `--ocm-url` — `production`, `staging`, `integration`, or an approved canonical URL
- `--ocm-auth-flow` — `auth-code` (default) or `device`
- `--output text|json`

**`session join`**: `--container` (default: `rosa-boundary`), `--command` (default: `runuser -u sre -- sh -c 'cd ~ && exec bash --login'`), `--no-wait`

**`session credentials configure ocm`**: `--ocm-url` selects the environment and defaults to the non-secret URL in the workstation's OCM configuration; `--auth-flow auth-code|device` selects the fresh-token flow. The command never copies or caches local access, refresh, or offline tokens.

**`session list`**: `--status RUNNING|STOPPED|all` (default: `RUNNING`), `--output text|json`

**`session close`**: `--reason`, `--wait`, `--yes` (required without a terminal)

**`investigation close`**: `--dry-run`, `--force` (stop active sessions), `--yes` (required without a terminal unless dry-running). Only the investigation creator can close it through the CLI; verify the plan before confirmation. Stopping is not proof of audit sync.

**`login`**: `--force`

### Global Flags

```
--profile <name>         Select a saved deployment without changing the active profile
--verbose                Enable debug diagnostics (never secrets)
--timeout <duration>     Whole-command deadline (default 5m without a terminal)
--use-device-code[=bool] Select device approval for Boundary and the default OCM flow
```

### Configuration Precedence

Command-specific flags > `ROSA_BOUNDARY_*` environment variables > selected saved profile > defaults. `--profile` selects a saved profile or defaults to `active_profile`; an environment variable cannot silently change the selection. `config get` shows saved values only.

Environment variable examples: `ROSA_BOUNDARY_KEYCLOAK_URL`, `ROSA_BOUNDARY_LAMBDA_FUNCTION_NAME`, `ROSA_BOUNDARY_INVOKER_ROLE_ARN`.

## Building

### Container

Export a GitHub token in the shell running `make` (logging in with `gh` or
setting `GH_TOKEN` alone does not pass it to the image build). The root Makefile
does not source `.env`. It passes `GITHUB_TOKEN` as a Podman build secret, not a
build argument. For example, with an authenticated GitHub CLI:

```bash
export GITHUB_TOKEN="$(gh auth token)"
make REQUIRE_GITHUB_TOKEN=true build-amd64
unset GITHUB_TOKEN
```

If `gh` has multiple accounts configured, select the intended account with
`gh auth token --user <username>`.

Alternatively, export all three `GITHUB_APP_ID`, `GITHUB_APP_PEM`, and
`GITHUB_APP_INSTALL_ID` for GitHub App authentication. Do not put tokens on the
`make` command line or in a committed file.

```bash
# Build both architectures and create manifest
make all

# Build single architecture
make build-amd64
make build-arm64

# Create manifest list from existing builds
make manifest

# Remove all images and manifests
make clean
```

### CLI

```bash
# Build the rosa-boundary binary to ./bin/
make build-cli

# Install to $GOBIN
make install-cli

# Run Go unit tests
make test-cli
```

## Environment Variables

The easiest way to select tool versions is via environment variables at container startup:

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `OC_VERSION` | `4.14`, `4.15`, `4.16`, `4.17`, `4.18`, `4.19`, `4.20` | `4.20` | OpenShift CLI version |
| `S3_AUDIT_ESCROW` | S3 URI (e.g., `s3://bucket/path/`) | _(none)_ | S3 destination for /home/sre sync on exit |
| `CLAUDE_CODE_USE_BEDROCK` | `0`, `1` | `1` | Enable Claude Code via Amazon Bedrock |
| `AWS_REGION` | AWS region code | _(auto-detect)_ | AWS region for Bedrock. Auto-detected from ECS metadata; fallback to us-east-1 |
| `ANTHROPIC_MODEL` | Bedrock inference profile | `us.anthropic.claude-sonnet-5` | Claude model Claude Code uses by default. In ECS this is set from `claude_default_model`; Terraform maps the profile to a foundation model in `bedrock_model_agreements` when the manifest is nonempty. This is not an invocation allowlist or a live availability check |
| `DISABLE_INSTALLATION_CHECKS` | `0`, `1` | `1` | Suppress Claude's user-local installation self-check (the CLI is image-managed at `/usr/local/bin/claude`) |

**Examples:**
```bash
# Use OpenShift CLI 4.18
podman run -e OC_VERSION=4.18 rosa-boundary:latest

# With a custom command
podman run -e OC_VERSION=4.19 rosa-boundary:latest /bin/bash
```

## SRE User and Audit Escrow

The container includes a non-root `sre` user (uid=1000) designed for SSM/ECS Exec connections. `/home/sre` is EFS-backed, while `/home/sre/.config/ocm` and `/home/sre/.kube` are overlaid with task-scoped Fargate volumes. Credential state is destroyed when the task stops.

### Automatic S3 Sync on Exit

When the container receives termination signals (SIGTERM, SIGINT, SIGHUP) or exits normally, the entrypoint automatically syncs `/home/sre` to S3 if `S3_AUDIT_ESCROW` is set:

```bash
# Container will sync /home/sre to S3 on exit
podman run -e S3_AUDIT_ESCROW=s3://my-bucket/investigation-123/ rosa-boundary:latest
```

**Features:**
- Automatic sync on container exit or termination signals
- Graceful failure - warns but doesn't block exit if sync fails
- Only syncs if `S3_AUDIT_ESCROW` is defined (no sync if unset)
- Useful for preserving investigation artifacts after ephemeral container use
- Excludes `.config/ocm/*` and `.kube/*` so credential state is never copied to audit storage

## Tool Management

The container supports two methods for switching tool versions:

1. **Environment Variables** (recommended): Set `OC_VERSION` at container startup (see above)
2. **Alternatives Commands** (advanced): Manually switch versions inside a running container

### OpenShift CLI Versions

Seven OpenShift CLI versions are available (4.14-4.20), with 4.20 as the default:

```bash
# View available oc versions
alternatives --display oc

# Switch to a specific version
alternatives --set oc /opt/openshift/4.17/oc
alternatives --set oc /opt/openshift/4.19/oc
```

## Claude Code

The container includes Claude Code CLI with Amazon Bedrock integration for AI-assisted troubleshooting and automation.

### Configuration

**Location**: `/home/sre/.claude/`

Default configuration files are automatically initialized on first run:
- `settings.json` - Bedrock authentication and auto-update settings
- `CLAUDE.md` - SRE workflow guidance and available tools documentation

**Authentication**: Uses IAM via Amazon Bedrock (no API keys required)

### AWS Region Detection

Claude Code automatically detects the AWS region from ECS task metadata:

1. Checks if `AWS_REGION` environment variable is set (explicit override)
2. Queries ECS metadata endpoint to extract region from Task ARN
3. Falls back to `us-east-1` if detection fails

This ensures Claude Code uses Bedrock in the same region as the running container.

### IAM Permissions and Model Access

The ECS task role's Bedrock permissions are defined in
[`deploy/regional/iam.tf`](deploy/regional/iam.tf). See the
[model-agreement guide](docs/configuration/bedrock-model-agreements.md) for
account-level model enablement and why agreements are not an invocation
allowlist.

### Usage Examples

```bash
# Start Claude Code session
claude

# Get help with a command
claude "How do I check the status of cluster operators?"

# Run interactive investigation
claude "Investigate pods in crashloop in default namespace"

# Disable Bedrock mode (not the installed Claude Code CLI)
podman run -e CLAUDE_CODE_USE_BEDROCK=0 rosa-boundary:latest
```

### Configuration Persistence

Configuration files in `/home/sre/.claude/` are preserved across container restarts when using EFS:
- **First run**: Skeleton files copied from `/etc/skel-sre/.claude/`
- **Subsequent runs**: Existing configuration preserved (no overwrite)
- **Customize**: Edit `/home/sre/.claude/CLAUDE.md` to add cluster-specific context

## Usage

### Running locally
```bash
# Run with default versions (OC 4.20, official AWS CLI)
podman run -it rosa-boundary:latest /bin/bash

# Run with specific versions
podman run -it -e OC_VERSION=4.18 rosa-boundary:latest /bin/bash

# Check tool versions
podman run --rm rosa-boundary:latest sh -c "aws --version && oc version --client"
```

## Image Details

- **Base**: Red Hat UBI9
- **AWS CLI**: Official AWS CLI v2
- **OpenShift CLI**: 4.14.x, 4.15.x, 4.16.x, 4.17.x, 4.18.x, 4.19.x, 4.20.x
- **Claude Code**: 2.0.69 (native installer), auto-updates disabled
- **Additional tools**: util-linux (includes su for user switching)

## Architecture Support

The manifest list automatically selects the appropriate image for your platform:
- `linux/amd64` - x86_64 architecture
- `linux/arm64` - ARM64/aarch64 architecture (Graviton)

## Testing

Start with [CONTRIBUTING.md](CONTRIBUTING.md) for tool and license setup, then the
[testing guide](docs/testing.md) for complete coverage and limitations.
`make test` runs offline unit/regression suites; `make check` adds quality gates.
With LocalStack running, `make test-all` also attempts Terraform, integration,
and image-build checks. Skipped integration coverage is reported as INCOMPLETE;
use `TEST_ALL_ARGS=--require-complete` to make it nonzero.

### LocalStack Integration Tests

Test AWS functionality locally before production deployment:

```bash
# Start LocalStack (requires LocalStack Pro token)
make localstack-up

# Run fast tests (~2-3 min)
make test-localstack-fast

# Run full test suite (~5-7 min)
make test-localstack

# Stop LocalStack
make localstack-down
```

See [`tests/localstack/README.md`](tests/localstack/README.md) for complete documentation.

### Lambda Unit Tests

```bash
cd lambda/create-investigation/
make test
```

## CI/CD

Prow presubmit and postsubmit jobs run on PRs and merges to `main` (job definitions in `openshift/release`):

- **LocalStack Integration Tests** - The repository's `tests/localstack/ci-run.sh`
  starts LocalStack in Podman with a container-runtime socket and runs the full
  integration selection with JUnit output. External job triggers/configuration
  are managed in `openshift/release`.
- **Lambda Unit Tests** - Handler function validation with moto (`make test-lambda-create-investigation`)

**Required secret input**: `LOCALSTACK_AUTH_TOKEN`. Confirm its current Vault and
cluster-secret mapping with the CI/platform administrators and the authoritative
`openshift/release` secret-sync configuration; local setup does not change it.

See [`tests/localstack/README.md`](tests/localstack/README.md) for full CI and local testing documentation.

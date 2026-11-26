# Development Guide

This document explains how to set up a local development environment for the ROSA Trusted Actions Server.

## Prerequisites

| Tool          | Version | Purpose               |
|---------------|---------|-----------------------|
| Go            | 1.27.4+ | Primary language      |
| Node.js       | 16+     | OpenAPI spec bundling |
| Make          | any     | Build automation      |
| Git           | any     | Version control       |
| golangci-lint | 1.61+   | Go linting            |
| pre-commit    | any     | Git hook management   |

The minimum Go version is declared in [`go.mod`](go.mod). The repository-root
[`mise.toml`](../../mise.toml) selects the contributor Go version.

## Initial Setup

```bash
# Clone the monorepo and enter the Trusted Actions component
git clone https://github.com/openshift-online/rosa-boundary.git
cd rosa-boundary/components/trusted-actions

# Install all dependencies
make deps

# Install repository-root pre-commit hooks from the rosa-boundary root
cd ../..
pip install pre-commit
pre-commit install
cd components/trusted-actions

# Generate code and build
make all
```

## Development Workflow

### Building

```bash
make build              # Build server and rta (snapshot, current OS/arch)
make build-all          # Build all release targets (linux, darwin)
```

These upstream GoReleaser targets have **not** been made functional for the
Boundary monorepo: `.goreleaser.yaml` is nested under this component, not at
the repository root, so a root-level release invocation will not discover it.
The config, paths, and release workflow need a follow-up adaptation before
these targets are relied on. For local compilation in this checkout, run
`go build ./cmd/rta` or `go build ./cmd/server` from this directory.

### Running Locally

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with your settings

# Run the server
make run                # Starts on :8080

# Or with custom flags
go run ./cmd/server --listen-addr=":3000" --log-level="debug" --log-json
```

### Running Against the LocalStack RDS Database (IAM token auth)

The development database is a LocalStack RDS PostgreSQL instance with IAM
database authentication enabled. The server connects with per-connection IAM
tokens — no password exists on this path anywhere.

```bash
# Requires a LocalStack Pro license token in the environment (RDS is a pro
# feature). The token is passed to the container only, never committed.
export LOCALSTACK_AUTH_TOKEN=...

make localstack-db      # Provision LocalStack + RDS, bootstrap, write .env.localstack-db
make run-localstack-db  # Run the server against it (sources .env.localstack-db; needs ROSA_TA_KUBECONFIG)
make localstack-db-down # Tear down LocalStack, its volume, and the env file
```

`make localstack-db` reuses a running LocalStack container but replaces the
RDS instance and its data each run (a fresh master password is generated per
run and LocalStack does not apply password modifications) — treat the dev
database as disposable: schema is rebuilt by bootstrap + migrations, row data
is not. The generated `.env.localstack-db` (gitignored) carries
`ROSA_TA_DB_HOST/PORT/NAME/USER`, `ROSA_TA_DB_SSLMODE=disable`, static
LocalStack AWS credentials, the region, and the local-dev contract
(`ROSA_TA_AUTH=disabled`, `ROSA_TA_AWS_ENDPOINT_URL` pointing at LocalStack,
loopback `ROSA_TA_LISTEN_ADDR`) — no password and no master credentials.
Only `make run-localstack-db` sources it; plain `make run` never does, so
the LocalStack env can never shadow a caller's own environment. The server
refuses to start with auth disabled unless `ROSA_TA_KUBECONFIG` is set
(e.g. from `make itest-up`, or your own kubeconfig).

### Code Generation

The API server code is generated from OpenAPI specifications:

```bash
# After modifying files in openapi/
make generate           # Bundle spec + generate Go code
make validate-spec      # Validate spec without generating
```

The generated file `internal/openapi/api.go` is committed to the repository. After running `make generate`, commit the updated generated code along with your spec changes.

### Linting

```bash
make lint               # Run golangci-lint with project config
make fmt                # Auto-format code
```

Lint configuration is in `.golangci.yml`. All PRs must pass linting.

### Adding a Trusted Action

To author a new Trusted Action (implementation, policy/catalog, tests, review,
and deployment), see
[docs/adding-a-trusted-action.md](docs/adding-a-trusted-action.md). Coding agents
can also use the
[`add-trusted-action`](.agents/skills/add-trusted-action/SKILL.md) skill.

### Testing

See [TESTING.md](TESTING.md) for detailed testing guidance.

```bash
make test               # Run all unit tests
make test-race          # Run with race detection
make test-coverage      # Generate coverage report
make test-integration   # Run integration tests (starts server)
```

## Project Architecture

### Request Flow

```
Client Request
  -> chi Router
    -> Middleware (logging, request ID, recovery, CORS)
      -> Generated OpenAPI handler (internal/openapi/)
        -> API handler (internal/handlers/)
          -> Response
```

### Key Packages

- **`cmd/server`** — Application entry point. Configures CLI flags, sets up the router, and starts the HTTP server.
- **`internal/config`** — Loads configuration from environment variables. Server flags are handled separately in `cmd/server`.
- **`internal/handlers`** — Implements the `ServerInterface` generated by oapi-codegen. All business logic goes here.
- **`internal/middleware`** — HTTP middleware for structured logging, request IDs, and panic recovery.
- **`internal/openapi`** — Generated code from oapi-codegen. **Do not edit manually.**

### Configuration

The server uses two configuration layers:

1. **CLI flags** (via cobra): `--listen-addr`, `--log-level`, `--log-json`
2. **Environment variables**: AWS credentials, S3 bucket, auth settings (see `.env.example`)

## Editor Setup

### VS Code

Recommended extensions:
- `golang.go` — Go language support
- `42Crunch.vscode-openapi` — OpenAPI editor

### GoLand / IntelliJ

- Enable the Go plugin
- Set `goimports` as the formatter with local prefix: `github.com/openshift-online/rosa-trusted-actions`

## Troubleshooting

### `make generate` fails

- Ensure Node.js dependencies are installed: `make deps-npm`
- Ensure the bundled spec is valid: `make validate-spec`

### Lint errors on generated code

- Generated code in `internal/openapi/` is excluded from linting via `.golangci.yml`. If you see lint errors from that directory, ensure the exclusion is in place.

### Pre-commit hooks fail

- Update hooks: `pre-commit autoupdate`
- Run on all files to check: `pre-commit run --all-files`
- For secret detection false positives, add entries to `.gitleaksignore`

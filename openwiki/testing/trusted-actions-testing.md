---
type: testing-guide
title: Trusted Actions testing and CI
description: Describes the Trusted Actions component's unit, integration, and mock-dependency testing strategy, its Make targets, Postgres/LocalStack-RDS IAM-token test tooling, and its Codecov patch-coverage gate, plus the Konflux Tekton pipelines that build and push its image on PR and push events in this monorepo.
tags: [trusted-actions, testing, ci, codecov, coverage, integration-tests, backplane, postgres, iam-auth, tekton, go]
verified:
  - by: openwiki/0.9.0
    at: 2026-11-26T16:03:02.488Z
sources:
  - id: openwiki-source-eebdf2baefd63a03b1cb3b5e
    resource: repo://.tekton/rosa-trusted-actions-pull-request.yaml
  - id: openwiki-source-12238a6f88dc834f61553058
    resource: repo://.tekton/rosa-trusted-actions-push.yaml
  - id: openwiki-source-5f7022cb75865b779a5792a0
    resource: repo://codecov.yml
  - id: openwiki-source-3051f255965c31db61eae3a3
    resource: repo://components/trusted-actions/codecov.yml
  - id: openwiki-source-3171b915c13566ad7c807787
    resource: repo://components/trusted-actions/compose.localstack-db.yml
  - id: openwiki-source-da2b59baf4fcefd99282d06d
    resource: repo://components/trusted-actions/compose.postgres.yml
  - id: openwiki-source-c62a53560e154d1649f9a5b2
    resource: repo://components/trusted-actions/CONTRIBUTING.md
  - id: openwiki-source-6b93bc866fdc94b322d46e84
    resource: repo://components/trusted-actions/docker-compose.test.yml
  - id: openwiki-source-2d8b922c7e5e8b7514a7bbff
    resource: repo://components/trusted-actions/docs/adding-a-trusted-action.md
  - id: openwiki-source-56c54c10348f1e72daffc214
    resource: repo://components/trusted-actions/go.mod
  - id: openwiki-source-54625ad7b6d11a03282fee57
    resource: repo://components/trusted-actions/integration/itest-run.sh
  - id: openwiki-source-3c3562d58ce85865e73956fe
    resource: repo://components/trusted-actions/integration/itest-up.sh
  - id: openwiki-source-4d7e1795787385e81691a866
    resource: repo://components/trusted-actions/integration/podman-compose.yml
  - id: openwiki-source-f31219609de20fbaee6c658e
    resource: repo://components/trusted-actions/internal/config/config_test.go
  - id: openwiki-source-25960f1da7fae36f9a10e870
    resource: repo://components/trusted-actions/internal/config/config.go
  - id: openwiki-source-6fa73d968628eb0b312bf0ee
    resource: repo://components/trusted-actions/internal/rta/command_test.go
  - id: openwiki-source-8be4fe66d49e4dbda11c48b0
    resource: repo://components/trusted-actions/internal/store/postgres_iam_test.go
  - id: openwiki-source-4c833b02bf6d5fc7a2476dea
    resource: repo://components/trusted-actions/Makefile
  - id: openwiki-source-3a13739b5848ad6b59fbe22d
    resource: repo://components/trusted-actions/scripts/localstack-db.sh
  - id: openwiki-source-48302ab227b3652ec0a8dd2d
    resource: repo://components/trusted-actions/scripts/test-api.sh
  - id: openwiki-source-27ba9c102f3ba85a206dd83d
    resource: repo://components/trusted-actions/TESTING.md
  - id: openwiki-source-32b156c25339b97d19713ce3
    resource: repo://components/trusted-actions/tests/actions/main_test.go
  - id: openwiki-source-7fb7f94b66091c260f5a54d1
    resource: repo://components/trusted-actions/tests/mock-backplane/README.md
  - id: openwiki-source-9ba09077ca542d7f7f8c02fd
    resource: repo://components/trusted-actions/tests/proxy-backplane/README.md
generated: { by: "openwiki/0.9.0", at: "2026-11-26T16:03:02.488Z" }
---

## Scope and where these tests live

This page covers the Trusted Actions component's own test suite and build
tooling, all of which live under
[`components/trusted-actions/`](../../components/trusted-actions/README.md). Trusted
Actions is an independent Go module (`module
github.com/openshift-online/rosa-trusted-actions`) with its own `go.mod` and
`Makefile`; root-level commands do not exercise it:

> Run Trusted Actions commands from `components/trusted-actions/` (for
> example, `make -C components/trusted-actions test`). Root `go test ./...`
> and root Makefile targets do **not** exercise the nested Go module.

This is a load-bearing operational fact, not a style preference — the nested
module is invisible to any tooling that only walks the repository root's
`go.mod`. [`docs/trusted-actions-monorepo-migration.md`](../../docs/trusted-actions-monorepo-migration.md)
states this directly: "Run Trusted Actions builds and tests from
`components/trusted-actions/`; Boundary's root Go and Make commands do not
cover its separate module." That document is an explicit point-in-time
migration record (not a living status page), but this specific fact —
Trusted Actions' separate module boundary — is also independently confirmed
by `components/trusted-actions/go.mod` and `Makefile` existing only under
the component directory. See
[Monorepo components: Boundary and Trusted Actions](../architecture/monorepo-and-trusted-actions.md)
for the full picture of how this component sits inside the `rosa-boundary`
monorepo.

## Make targets

All targets below are defined in
[`components/trusted-actions/Makefile`](../../components/trusted-actions/Makefile)
and documented in
[`components/trusted-actions/TESTING.md`](../../components/trusted-actions/TESTING.md).
Run them from `components/trusted-actions/`, or prefix with `-C
components/trusted-actions` from the repository root.

| Target | What it does |
| --- | --- |
| `make test` | Generates OpenAPI code, compiles (but does not run) the `tests/actions` integration tests under the `integration` build tag to catch build breakage early, then runs `go test -v ./...` (SQLite-backed store tests only; Postgres-backed store tests require `TEST_POSTGRES_URL` and are opt-in via `make test-postgres`). |
| `make test-race` | Runs `go test -race -v ./...` for the same unit test set with the Go race detector enabled. |
| `make test-coverage` | Runs `go test -coverprofile=coverage.out ./...` and renders `coverage.html` via `go tool cover -html`. |
| `make test-postgres` | Starts an ephemeral Postgres container via `docker-compose.test.yml` (`make test-postgres-up`), runs `go test -v -count=1 ./internal/store/...` against it with `TEST_POSTGRES_URL` set, then tears the container down (`make test-postgres-down`) — including when the tests themselves fail. |
| `make test-integration` | Starts the server in the background (`make run &`), waits a few seconds, runs `scripts/test-api.sh` against it, then stops the server. Fails and kills the server if the script fails. |
| `make test-api` | Runs `scripts/test-api.sh` directly against an already-running server; does not start or stop anything itself. |
| `make test-actions` | Runs the `tests/actions` action-level integration tests (`-tags=integration`) against the mock Backplane server, which must already be running via `make mock-backplane`. |
| `make test-actions-proxy` | Runs the subset of `tests/actions` tests matched by `-run Proxy` against the proxy Backplane server (`make proxy-backplane`), which requires a real `KUBECONFIG`. |
| `make itest-up` / `make itest-run` / `make itest-down` | Wrap the `integration/` podman-compose end-to-end harness (see below). |

`make test` is the baseline unit-test gate; `make test-coverage` is the local
equivalent of the CI coverage step described below.

### Postgres test tooling: two separate Compose files

Trusted Actions' `Makefile` defines two distinct Postgres Compose stacks, and
only one of them is part of the automated test harness:

- **`docker-compose.test.yml`** backs the actual Postgres-backed test target.
  `make test-postgres-up` starts an ephemeral container (database
  `trusted_actions_test`, exposed on `localhost:5433`) via `$(COMPOSE) -p
  rosa-ta-postgres-test -f docker-compose.test.yml up -d --wait`. The
  composite `make test-postgres` target starts that container, runs `go test
  -v -count=1 ./internal/store/...` with `TEST_POSTGRES_URL=postgres://postgres:postgres@localhost:5433/trusted_actions_test?sslmode=disable`,
  and tears the container down afterward — including on failure, via
  `test-postgres-down` before exiting non-zero. These store tests are opt-in:
  plain `make test` / `make test-coverage` never start Postgres and only
  exercise the SQLite-backed code paths across `./...`.
- **`compose.postgres.yml`** is a separate, longer-lived Postgres instance
  for local development and manual testing rather than automated tests:
  `make postgres-up` / `postgres-down` / `postgres-logs` start, stop, and
  tail it (database `trusted_actions` on `localhost:5432` — a different port
  from the test stack's `5433` so both can run at once), and `make
  run-postgres` runs the server directly against it
  (`DATABASE_URL=postgres://postgres:postgres@localhost:5432/trusted_actions?sslmode=disable
  go run ./cmd/server`). No `test-*` Make target touches
  `compose.postgres.yml`.

Both files are selected through the same `COMPOSE` Makefile variable, which
prefers `podman compose` when `podman-compose`/`docker-compose` and `podman`
are both on `PATH`, falling back to `docker compose` otherwise. This Postgres
tooling is unrelated to the `integration/` harness described below: that
harness never touches Postgres (the server runs SQLite-backed during
`itest-run.sh`) and uses its own, separate `podman-compose.yml` solely to run
the `localstack` AWS emulator.

### LocalStack RDS Postgres (IAM-token) manual integration path

Neither `docker-compose.test.yml` nor `compose.postgres.yml` exercises the
IAM-token database-authentication connector in
`internal/store/postgres_iam.go`: both stacks are plain Postgres containers
reached with a static username/password DSN. A third, separate tier exists
specifically to exercise that connector against something that behaves like
a real AWS RDS instance: `compose.localstack-db.yml` runs a **licensed**
LocalStack Pro container (RDS is a Pro-only LocalStack service) on
`127.0.0.1:4567`, and `scripts/localstack-db.sh` drives it end-to-end:

- **`make localstack-db`** (`scripts/localstack-db.sh up`) starts or reuses
  the LocalStack container; creates an `rds create-db-instance` with
  `--enable-iam-database-authentication` (on a rerun it deletes and
  re-creates the instance with a freshly generated master password instead
  of trying to modify it in place, since LocalStack does not apply
  master-password changes — the dev database and any rows in it are
  disposable, while the schema is rebuilt every run); discovers the
  instance's container-network endpoint; runs `go run ./cmd/server
  bootstrap` against it over a one-shot master-user DSN to create the
  `trusted_actions_app` IAM-auth database role and schema; and writes a
  gitignored `.env.localstack-db` containing only
  `ROSA_TA_DB_HOST`/`PORT`/`NAME`/`USER`/`SSLMODE`, `AWS_REGION`, and static
  LocalStack AWS credentials — no password or master DSN is persisted to
  disk, matching the IAM-token contract itself. It requires
  `LOCALSTACK_AUTH_TOKEN` (a Pro license) in the environment and `jq`,
  `openssl`, `curl`, and `go` on `PATH`.
- **`make run-localstack-db`** sources `.env.localstack-db` over the
  caller's environment and runs the server, so it connects to the LocalStack
  RDS instance by minting per-connection IAM tokens exactly as it would
  against real AWS RDS, instead of a static password.
- **`make localstack-db-down`** stops and removes the LocalStack container,
  its volume, and `.env.localstack-db`.

This is a **manual, local** path only — there is no automated
`test-localstack-db` Make target or CI gate wired to it — distinct from both
the SQLite-backed default of plain `make test` and the password-DSN Postgres
path exercised by `make test-postgres`/`docker-compose.test.yml`. The
unit-level correctness of the IAM-token DSN/connector logic itself (token
shape, validity window, DSN assembly, and loud failure on a partial
`ROSA_TA_DB_*` contract) is pinned separately by
`internal/store/postgres_iam_test.go`, covered below, which runs under plain
`make test` with no LocalStack or network dependency at all.

## Coverage: Codecov patch-coverage gate

Per `TESTING.md`, `CONTRIBUTING.md`, and
[`docs/adding-a-trusted-action.md`](../../components/trusted-actions/docs/adding-a-trusted-action.md),
Trusted Actions' contributor documentation states that it enforces **patch
coverage >= 80% on all PRs** via Codecov, and that new code must include unit
tests to meet that bar. Coverage effort is explicitly focused on the two
packages considered the primary correctness surface:

- `internal/handlers/` — the HTTP API handler logic.
- `internal/config/` — configuration loading and validation.

`components/trusted-actions/codecov.yml` carries the Codecov parser and
reporting configuration for this module — precision/rounding, the
`require_ci_to_pass: no` notification setting, gcov branch-detection options,
and an `ignore` list (`**/mocks`, `**/zz_generated*.go`) that keeps generated
and mock code out of coverage metrics. `TESTING.md` additionally excludes
`vendor/`, `node_modules/`, `internal/openapi/` (generated code), `**/*_test.go`,
`tools.go`, and `docs/` from coverage accounting. This Trusted-Actions-specific
`codecov.yml` is distinct from the monorepo's root-level `codecov.yml`, which
sets an auto/informational project and patch target for the Boundary side of
the repository and does not define a Trusted-Actions-specific handlers/config
gate.

**Documentation and config currently disagree on the actual number.**
`components/trusted-actions/codecov.yml` itself sets
`coverage.status.patch.default.target` to `50%` (its own header comment reads
"Enforces >=50% patch coverage on all PRs"), not 80% — so the patch-coverage
threshold Codecov mechanically enforces is lower than the 80% bar stated in
`TESTING.md`, `CONTRIBUTING.md`, and `docs/adding-a-trusted-action.md`.
Contributors should still target 80% as the project's documented expectation,
but should not assume Codecov will fail a PR whose patch coverage falls
between 50% and 80%; check the current `codecov.yml` value directly rather
than relying on either number as the ground truth for what CI will actually
gate on.

Generate a local coverage report with:

```bash
make test-coverage
open coverage.html      # macOS
xdg-open coverage.html  # Linux
```

## Test conventions: stdlib-only, table-driven, isolated

Trusted Actions tests deliberately avoid third-party test/assertion
frameworks:

- **No test frameworks** — use the standard library `testing` package and
  `net/http/httptest` for HTTP handler tests. No `testify`, `gomega`, or
  similar.
- **Table-driven subtests** — multiple cases for one unit are expressed as a
  slice of struct cases run through `t.Run` subtests, following the pattern
  shown in `TESTING.md` (e.g. `TestAPIHandler_Describe`).
- **Naming** — `Test<Type>_<Method>` or
  `Test<Type>_<Method>_<Scenario>` (e.g. `TestAPIHandler_CreateExecution_InvalidJSON`).
- **Per-test isolation** — each test constructs its own handler instance and
  logger; there is no shared mutable state between tests. Non-fatal checks
  use `t.Errorf`, preconditions that block further testing use `t.Fatalf`.

Tests live alongside the code they exercise (Go convention), e.g.
`internal/handlers/api_test.go` next to `internal/handlers/api.go`, and
`internal/config/config_test.go` next to `internal/config/config.go`.

Three representative packages illustrate these conventions in practice:

- **`internal/config/config_test.go`** table-tests the small environment-
  variable helpers (`getEnv`, `getBoolEnv`, `getIntEnv`, `getDurationEnv`,
  `getPositiveIntEnv`, `getPositiveDurationEnv`, `getStringSliceEnv`) across
  set/unset/empty/unparseable-value cases (e.g. `TestGetBoolEnv` covers
  `"true"`, `"false"`, `"1"`, `"0"`, unset, and an unparseable `"yes"`), then
  exercises the full `Load` path — `TestLoad_Defaults`,
  `TestLoad_AWSAllowedRegionsFromEnv`/`FromFile`, `TestLoad_OCMBackplaneFromFile`,
  `TestLoad_OCMBackplaneEnvOverridesFile`, `TestLoad_AuthPolicy`,
  `TestLoad_EnvOverrides`, and `TestLoad_IAMDatabaseEnv` — to pin down
  config-file vs. environment-variable precedence for every settable value,
  plus file-read and parse error paths (`TestReadConfigFile_ReadError`,
  `TestReadConfigFile_UnmarshalError`). `TestLoad_IAMDatabaseEnv` specifically
  pins the IAM-token database contract: `ROSA_TA_DB_HOST`/`PORT`/`NAME`/`USER`
  arrive as separate environment variables (no URL, no password anywhere),
  `DBSSLMode` defaults to `verify-full`, and `ROSA_TA_DB_SSLMODE` can lower it
  (used only by the LocalStack development env file, described below).
- **`internal/rta/command_test.go`** drives the `rta` CLI's Cobra command
  tree end-to-end through `NewCommand()`, capturing stdout/stderr buffers
  rather than mocking Cobra, and asserts on rendered text and JSON output
  across the version, action list/describe/run, execution list/get/output,
  and audit list subcommands (`TestVersion_Text`/`TestVersion_JSON`,
  `TestActionList_Text`/`_JSON`, `TestExecutionList_Text`,
  `TestAuditList_Text`) as well as user-facing error paths: an unknown
  subcommand with a "did you mean" suggestion
  (`TestRoot_UnknownSubcommand_Suggestion`), an unknown flag, missing
  required arguments, and a missing server (`TestActionRun_MissingServer`).
  This is the same stdlib-only, table/subtest style applied to a CLI surface
  instead of an HTTP handler, and it requires no running server, Backplane,
  or cluster — a missing `--server` is itself one of the asserted error
  cases.
- **`internal/store/postgres_iam_test.go`** unit-tests the IAM-token
  database-authentication connector in isolation, with no real Postgres,
  LocalStack, or network dependency: `TestMintAuthToken_PresignedShape`
  asserts the minted RDS auth token is a SigV4-signed
  `host:port?Action=connect&DBUser=...` query string carrying no password or
  user-info component; `TestMintAuthToken_ValidityWindow` checks that its
  `X-Amz-Expires` is positive and within the 15-minute RDS maximum;
  `TestBuildIAMTokenDSN` checks that the assembled `pgx` connection URL
  carries the minted token only in the password slot, with `sslmode` taken
  from config; and `TestNewIAMStore_MissingContract` /
  `TestNewWithIAM_PartialContractFailsLoudly` assert that an incomplete or
  partial `ROSA_TA_DB_HOST`/`PORT`/`NAME`/`USER`/`AWS_REGION` contract fails
  loudly, naming the missing variable, instead of silently falling back to
  the password-DSN or SQLite path.

## Integration tests

### `integration/`: kind and podman-compose end-to-end harness

The integration run restarts the server with an allowlist excluding the test cluster's region, then checks both scopes for a denied execution rather than treating any failure as a passing test.

[`components/trusted-actions/integration/`](../../components/trusted-actions/integration/README.md)
is a disposable, podman-compose-based end-to-end harness that proves a real
execution request flows through the whole stack — HTTP → auth middleware →
executor → a real (if disposable) cluster → response — with **mock auth** and
**no OCM or Backplane dependency**. It is driven by three scripts, each also
exposed as a `make` target:

- **`itest-up.sh`** (`make itest-up`) — creates (or reuses) a disposable
  `kind` cluster and waits for its `kube-system` pods to become ready; starts
  the `podman-compose.yml` stack (`localstack`, an AWS emulator) and waits
  for it to report healthy; applies fixtures from `integration/fixtures/` (a
  pull secret and a Prometheus deployment) and waits for the `prometheus-k8s-0`
  pod to become ready; and then waits for at least two Prometheus
  alert-evaluation cycles (polling the `ALERTS` query until it returns two or
  more results) before reporting the environment ready. All of this runs
  under a configurable timeout (`ROSA_TA_ITEST_WAIT_TIMEOUT`, default 120s
  per wait) and requires `kind`, `kubectl`, `podman`, `podman-compose`, and
  `jq` on `PATH`.
- **`itest-run.sh`** (`make itest-run`) — retrieves a fresh kubeconfig from
  the kind cluster, exports `ROSA_TA_AUTH=disabled`, `ROSA_TA_KUBECONFIG`,
  `DATABASE_URL`, and the AWS emulator endpoint/region/credential variables,
  builds and starts the server, and waits for `/health`. It then runs a
  sequence of real actions against the live server and polls `GET
  /runs/{id}` until each reports `status: succeeded`: a `kube-api` `get`
  listing pods in `kube-system`; `describe-nodes` across all nodes and then
  against a single named node, asserting the response carries `conditions`,
  `capacity`, and a `pods` array; `get-pull-secret-email`; `list-alerts` with
  and without a `severity` filter, asserting both critical and warning alert
  counts and that the filter excludes warnings; and an `aws-api` `aws-get`
  sweep that seeds and reads back a tagged EC2 instance, then reads every
  other `aws-get` resource LocalStack's community image supports
  (`ec2-vpcs`, `ec2-subnets`, `ec2-route-tables`, `ec2-security-groups`,
  `ec2-dhcp-options`, `route53-hosted-zones`, `route53-record-sets`), seeding
  a DHCP option set and a hosted zone first since neither exists in a stock
  LocalStack. It finishes by submitting an `aws-get` request with a param the
  resource does not accept and asserting that execution fails, confirming
  input validation survives the full HTTP path. The server is stopped on
  exit either way.
- **`itest-down.sh`** (`make itest-down`) — stops localstack (if its
  container exists), deletes the kind cluster (if one with the configured
  name exists), and removes generated local artifacts (kubeconfig, SQLite DB
  file and its `-shm`/`-wal` siblings, server log). Safe to run even if
  nothing is up.

This harness requires `kind`, `kubectl`, `podman`, `podman-compose`, `jq`,
`go`, and `curl` on `PATH`. Per `integration/README.md`, five `aws-get`
resources (`load-balancers`, `load-balancers-classic`, `target-groups`,
`target-health`, `cloudtrail-events`) are **not** exercised by this harness
because they require LocalStack Pro services; those resources are covered
only by unit tests against fakes in `internal/actions`. Audit-log storage is
likewise not verified end-to-end here, since the server still wires in
`audit.NewMockLogger` rather than a persistent S3/CloudWatch backend.

### `tests/actions/`: action-level integration tests

[`components/trusted-actions/tests/actions/`](../../components/trusted-actions/tests/actions/main_test.go)
holds Go integration tests (build tag `integration`) that exercise individual
trusted actions end-to-end against a running Backplane stand-in, rather than
against the full HTTP server. `main_test.go`'s `TestMain` probes both
`MOCK_BACKPLANE_URL` (default `http://localhost:8087`) and
`PROXY_BACKPLANE_URL` (default `http://localhost:8088`) for availability,
and honors a `TEST_BACKPLANE=mock|proxy` selector: if a specific backend is
requested but unreachable, the test binary exits immediately with an
instructive error rather than silently skipping. These tests exercise the
real `internal/actions`, `internal/executor`, `internal/authorization`,
`internal/backplane`, and `internal/audit` packages, unlike the mocked-out
handler unit tests. They are run via `make test-actions` (mock backend) or
`make test-actions-proxy` (proxy backend, requires a real `KUBECONFIG`).

## Backplane test harnesses under `tests/`

Trusted Actions actions authenticate to target clusters through Backplane.
Two independent stand-ins for the real Backplane API live under `tests/` so
that Backplane-dependent code can be exercised without a live Backplane
service:

### `tests/mock-backplane/`: fixture-driven fake Backplane API

[`tests/mock-backplane/`](../../components/trusted-actions/tests/mock-backplane/README.md)
is a standalone fake Backplane API server built on the Imposter mock engine
(`backplane.yaml` config, `backplane-config.yaml`, fixture data under
`data/`). It is started with `make mock-backplane` (pinning the Imposter Go
native engine, version 5, with auto-restart disabled) and listens on
`MOCK_BACKPLANE_PORT` (default `8087`; `8080` if run standalone, same as
`make run`, so a distinct port must be set to run both together). State is
held in memory, so restarting the mock resets it and nothing leaks between
test runs.

The mock models the real Backplane CRUD + proxy contract: `POST
/backplane/trustedactions/{clusterId}` registers a trusted action and
returns a `proxyUri`; `DELETE .../{clusterId}/{instanceId}` removes it;
requests against the returned proxy path are answered from a preloaded
cluster fixture (`data/cluster.json`), keyed by `{clusterId}:{kubernetes
path}` and each declaring the RBAC identity (API group, resource, namespace)
that access is evaluated against. The mock distinguishes a modeled-but-absent
resource (`501`, "no fixture entry") from a resource that exists but was
never granted (`403`, "never requested") so that a gap in the fixture data
cannot be mistaken for a legitimate not-found or a passing negative test.
`kubectl` cannot be used directly against this mock because it performs API
discovery that the mock does not model; tests use `curl` or a dynamic client
constructed with an explicit `GroupVersionResource`.

### `tests/proxy-backplane/`: recording/replay proxy against a real cluster

[`tests/proxy-backplane/`](../../components/trusted-actions/tests/proxy-backplane/README.md)
is a lightweight reverse-proxy stand-in used by integration tests when a real
Kubernetes API response is needed rather than canned fixture data. Unlike the
Imposter mock, it accepts a real, base64-encoded kubeconfig at registration
time (`POST /backplane/trustedactions/{clusterId}`), parses TLS credentials
from it, builds an `http.Transport`, and stores the entry in memory; it then
forwards any HTTP method on the returned `proxyUri` through to the live
upstream cluster, injecting the kubeconfig's bearer token, until the entry is
deleted. It is started with `make proxy-backplane` and listens on
`PROXY_BACKPLANE_PORT` (default `8088`; `8080` if run standalone via `go run
./tests/proxy-backplane`). Because it proxies arbitrary methods, it is also
used to exercise Kubernetes write operations (create/patch/delete/scale)
that the fixture-based mock cannot represent.

## CI pipelines: Konflux Tekton PipelineRuns in `.tekton/`

Two Konflux Tekton `PipelineRun` definitions build and push the Trusted
Actions container image on GitHub events against this monorepo:

| File | Trigger | Output image |
| --- | --- | --- |
| [`.tekton/rosa-trusted-actions-pull-request.yaml`](../../.tekton/rosa-trusted-actions-pull-request.yaml) | `pull_request` events targeting `main` | `quay.io/redhat-user-workloads/rosa-tenant/rosa-trusted-actions:on-pr-{{revision}}` (expires after 5 days) |
| [`.tekton/rosa-trusted-actions-push.yaml`](../../.tekton/rosa-trusted-actions-push.yaml) | `push` events to `main` | `quay.io/redhat-user-workloads/rosa-tenant/rosa-trusted-actions:{{revision}}` |

Both PipelineRuns are adapted for the component's monorepo location: the
`build.appstudio.openshift.io/repo` annotation points at
`openshift-online/rosa-boundary`, `path-context` is
`components/trusted-actions`, `dockerfile` is `Containerfile`, and each
pipeline's `pipelinesascode.tekton.dev/on-cel-expression` restricts firing
to events whose changed paths match `components/trusted-actions/***` or the
pipeline's own `.tekton/rosa-trusted-actions-{pull-request,push}.yaml` file.
As currently written, neither expression is gated by a `false &&` prefix or
any other unconditional disable — the CEL conditions evaluate normally for
matching `pull_request`/`push` events. Both files do, however, carry the
retained comment `# Enable only at the coordinated cutover after checking
the shared image/release destination` directly above the expression. That
comment is a record of the pipelines' pre-cutover intent, not something the
YAML itself currently enforces, so **do not infer live/firing CI status from
this file content alone** — verify the current Konflux application,
component, and image/release bindings directly (e.g. in the Konflux console
or via `releng/konflux-release-data`) before relying on these pipelines as
an active signal. See
[Monorepo components: Boundary and Trusted Actions](../architecture/monorepo-and-trusted-actions.md)
("Tekton pipelines" section) for the full account of this history and the
caveats around it.

Either way, the pipeline build step itself only builds and pushes the
container image per `Containerfile` and does **not** invoke `go test`,
`make test`, or any other Go unit-test target from
`components/trusted-actions/Makefile` — Go unit tests, coverage, and the
integration/Backplane harnesses described above are a separate, Make-driven
concern that is not wired into these Tekton pipelines. Treat the Make
targets and harnesses on this page as the authoritative way to exercise
Trusted Actions' tests, and verify current CI/build activity (this
monorepo's Konflux pipelines vs. any still-active system tied to the
original `openshift-online/rosa-trusted-actions` repository) directly rather
than assuming either one is authoritative.

## Related pages

- [Monorepo components: Boundary and Trusted Actions](../architecture/monorepo-and-trusted-actions.md)
- [Trusted Actions deployment](../infrastructure/trusted-actions-deployment.md)
- [CI/CD and quality gates](../operations/ci-cd-and-quality-gates.md)
- [Trusted Actions API](../integrations/trusted-actions-api.md)
- [Verification](verification.md)
- [Trusted Actions execution workflow](../workflows/trusted-actions-execution.md)

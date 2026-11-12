---
type: testing-guide
title: Trusted Actions testing and CI
description: Describes the Trusted Actions component's unit, integration, and mock-dependency testing strategy, its Make targets and Codecov patch-coverage gate, and the Konflux Tekton pipelines that build and push its image on PR and push events in this monorepo.
tags: [trusted-actions, testing, ci, codecov, coverage, integration-tests, backplane, tekton, go]
verified:
  - by: openwiki/0.7.1
    at: 2026-11-12T16:02:44.301Z
sources:
  - id: openwiki-source-eebdf2baefd63a03b1cb3b5e
    resource: repo://.tekton/rosa-trusted-actions-pull-request.yaml
  - id: openwiki-source-12238a6f88dc834f61553058
    resource: repo://.tekton/rosa-trusted-actions-push.yaml
  - id: openwiki-source-5f7022cb75865b779a5792a0
    resource: repo://codecov.yml
  - id: openwiki-source-3051f255965c31db61eae3a3
    resource: repo://components/trusted-actions/codecov.yml
  - id: openwiki-source-c62a53560e154d1649f9a5b2
    resource: repo://components/trusted-actions/CONTRIBUTING.md
  - id: openwiki-source-2d8b922c7e5e8b7514a7bbff
    resource: repo://components/trusted-actions/docs/adding-a-trusted-action.md
  - id: openwiki-source-56c54c10348f1e72daffc214
    resource: repo://components/trusted-actions/go.mod
  - id: openwiki-source-01f41ebb3a6fce788680a5cc
    resource: repo://components/trusted-actions/integration/itest-down.sh
  - id: openwiki-source-54625ad7b6d11a03282fee57
    resource: repo://components/trusted-actions/integration/itest-run.sh
  - id: openwiki-source-3c3562d58ce85865e73956fe
    resource: repo://components/trusted-actions/integration/itest-up.sh
  - id: openwiki-source-642a30c5f33a9f636dc1436a
    resource: repo://components/trusted-actions/integration/README.md
  - id: openwiki-source-f31219609de20fbaee6c658e
    resource: repo://components/trusted-actions/internal/config/config_test.go
  - id: openwiki-source-6fa73d968628eb0b312bf0ee
    resource: repo://components/trusted-actions/internal/rta/command_test.go
  - id: openwiki-source-4c833b02bf6d5fc7a2476dea
    resource: repo://components/trusted-actions/Makefile
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
  - id: openwiki-source-202f5239bfb095a7cbbf7f0f
    resource: repo://docs/trusted-actions-monorepo-migration.md
generated: { by: "openwiki/0.7.1", at: "2026-11-12T16:02:44.301Z" }
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
| `make test-integration` | Starts the server in the background (`make run &`), waits a few seconds, runs `scripts/test-api.sh` against it, then stops the server. Fails and kills the server if the script fails. |
| `make test-api` | Runs `scripts/test-api.sh` directly against an already-running server; does not start or stop anything itself. |
| `make test-actions` | Runs the `tests/actions` action-level integration tests (`-tags=integration`) against the mock Backplane server, which must already be running via `make mock-backplane`. |
| `make test-actions-proxy` | Runs the subset of `tests/actions` tests matched by `-run Proxy` against the proxy Backplane server (`make proxy-backplane`), which requires a real `KUBECONFIG`. |
| `make itest-up` / `make itest-run` / `make itest-down` | Wrap the `integration/` podman-compose end-to-end harness (see below). |

`make test` is the baseline unit-test gate; `make test-coverage` is the local
equivalent of the CI coverage step described below.

## Coverage: Codecov patch-coverage gate

Per `TESTING.md`, `CONTRIBUTING.md`, and
[`docs/adding-a-trusted-action.md`](../../components/trusted-actions/docs/adding-a-trusted-action.md),
Trusted Actions enforces **patch coverage >= 80% on all PRs** via Codecov,
and new code must include unit tests to meet that bar. Coverage effort is
explicitly focused on the two packages considered the primary correctness
surface:

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
the repository and does not define the 80% handlers/config gate.

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

Two representative packages illustrate these conventions in practice:

- **`internal/config/config_test.go`** table-tests the small environment-
  variable helpers (`getEnv`, `getBoolEnv`, `getIntEnv`, `getDurationEnv`,
  `getPositiveIntEnv`, `getPositiveDurationEnv`, `getStringSliceEnv`) across
  set/unset/empty/unparseable-value cases (e.g. `TestGetBoolEnv` covers
  `"true"`, `"false"`, `"1"`, `"0"`, unset, and an unparseable `"yes"`), then
  exercises the full `Load` path — `TestLoad_Defaults`,
  `TestLoad_AWSAllowedRegionsFromEnv`/`FromFile`, `TestLoad_OCMBackplaneFromFile`,
  `TestLoad_OCMBackplaneEnvOverridesFile`, `TestLoad_AuthPolicy`, and
  `TestLoad_EnvOverrides` — to pin down config-file vs. environment-variable
  precedence for every settable value, plus file-read and parse error paths
  (`TestReadConfigFile_ReadError`, `TestReadConfigFile_UnmarshalError`).
- **`internal/rta/command_test.go`** drives the `rta` CLI's Cobra command
  tree end-to-end through `NewCommand()`, capturing stdout/stderr buffers
  rather than mocking Cobra, and asserts on rendered text and JSON output
  (`TestVersion_Text`/`TestVersion_JSON`, `TestActionList_Text`/`_JSON`) as
  well as user-facing error paths: an unknown subcommand with a "did you
  mean" suggestion (`TestRoot_UnknownSubcommand_Suggestion`), an unknown
  flag, missing required arguments, and a missing server
  (`TestActionRun_MissingServer`). This is the same stdlib-only,
  table/subtest style applied to a CLI surface instead of an HTTP handler.

## Integration tests

### `integration/`: podman-compose end-to-end harness

[`components/trusted-actions/integration/`](../../components/trusted-actions/integration/README.md)
is a disposable, podman-compose-based end-to-end harness that proves a real
execution request flows through the whole stack — HTTP → auth middleware →
executor → a real (if disposable) cluster → response — with **mock auth** and
**no OCM or Backplane dependency**. It is driven by three scripts, each also
exposed as a `make` target:

- **`itest-up.sh`** (`make itest-up`) — creates (or reuses) a disposable
  `kind` cluster, starts the `podman-compose.yml` stack (`localstack`, an AWS
  emulator), waits for both to report healthy, applies fixtures from
  `integration/fixtures/` (a pull secret and a Prometheus deployment), and
  waits for at least two Prometheus alert-evaluation cycles before returning.
- **`itest-run.sh`** (`make itest-run`) — retrieves a fresh kubeconfig from
  the kind cluster, exports `ROSA_TA_AUTH=disabled`, `ROSA_TA_KUBECONFIG`,
  `DATABASE_URL`, and the AWS emulator endpoint variables, starts the server,
  waits for `/health`, then exercises one action per execution scope (a
  `kube-api` `get` against `kube-system` pods, and an `aws-api` `aws-get`
  sweep across the EC2 and Route 53 resources LocalStack's community image
  supports), polling `GET /runs/{id}` until each execution reports
  `status: succeeded`. It also submits a request with an invalid param and
  asserts that execution fails, to confirm input validation survives the
  full HTTP path. The server is stopped on exit either way.
- **`itest-down.sh`** (`make itest-down`) — stops localstack, deletes the
  kind cluster, and removes generated local artifacts (kubeconfig, SQLite
  DB file, server log). Safe to run even if nothing is up.

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
- [Trusted Actions API](../integrations/trusted-actions-api.md)
- [Verification](verification.md)
- [Trusted Actions execution workflow](../workflows/trusted-actions-execution.md)

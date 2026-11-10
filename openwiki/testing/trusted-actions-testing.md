---
type: testing-guide
title: Trusted Actions testing and CI
description: Describes the Trusted Actions component's unit, integration, and mock-dependency testing strategy, its Make targets and Codecov patch-coverage gate, and the current (pending-cutover) state of its CI pipelines in this monorepo.
tags: [trusted-actions, testing, ci, codecov, coverage, integration-tests, backplane, tekton, go]
verified:
  - by: openwiki/0.7.1
    at: 2026-11-10T16:03:08.957Z
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
  - id: openwiki-source-01f41ebb3a6fce788680a5cc
    resource: repo://components/trusted-actions/integration/itest-down.sh
  - id: openwiki-source-54625ad7b6d11a03282fee57
    resource: repo://components/trusted-actions/integration/itest-run.sh
  - id: openwiki-source-3c3562d58ce85865e73956fe
    resource: repo://components/trusted-actions/integration/itest-up.sh
  - id: openwiki-source-642a30c5f33a9f636dc1436a
    resource: repo://components/trusted-actions/integration/README.md
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
  - id: openwiki-source-f37fcbb022d24ddfd8044d01
    resource: repo://docs/trusted-actions-source-colocation.md
generated: { by: "openwiki/0.7.1", at: "2026-11-10T16:03:08.957Z" }
---

## Scope and where these tests live

This page covers the Trusted Actions component's own test suite and build
tooling, all of which live under
<!-- openwiki: broken internal link [../../components/trusted-actions] file "../../components/trusted-actions" does not exist. Fix the href or restore the target, then delete this comment. -->
[`components/trusted-actions/`](../../components/trusted-actions). Trusted
Actions is an independent Go module with its own `go.mod` and `Makefile`;
root-level commands do not exercise it:

> Run Trusted Actions commands from `components/trusted-actions/` (for
> example, `make -C components/trusted-actions test`). Root `go test ./...`
> and root Makefile targets do **not** exercise the nested Go module.

This is a load-bearing operational fact, not a style preference — the nested
module is invisible to any tooling that only walks the repository root's
`go.mod`. See
[source co-location notes](../../docs/trusted-actions-source-colocation.md)
and [Monorepo components: Boundary and Trusted Actions](../architecture/monorepo-and-trusted-actions.md)
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

## Integration tests

### `integration/`: podman-compose end-to-end harness

<!-- openwiki: broken internal link [../../components/trusted-actions/integration] file "../../components/trusted-actions/integration" does not exist. Fix the href or restore the target, then delete this comment. -->
[`components/trusted-actions/integration/`](../../components/trusted-actions/integration)
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

<!-- openwiki: broken internal link [../../components/trusted-actions/tests/actions] file "../../components/trusted-actions/tests/actions" does not exist. Fix the href or restore the target, then delete this comment. -->
[`components/trusted-actions/tests/actions/`](../../components/trusted-actions/tests/actions)
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

<!-- openwiki: broken internal link [../../components/trusted-actions/tests/mock-backplane] file "../../components/trusted-actions/tests/mock-backplane" does not exist. Fix the href or restore the target, then delete this comment. -->
[`tests/mock-backplane/`](../../components/trusted-actions/tests/mock-backplane)
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

<!-- openwiki: broken internal link [../../components/trusted-actions/tests/proxy-backplane] file "../../components/trusted-actions/tests/proxy-backplane" does not exist. Fix the href or restore the target, then delete this comment. -->
[`tests/proxy-backplane/`](../../components/trusted-actions/tests/proxy-backplane)
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

## CI status: present in `.tekton/` but held pending cutover

CI for this component is **not** currently running from this monorepo.
Trusted Actions' Tekton PipelineRun definitions —
`.tekton/rosa-trusted-actions-pull-request.yaml` and
`.tekton/rosa-trusted-actions-push.yaml` — exist in this repository and were
adapted for their monorepo location (repo annotation, `path-context`, and
`pathChanged()` filters all point at `components/trusted-actions`), but both
pipelines' `pipelinesascode.tekton.dev/on-cel-expression` triggers are
prefixed with `false &&`, which makes them structurally present but
unconditionally inactive. This is a deliberate pre-cutover hold, not a
leftover: it prevents Boundary PR/push events from starting TA builds,
publishing into the TA Quay image repository, or producing TA
snapshots/releases through this path while the Konflux component's source
binding still points at the original `openshift-online/rosa-trusted-actions`
repository. See
[Monorepo components: Boundary and Trusted Actions](../architecture/monorepo-and-trusted-actions.md#tekton-pipelines-present-but-held)
for the full account of the guard and the planned cutover.

Until that cutover happens, treat the Make targets and harnesses on this page
as the authoritative way to exercise Trusted Actions' tests — they are not
yet wired into an active CI pipeline inside this monorepo, and the original
`rosa-trusted-actions` repository remains the active development source and
CI system of record for this component.

## Related pages

- [Monorepo components: Boundary and Trusted Actions](../architecture/monorepo-and-trusted-actions.md)
- [Trusted Actions API](../integrations/trusted-actions-api.md)
- [Verification](verification.md)
- [Trusted Actions execution workflow](../workflows/trusted-actions-execution.md)

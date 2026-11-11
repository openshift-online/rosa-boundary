# Trusted Actions contributor guidance

This directory is a **separate Go module** within rosa-boundary. Read this file
for Trusted Actions changes, then verify behavior against current code and tests.
The repository-root [AGENTS.md](../../AGENTS.md) describes cross-component and
deployment boundaries. Its Boundary CLI, Lambda, and ECS Exec rules do not
automatically describe this API server.

## Start here

- [README.md](README.md) for the API and local usage;
  [TESTING.md](TESTING.md) for test conventions;
  [docs/deployment.md](docs/deployment.md) for Trusted Actions deployments.
- `cmd/server/` wires the chi HTTP server, middleware, and workers.
  `cmd/rta/` is the separate CLI. `internal/handlers/` implements the generated
  OpenAPI server interface, with auth, authorization, action execution, storage,
  and audit code under their respective `internal/` packages.
- `openapi/` is the API source. `internal/openapi/api.go` is generated; edit the
  spec and run `make generate` rather than editing generated code by hand.
- `terraform/global/` and `terraform/regional/` are independent roots and
  states; they are not part of Boundary's `deploy/` Terraform states. The
  HCP definitions at the repository root now point the existing workspaces
  at Boundary; see [migration and current layout](../../docs/trusted-actions-monorepo-migration.md).

## Working in this component

Run Go and Make commands from `components/trusted-actions/` (or use
`make -C components/trusted-actions ...` from the repository root). Root
`go test ./...` and root Make targets do not test this module. The module path
remains `github.com/openshift-online/rosa-trusted-actions`.

- Prefer focused changes that follow existing handler, middleware, and config
  patterns. Use standard Go formatting and update affected tests, never delete
  failing tests to make a change pass.
- Protect account/cluster authorization, action scoping, credentials, and audit
  boundaries. Do not commit secrets or write sensitive credentials to logs.
- After Go changes, run focused package tests and `make test`; use `make
  test-race` when concurrency is affected. After OpenAPI changes, run `make
  generate` and check the generated diff. Choose additional checks from the
  [testing guide](TESTING.md) and actual Makefile recipes.
- The imported `make build`, `build-rta`, and `build-server` targets invoke
  GoReleaser, but are not validated monorepo build paths. The imported
  `.goreleaser.yaml` lives in this component, not at the repository root;
  a root-level GoReleaser release invocation will not find it as-is. Adapt
  config selection and nested source paths in a follow-up before relying on
  these targets or enabling a Boundary TA release. For now, use `go build
  ./cmd/rta` or `go build ./cmd/server` from this directory for a local build.
  The component also has its own `VERSION`; do not use a Boundary-root `v*`
  tag or enable the old repository's release workflow without a reviewed cutover.
- The repo-root `renovate.json`, `.coderabbit.yaml`, and
  `.pre-commit-config.yaml` govern both components. The copied component
  `.pre-commit-config.yaml` is not run by the repository's Git hook or root
  pre-commit; running `pre-commit` directly from this directory does select
  the copied, standalone config. Run the root hooks from the repository root,
  and run `make lint` in this directory for full-module linting. The imported
  baseline has existing lint findings; TA lint is not yet a working root
  pre-commit gate.
- The repository-root `openwiki/` is the **only** monorepo wiki. Trusted Actions
  source is covered there after a root OpenWiki update; do not recreate the
  old component-local generated wiki or add a component `.openwikiignore`.

The archived original repository used `AGENTS.md` too. Keep this
monorepo-specific component guide rather than copying its standalone root
guide over it. Agent skills live in
`.agents/skills/`, with `.claude/skills/` symlinks for Claude Code discovery.
The component retains `.claude/` helper material from the original repository.

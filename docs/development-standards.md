# Development standards

This is the contributor checklist for changing Boundary's image, shell runtime, CLI, Lambda, or infrastructure. For current implementation details, use the linked source and tests rather than treating examples here as a runtime inventory. See [docs/testing.md](testing.md) for suite setup and CI, and the root [Makefile](../Makefile) for supported targets.

## Builds and deployments

- Use root Makefile targets for image and Go builds, Lambda tests, and LocalStack. Build Lambda dependencies for local Terraform via the [regional Makefile](../deploy/regional/Makefile); use its `init`, `validate`, `plan`, and `apply` targets rather than invoking Terraform directly. Build images through `make`, not direct `podman build`.
- The staging delivery path is Git/PR → HCP Terraform, **not** the dev Makefile. Follow [staging deployment](staging-deployment.md) and check `hcp-terraform/rosa-boundary/main.tf` for the current regional variable list and apply settings. Do not mutate HCP-managed regional workspace variables outside Git.
- Keep environment-specific values in approved configuration. For local dev, check the root `.env` for variables lacking defaults in `deploy/regional/variables.tf`, then ask for missing inputs; never expose or commit secrets. Do not copy local values into staging code.

## Image and shell changes

Apply these requirements to new and changed code in [Containerfile](../Containerfile), [entrypoint.sh](../entrypoint.sh), `build/`, `skel/sre/`, and shell utilities:

- Keep the multi-stage image and existing digest-pinned UBI9 base; changing the base requires explicit approval. Keep installers and build tools in builder stages, and put only final artifacts in the runtime image. Use `platform_convert` where architectures differ. Report architecture limitations rather than claiming support from image labels. ARM enablement and base-image migration are outside the six-tool update scope.
- Pin externally downloaded tool releases and preserve published SHA256/signature verification unless supplied through `dnf`. The reduced SRE tool scope is ocm, ocm-backplane, osdctl, yq, oc, and AWS CLI v2. Select latest stable releases at implementation time, record the lookup date in the PR, and keep the only editable exact defaults in the six annotated `Containerfile` ARGs. Do not discover latest at build time or silently substitute versions. Require published SHA256 for the four GitHub tools, a pinned Red Hat signature plus archive SHA256 for oc, and a pinned-key detached signature for AWS CLI v2; a computed hash alone is not verification. Follow the [six-tool contract](dependency-management-automation.md#six-tool-exact-pin-contract-rosaeng-67158). Reuse authenticated GitHub downloads and build secret mounts; never execute downloaded tools while token/private-key mounts are accessible, bake secrets into layers, use `curl | bash`, or install through npm. Keep verification dependencies in builder stages. Do not harvest/vendor licenses or add bespoke notice extraction; preserve files needed by normal distributions.
- Preserve OCI labels, stage-purpose comments, comments explaining non-obvious RUNs, grouped layers, `COPY --chmod` where applicable, and `dnf clean all` plus cache removal after installs. Prefer readable long-form options in RUN and shell code when the tool supports them (builtins and tools without long forms excepted).
- Shell functions need purpose comments; optional environment-gated behavior needs documented defaults and a graceful unset path. Keep `bashrc.d` files numerically prefixed for lexical ordering. Make executable scripts sourceable for bats by guarding `main` with `[[ "${BASH_SOURCE[0]}" == "${0}" ]]`. Add bats coverage for changed entrypoint functions, bashrc fragments, and utilities. See [tests/shell](../tests/shell) and [`.shellcheckrc`](../.shellcheckrc); changed shell code must be shellcheck-clean.
- Preserve the runtime's least-privilege boundary: the workload/ECS Exec user is `sre`; privileged setup must not turn the workload into root. Keep credential-derived OCM and kubeconfig state on **task-scoped, audit-excluded mounts**, not the persistent EFS home or S3 escrow. See `entrypoint.sh` mount checks and [architecture](architecture/overview.md).
- Preserve `sync_to_s3()` for normal exit and SIGTERM/SIGINT/SIGHUP, including its no-follow-symlinks behavior; do not `exec` away the shell that handles cleanup. Timeout enforcement belongs to the [reaper Lambda](../lambda/reap-tasks/handler.py), not the container. Consult [entrypoint tests](../tests/shell/entrypoint.bats) when editing shutdown behavior.

## Verification before a PR

Use the narrowest relevant checks, then expand to affected integration gates. Do not claim a target covers a tool unless its Make recipe does. The root `make test` runs unit/regression suites, while `make check` adds lint, Staticcheck, and pre-commit. `make test-shell` runs Bats suites; `make lint-shell` is strict ShellCheck and is included in `make lint`. Neither aggregate starts LocalStack. With the additional prerequisites in
[CONTRIBUTING.md](../CONTRIBUTING.md), `make test-all` attempts the broader local
gates against an already-running LocalStack. It reports skips as INCOMPLETE;
`TEST_ALL_ARGS=--require-complete` makes incomplete coverage nonzero. This does
not alter the separate CI entrypoint's JUnit guard.

| Changed surface | Required checks / references |
|-----------------|------------------------------|
| Go | `make test-cli`, `make test-coverage`, `make fmt` (review resulting diff), `make lint`, `make staticcheck` |
| Lambda | `make test-lambda`; for AWS interactions also LocalStack integration below |
| Shell, entrypoint, bashrc | `bats tests/shell/` and `shellcheck` on changed shell scripts; inspect [tests/shell](../tests/shell) for additional coverage |
| Infrastructure, Lambda, ECS | `make localstack-up`, `make test-localstack-fast`, relevant full `make test-localstack` when feasible, `make localstack-down`; see [LocalStack README](../tests/localstack/README.md) |
| Containerfile, entrypoint, skel | `make test-github-dl` for build-helper unit/contract tests; build through the existing Make target for the usable architecture, then `make verify-image-tools TOOL_IMAGE=<local image tag or digest>`. Retain the printed image ID and results. Test affected architectures for architecture-sensitive changes and report blocked checks; ARM enablement is not a prerequisite for the six-tool update. Add interactive/entrypoint checks when those surfaces change; see [SRE tool acceptance](testing.md#sre-tool-pin-migration-acceptance) |
| Security findings | `make validate-findings`, `make convert-sarif`; schema and converter are in `scripts/findings-to-sarif.py` |

For the six-tool migration, require exact final-image executable versions, Backplane plugin discovery, AWS invocation/layout, retained completions, and absence of ocm-addons, the backplane-tools installer, and added license-vendoring artifacts. Keep six pin-update rules with explicit `automerge: false` and normal human review. Integrity or version failures block acceptance. Earlier draft results are not evidence for the revised change. Local checks do not prove ARM, hosted automation, staging, or production behavior. Deployment, promotion redesign, and operational ownership projects are not prerequisites for this source change.

Run `make pre-commit` (uv-managed hooks) before a PR. For Prow's LocalStack entrypoint itself, run `bats tests/localstack/ci-run.bats` locally (it cannot self-test in CI). If prerequisites prevent a gate, state which check was not run and why. Do not commit credentials or generated artifacts.

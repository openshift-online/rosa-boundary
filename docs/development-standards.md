# Development standards

This is the contributor checklist for changing Boundary's image, shell runtime, CLI, Lambda, or infrastructure. For current implementation details, use the linked source and tests rather than treating examples here as a runtime inventory. See [docs/testing.md](testing.md) for suite setup and CI, and the root [Makefile](../Makefile) for supported targets.

## Builds and deployments

- Use root Makefile targets for image and Go builds, Lambda tests, and LocalStack. Build Lambda dependencies for local Terraform via the [regional Makefile](../deploy/regional/Makefile); use its `init`, `validate`, `plan`, and `apply` targets rather than invoking Terraform directly. Build images through `make`, not direct `podman build`.
- The staging delivery path is Git/PR → HCP Terraform, **not** the dev Makefile. Follow [staging deployment](staging-deployment.md) and check `hcp-terraform/rosa-boundary/main.tf` for the current regional variable list and apply settings. Do not mutate HCP-managed regional workspace variables outside Git.
- Keep environment-specific values in approved configuration. For local dev, check the root `.env` for variables lacking defaults in `deploy/regional/variables.tf`, then ask for missing inputs; never expose or commit secrets. Do not copy local values into staging code.

## Image and shell changes

Apply these requirements to new and changed code in [Containerfile](../Containerfile), [entrypoint.sh](../entrypoint.sh), `build/`, `skel/sre/`, and shell utilities:

- Keep one multi-stage, amd64/arm64 image on the existing digest-pinned UBI9 base; changing the base requires explicit approval. Keep installers and build tools in builder stages, and put only final artifacts in the runtime image. Use `platform_convert` where architectures differ. Test both architectures for architecture-sensitive changes.
- Pin externally downloaded tool releases and verify published SHA256 (or stronger) checksums unless supplied through `dnf` or `backplane-tools`. Use authenticated GitHub API calls and build secret mounts; never bake secrets into layers, use `curl | bash`, or install through npm. See `build/github_dl.py` and the Containerfile for current patterns.
- Preserve OCI labels, stage-purpose comments, comments explaining non-obvious RUNs, grouped layers, `COPY --chmod` where applicable, and `dnf clean all` plus cache removal after installs. Prefer readable long-form options in RUN and shell code when the tool supports them (builtins and tools without long forms excepted).
- Shell functions need purpose comments; optional environment-gated behavior needs documented defaults and a graceful unset path. Keep `bashrc.d` files numerically prefixed for lexical ordering. Make executable scripts sourceable for bats by guarding `main` with `[[ "${BASH_SOURCE[0]}" == "${0}" ]]`. Add bats coverage for changed entrypoint functions, bashrc fragments, and utilities. See [tests/shell](../tests/shell) and [`.shellcheckrc`](../.shellcheckrc); changed shell code must be shellcheck-clean.
- Preserve the runtime's least-privilege boundary: the workload/ECS Exec user is `sre`; privileged setup must not turn the workload into root. Keep credential-derived OCM and kubeconfig state on **task-scoped, audit-excluded mounts**, not the persistent EFS home or S3 escrow. See `entrypoint.sh` mount checks and [architecture](architecture/overview.md).
- Preserve `sync_to_s3()` for normal exit and SIGTERM/SIGINT/SIGHUP, including its no-follow-symlinks behavior; do not `exec` away the shell that handles cleanup. Timeout enforcement belongs to the [reaper Lambda](../lambda/reap-tasks/handler.py), not the container. Consult [entrypoint tests](../tests/shell/entrypoint.bats) when editing shutdown behavior.

## Verification before a PR

Use the narrowest relevant checks, then expand to affected integration gates. Do not claim a target covers a tool unless its Make recipe does; in particular, the root `make lint` currently tolerates shellcheck failures and there are no root `test-shell` or `lint-shell` targets.

| Changed surface | Required checks / references |
|-----------------|------------------------------|
| Go | `make test-cli`, `make test-coverage`, `make fmt` (review resulting diff), `make lint`, `make staticcheck` |
| Lambda | `make test-lambda`; for AWS interactions also LocalStack integration below |
| Shell, entrypoint, bashrc | `bats tests/shell/` and `shellcheck` on changed shell scripts; inspect [tests/shell](../tests/shell) for additional coverage |
| Infrastructure, Lambda, ECS | `make localstack-up`, `make test-localstack-fast`, relevant full `make test-localstack` when feasible, `make localstack-down`; see [LocalStack README](../tests/localstack/README.md) |
| Containerfile, entrypoint, skel | `make build` (or both architecture targets), verify affected tools and an interactive runtime with `podman run`; see root Makefile and [README.md](../README.md) |
| Security findings | `make validate-findings`, `make convert-sarif`; schema and converter are in `scripts/findings-to-sarif.py` |

Run `pre-commit run --all-files` before a PR. For Prow's LocalStack entrypoint itself, run `bats tests/localstack/ci-run.bats` locally (it cannot self-test in CI). If prerequisites prevent a gate, state which check was not run and why. Do not commit credentials or generated artifacts.

# Trusted Actions: where things live

> **Point-in-time record (2026-11-11):** This document captures the monorepo
> immediately after the successful Trusted Actions migration. It is not a
> living status page and is not intended to be updated as the repository or
> deployments evolve. For current behavior, check source, HCP settings and
> the relevant delivery systems directly.

Trusted Actions was copied into `openshift-online/rosa-boundary`. The
[original repository](https://github.com/openshift-online/rosa-trusted-actions)
is archived but remains the source-history reference.

| What | Where |
| --- | --- |
| API, CLI, tests, Go module, container build | `components/trusted-actions/` |
| Terraform resource definitions | `components/trusted-actions/terraform/{global,regional}/` |
| HCP workspace definitions | `hcp-terraform/rosa-trusted-actions/` |
| Konflux build pipelines | `.tekton/rosa-trusted-actions-{pull-request,push}.yaml` |
| GoReleaser config | `components/trusted-actions/.goreleaser.yaml` |
| Konflux release configuration | [`releng/konflux-release-data`](https://gitlab.cee.redhat.com/releng/konflux-release-data) |
| Prow job configuration | [`openshift/release`](https://github.com/openshift/release) |

Run Trusted Actions builds and tests from `components/trusted-actions/`;
Boundary's root Go and Make commands do not cover its separate module.

## Migration outcome

The source, CI build triggers, and deployment source moved to Boundary. The
existing Trusted Actions HCP meta, global, and stage workspaces were rebound to
this repository and its component Terraform roots **in place**; their AWS state
was not moved into Boundary's Terraform stacks. Konflux now builds the TA image
from Boundary. The old repository is archived.

This was a files-only import, not a Git-history merge. The final reconciled
source revision from the former repository was
`119b5d522eb2e12459ee1bdc2835a9385821e9a8`; subsequent development
belongs in Boundary. The old Git history remains available in the archived
repository. Some files required reconciliation rather than a verbatim copy:

- Repo-level Renovate configuration lives in root `renovate.json`; root
  `.coderabbit.yaml` and `.pre-commit-config.yaml` govern the combined repo.
  Component guidance is in `components/trusted-actions/AGENTS.md`.
- The original generated `openwiki/` was **not** imported. The combined wiki
  lives at Boundary's root `openwiki/`; do not maintain a second component wiki.
- The old repository's GitHub release and lockfile workflows were **not**
  installed at the Boundary root. The GoReleaser config was imported under
  the component, but a working monorepo GitHub release workflow still needs
  its own review (tag namespace, nested paths, credentials and action pins).

## Source and deployment boundaries

| Component | Source and build | Terraform roots/state | HCP definitions |
| --- | --- | --- | --- |
| Boundary | Repository root (`go.mod`, `Makefile`, `Containerfile`, `lambda/`) | `deploy/account/`, `deploy/network/`, `deploy/regional/` | `hcp-terraform/rosa-boundary/` and `hcp-terraform/aws-creds/` |
| Trusted Actions | `components/trusted-actions/` (independent `go.mod`, `Makefile`, `Containerfile`) | `components/trusted-actions/terraform/global/` and `components/trusted-actions/terraform/regional/` | `hcp-terraform/rosa-trusted-actions/` |

Boundary's `lambda/` applications have not moved into the component. TA has
its own authentication, credentials, and audit model; Boundary's ECS Exec
controls do not apply to it. TA-specific `OWNERS` files under the component,
HCP root and `.tekton/` add approvers while inheriting root approvers. Check
Prow/Tide behavior on real PRs rather than inferring merge permissions from
the files alone. Root pre-commit hooks cover both components; the imported
TA `.pre-commit-config.yaml` is not the repository-root hook configuration.

The **existing** `rosa-trusted-actions-global` and
`rosa-trusted-actions-stage` HCP workspaces use this repository and the
component's `terraform/global` and `terraform/regional` directories. The
meta-workspace reads `hcp-terraform/rosa-trusted-actions/`. Stage reads global
remote state and is triggered after successful global applies. Do not create
a duplicate TA stack under Boundary's Terraform roots or edit Git-managed
workspace variables directly in HCP.

Global/stage `auto_apply` and `auto_apply_run_trigger` were temporarily
disabled for the cutover, then [restored](https://github.com/openshift-online/rosa-boundary/pull/517)
to `true` on 2026-11-11 after successful workspace runs. The first meta run
after rebind auto-applied unexpectedly. For subsequent runs, check
[the workspace definitions](../hcp-terraform/rosa-trusted-actions/main.tf)
and live HCP settings, and review global and stage AWS plans separately;
a meta plan alone does not show downstream resource changes.

The TA [Konflux PR and main-push pipelines](../.tekton/) use the nested build
context, TA-specific path filters, and a distinct TA image destination.
Konflux release configuration is external. As of this snapshot, a
Boundary-hosted GitHub release flow had not been established.

For the historical cutover sequence and reviewed plans, see the
[cutover plan](https://docs.google.com/document/d/1hXarsd3n1vtMr5zeDlwW9JtGP74euL38AsjUZSB4Z34/edit?tab=t.0)
and [Terraform cutover thread](https://redhat-internal.slack.com/archives/C0B9BKW9T7V/p1794406759141519).

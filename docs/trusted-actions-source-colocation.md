# Trusted Actions source co-location

Trusted Actions files were copied from `openshift-online/rosa-trusted-actions`
`main` at `8ce39a7344b52444576fc1e44ab1f532fd0dfac4`. This is a files-only
import. No Trusted Actions commits or per-file Git history were imported; the
original repository remains the historical reference. Do not archive it until
the separate CI and deployment-source cutover has been verified with its owners.
See the [migration inventory and refresh procedure](trusted-actions-monorepo-migration.md)
before reconciling new development from the still-active TA repository.

## Source and ownership

| Component | Source and build | Terraform root/state | HCP definitions |
| --- | --- | --- | --- |
| Boundary | Repository root (`go.mod`, `Makefile`, `Containerfile`) | `deploy/account/`, `deploy/network/`, `deploy/regional/` | `hcp-terraform/rosa-boundary/` and `hcp-terraform/aws-creds/` |
| Trusted Actions | `components/trusted-actions/` (independent `go.mod`, `Makefile`, `Containerfile`) | `components/trusted-actions/terraform/global/` and `components/trusted-actions/terraform/regional/` | `hcp-terraform/rosa-trusted-actions/` |

`components/` names independently built parts without implying every part is
a long-running service. Boundary's `lambda/` directory has not moved: its
functions likely belong under `components/boundary/` eventually, alongside the
Boundary CLI and container. That relocation needs a separate change because
Terraform packaging, Make targets, tests, and Konflux reference today's paths.

Run Trusted Actions commands from `components/trusted-actions/`, for example
`make -C components/trusted-actions test`. Root `go test ./...` and root Makefile
targets do **not** cover the nested module. The Go module path and the two
components' image destinations remain unchanged. The monorepo uses **one**
generated OpenWiki at repository-root `openwiki/` for both components; TA's
old generated wiki and any TA `.openwikiignore` are not imported. The root
OpenWiki periodic should incorporate TA source after merge; verify that it
does, rather than copying the old wiki or creating another under `components/`.

`components/trusted-actions/OWNERS` and `hcp-terraform/rosa-trusted-actions/OWNERS`
exclude inherited Boundary owners. `.tekton/OWNERS` gives TA its own approvals
for its pipeline files while retaining Boundary ownership of Boundary pipelines
and the shared approval file. Validate the intended TA-only, Boundary-only,
and mixed PR approvals with Prow/Tide before relying on independent merging.

## Deployment is **not** switched by this import

The copied TA HCP configuration still targets the original TA GitHub repository
and its original `terraform/global` and `terraform/regional` working directories.
The existing TA global and stage HCP workspaces own their current AWS resources;
the regional root still reads the named global workspace's remote state. This
import does not bind the TA meta-workspace or workload workspaces to Boundary,
transfer state, apply Terraform, or create a second TA stack in Boundary's
regional state. Boundary's workspace definitions and AWS resources are unchanged.

Before switching the deployment source, coordinate the TA meta-workspace's VCS
binding with its bootstrap owner. Change the *existing* Git-managed TA workspace
definitions to point at `openshift-online/rosa-boundary` and
`components/trusted-actions/terraform/{global,regional}` while preserving workspace
identities, variable sets, run triggers, and remote-state permissions. Inspect
live auto-apply settings and queued runs and gate affected workspaces **before**
the VCS change: the copied TA definitions currently specify both `auto_apply`
and `auto_apply_run_trigger` as `true`. A meta plan does not show downstream AWS
changes; separately review downstream plans for no unexpected resource actions.
No workspace variables should be edited directly in HCP.

The copied TA image PipelineRuns in `.tekton/` use the nested build context and
TA-specific path filters, but external Konflux repository/component bindings,
Prow jobs, the old-repo TA OpenWiki periodic, Renovate/Codecov/CodeQL, required
checks and release paths still need independent validation and coordinated
cutover. The existing Boundary OpenWiki periodic continues to update the one
root wiki; do not rebind the TA periodic to the nested component. The TA image
and existing deployed image digest are not changed by importing files.
Do not treat this source import as proof of working CI or live deployment.

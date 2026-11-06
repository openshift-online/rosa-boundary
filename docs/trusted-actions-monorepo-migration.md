# Trusted Actions monorepo migration inventory

This inventory was checked on 2026-11-06. It records the **files-only**
import of Trusted Actions into
`openshift-online/rosa-boundary` and how to refresh it while
`openshift-online/rosa-trusted-actions` remains the active development source.
The imported baseline is the TA `main` commit
`8ce39a7344b52444576fc1e44ab1f532fd0dfac4`. These counts and comparisons
describe **that revision**, not all changes subsequently made in the TA repo.
No TA Git history was imported; the original repository remains the historical
reference and must not be archived until the source/CI/deployment cutover is
validated with its owners. See [source co-location](trusted-actions-source-colocation.md)
for deployment and ownership boundaries.

## What the import contains

All **283 Git-tracked files** at the baseline revision are accounted for:
**238 imported or reconciled**, and **45 intentionally omitted** OpenWiki
artifacts. The paths below are relative to each repository root:

| Original TA paths | Destination in Boundary | Count | Treatment |
| --- | --- | ---: | --- |
| All tracked paths except the five groups below | `components/trusted-actions/<original path>` | 231 | Keep the independent Go module, source, docs, OpenAPI, test fixtures, image build, `terraform/global/`, and `terraform/regional/` together. Includes TA `.claude/` helpers, `codecov.yml`, `.gitignore`, and `LICENSE`. |
| `CLAUDE.md` | `components/trusted-actions/AGENTS.md` | 1 | Replace the old startup guide with component-specific contributor guidance; do not keep both guides. |
| `.github/renovate.json` | Root `renovate.json` | 1 | Reconcile TA rules into Boundary's existing repo-level config; remove the nested `.github/` directory. |
| `hcp-terraform/rosa-trusted-actions/{main.tf,variables.tf,terraform.auto.tfvars}` | `hcp-terraform/rosa-trusted-actions/` | 3 | Byte-for-byte copy of TA's HCP meta-workspace definition and tracked variables. Its original VCS repo and working directories are intentionally **not** switched by the import. |
| `.tekton/rosa-trusted-actions-{pull-request,push}.yaml` | Root `.tekton/` | 2 | Update the repo annotation to Boundary, the build context to `components/trusted-actions`, and PR/push change filters to the component and each pipeline file. Keep the TA image destination separate. |
| `openwiki/**` | **Not imported** | 45 | Generated TA wiki pages, Claims sidecars, and state belong to the former repository; maintain one combined wiki at Boundary's root `openwiki/`. Do not copy a future TA `.openwikiignore` either. |

The component directory is therefore **not** a complete one-to-one copy of
the old repo root. Of the 238 imported/reconciled source files, **226 are
byte-for-byte copies** at their mapped destinations. The twelve transformed
files are:

| File at destination (original path if different) | Difference |
| --- | --- |
| `components/trusted-actions/OWNERS` | Added `options.no_parent_owners: true` so parent Boundary owners cannot approve TA-only changes. |
| `components/trusted-actions/cmd/rta/main.go` | Added final newline via pre-commit. |
| `components/trusted-actions/openapi/paths/README.md` | Removed trailing whitespace on three lines. |
| `components/trusted-actions/tests/mock-backplane/backplane.yaml` | Removed trailing whitespace on one line. |
| `components/trusted-actions/tests/mock-backplane/scripts/trustedactions-post.js` | Removed trailing whitespace on one line. |
| `.tekton/rosa-trusted-actions-pull-request.yaml` | Changed repo annotation, PR path filter, and build context as described above. |
| `.tekton/rosa-trusted-actions-push.yaml` | Changed repo annotation, push path filter, and build context as described above. |
| `CLAUDE.md` → `components/trusted-actions/AGENTS.md` | Replaced stale repository-root instructions with a concise, component-scoped startup guide; updated references in the copied `.claude/` helpers and Boundary's root `AGENTS.md`. |
| `.github/renovate.json` → root `renovate.json` | Merged TA's `go-yit` exclusion and scoped, review-only Go/Tekton rules into Boundary's config instead of preserving an inert nested config. |
| `components/trusted-actions/.claude/agents/docs-agent.md` | Pointed documentation maintenance at `AGENTS.md`. |
| `components/trusted-actions/.claude/hooks/README.md` | Updated the development-guide link to `AGENTS.md`. |
| `components/trusted-actions/.claude/skills/add-trusted-action/SKILL.md` | Updated the guardrails reference to `AGENTS.md`. |

Two **new** ownership files were added in Boundary, rather than copied from
TA: `hcp-terraform/rosa-trusted-actions/OWNERS` and `.tekton/OWNERS`. Boundary's
root README, `AGENTS.md`, `.gitignore`, `renovate.json`, `.coderabbit.yaml`,
and its two Boundary image pipelines were also edited for co-location. Apart
from the TA rules folded into root `renovate.json`, these are not copied TA
source files. There was no TA repo-local CodeRabbit config to copy;
Boundary's root `.coderabbit.yaml` adds TA-specific review instructions.

**One OpenWiki in the monorepo:** keep the existing Boundary root `openwiki/`
and let its scheduled OpenWiki update incorporate Trusted Actions source after
the merge. Do not copy the original TA `openwiki/` or a TA `.openwikiignore`,
do not initialize a second wiki in `components/trusted-actions/`, and do not
overwrite root-generated pages/Claims with the old repo's generated output.
The baseline TA revision has no tracked `.openwikiignore`; this exclusion also
applies if one appears during a later source refresh. Verify that a post-merge
root wiki update actually documents both components. The original TA-repo
OpenWiki periodic still targets the original repository; retire it as part of
the external CI cutover, not by rebinding it to the nested directory.

Renovate reads one repository-level config, not a nested component config.
The root rules keep TA's `go-yit` exclusion, separate non-major Go grouping,
review-only TA dependency updates (including Terraform), and scoped Tekton
discovery. The old OpenShift boilerplate preset is **not** extended globally
because it would also change Boundary's managers, grouping, labels and
automerge policy. Review actual MintMaker PRs before considering the
dependency automation cutover complete.

The repository Git hook runs from the Git root and selects the root pre-commit
config. Running `pre-commit` directly from the component directory instead
selects the imported TA `.pre-commit-config.yaml`, which remains a snapshot of
the original repository and has not been adapted for monorepo paths. Run root
pre-commit from the root. Root hooks now scan TA files for secrets and run its
Go build in the separate module. TA lint is not merged as a root gate yet: the
imported snapshot has existing lint findings, and the old pinned linter cannot
handle the current Go toolchain. Run full-module `make lint` and tests separately and
resolve that baseline before enforcing lint. The copied TA `go-mod-tidy` hook is
not part of the root commit hook because it rewrites module files, and its
`rbac-wildcard-check` calls a Make target not present in the imported module.

**Other files not imported into Git:** the original `.git/` directory, commit
ancestry, hooks, local build outputs, ignored files, and three untracked files
observed in the source checkout at import: `.opencode/agents/rosa-trusted-actions.md`,
`trusted-actions-enhancement-review-2026-10-12.md`, and
`trusted-actions-jira-reorganization.md`. The `.opencode` agent was copied only
to the working tree's root `.opencode/` for local use; that directory is
ignored and must not be committed. Recheck for new untracked files at refresh
time; their absence from this import is deliberate, not a blanket rule for
future source files.

## Refresh from the still-active TA repository

The old repo remains the source of truth **until** owners agree on cutover.
Do not refresh from an arbitrary local feature branch or assume that the
original baseline is still current. Work in a new or existing Boundary feature
branch/worktree; leave both source checkouts and local-only files intact.

1. Coordinate a candidate source revision with TA owners. Fetch the TA
   repository's upstream `main`, record its full SHA (`NEW_TIP`), and compare
   it to the last imported TA SHA (`BASE`, initially the SHA above). If `main`
   has moved again before cutover, repeat this comparison. Update the recorded
   baseline here only **after** the new snapshot has actually been copied and
   validated; preserve the earlier revision in the PR description.
2. Inventory **added, modified, renamed, and deleted** paths between those
   two TA revisions. For example, from a clone of TA:

   ```sh
   git fetch upstream main
   git diff --no-renames --name-status BASE NEW_TIP
   git ls-tree -r --name-only NEW_TIP
   ```

   Replace `BASE` and `NEW_TIP` with verified full commit SHAs. Compare the
   complete tracked-file lists, not only `git diff` output, so newly added
   paths have a deliberate destination. Inspect local untracked files
   separately; never copy `.git/`, `.opencode/`, credentials, or generated
   build outputs by copying a live working directory wholesale. Inventory
   `openwiki/**` and `.openwikiignore` only to confirm they stay **excluded**;
   a later change to those files is not a source delta to re-import.
3. Apply the same path map as the table above. Export **tracked files from the
   reviewed revision** (for example, `git archive NEW_TIP` into a temporary
   directory), then copy reviewed additions and modifications and handle
   deletions deliberately. Do not re-import history, squash a second repo,
   reset a component tree, or blindly overwrite Boundary-owned files. If TA
   introduces new `.tekton/` definitions, HCP roots, root-level CI config,
   ownership files, or other special paths, decide explicitly whether they
   belong in `components/trusted-actions/`, root `.tekton/`, root
   `hcp-terraform/`, or a shared repo-root config. Reconcile new TA `.github/`
   configuration into the appropriate root config rather than restoring a
   nested `.github/`. Keep the component's `AGENTS.md` as the sole agent startup
   guide instead of restoring the original `CLAUDE.md`. Never import the old
   `openwiki/` directory or a TA `.openwikiignore`; root OpenWiki owns the
   combined wiki and has its own update workflow.
4. Reconcile the twelve transformed files above rather than reverting them:
   retain TA-only Prow ownership, correct Konflux source/context/path filters,
   keep the four formatting-only fixes, and retain the root Renovate and
   component AGENTS.md reconciliation. Compare and review HCP Terraform
   definitions and **tracked auto tfvars** without exposing secrets.
   Do not change the TA HCP workspace VCS binding, working directories,
   variable values, state-sharing permissions, or auto-apply merely to sync
   source. Remove obsolete files only after reviewing their replacement and
   any required CI or state ownership.
5. Validate each component independently: Go build/unit tests and any changed
   API-generation checks from `components/trusted-actions/`, relevant
   Terraform formatting/validation in its own roots, YAML/OWNERS checks,
   Boundary regression checks for changed shared paths, and root pre-commit.
   Check TA-only, Boundary-only, and mixed PR approvals; external Prow, Konflux,
   image release, dependency automation, Codecov/CodeQL, and the **single root
   OpenWiki** update and old periodic retirement must be reviewed. Keep a
   per-file mapping and source SHA in the refresh PR so remaining drift is
   observable.

## Cutover boundary

The imported TA HCP meta-root still points the **existing** TA global/stage
workspaces to `openshift-online/rosa-trusted-actions` at `terraform/global`
and `terraform/regional`. Their state, dynamic-credential role group, remote
state sharing, run triggers, and deployed image remain separate from Boundary.
The source refresh is not a workspace or AWS resource migration. Before a
VCS/working-directory rebind, verify live HCP settings and queued runs, gate
auto-apply, and review both the meta-workspace plan and the downstream AWS
plans with deployment owners. Never create a duplicate TA stack in Boundary's
regional state or assume a meta plan proves a no-op AWS apply. Keep the old
repo available for development until the new PR, push, release, and HCP paths
are proven and a final `main`-to-import comparison has no unreviewed changes.

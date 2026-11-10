# Trusted Actions monorepo migration inventory

This inventory was checked on 2026-11-06. It records the **files-only**
import of Trusted Actions into
`openshift-online/rosa-boundary` and how to refresh it while
`openshift-online/rosa-trusted-actions` remains the active development source.
The initial imported baseline is the TA `main` commit
`8ce39a7344b52444576fc1e44ab1f532fd0dfac4`. These counts and comparisons
describe **that revision**, not all changes subsequently made in the TA repo.
The latest reconciled TA `main` revision is
`483f325fef305507b1e2471aa4cdaf6858cf3018` (2026-11-10, including
[upstream PR #158](https://github.com/openshift-online/rosa-trusted-actions/pull/158));
see [the refresh record](#refresh-of-2026-11-10). Use that revision, rather than
the initial baseline, for the next incremental source comparison.
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
| `CLAUDE.md` | `components/trusted-actions/AGENTS.md` | 1 | **Initial import only:** replaced the old startup guide with component-specific contributor guidance. Upstream PR #158 subsequently renamed its own guide to `AGENTS.md`; later refreshes map `AGENTS.md` directly, without another transition. |
| `.github/renovate.json` | Root `renovate.json` | 1 | Reconcile TA rules into Boundary's existing repo-level config; remove the nested `.github/` directory. |
| `hcp-terraform/rosa-trusted-actions/{main.tf,variables.tf,terraform.auto.tfvars}` | `hcp-terraform/rosa-trusted-actions/` | 3 | Byte-for-byte copy of TA's HCP meta-workspace definition and tracked variables. Its original VCS repo and working directories are intentionally **not** switched by the import. |
| `.tekton/rosa-trusted-actions-{pull-request,push}.yaml` | Root `.tekton/` | 2 | Update the repo annotation to Boundary, the build context to `components/trusted-actions`, and PR/push change filters to the component and each pipeline file. Keep the TA image destination separate. **Post-import:** Boundary-side event triggers are guarded with `false &&` until cutover (see below). |
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

## Pre-cutover Konflux trigger hold

The initial import's Boundary-side TA Pipeline-as-Code definitions were **live**:
the TA push pipeline ran after the import merged, despite the Konflux component
source binding still pointing at the original TA repository. Both
`.tekton/rosa-trusted-actions-{pull-request,push}.yaml` now prefix their
`pipelinesascode.tekton.dev/on-cel-expression` with `false &&`. Once this
change merges, Boundary PR and main-push events should not start these TA
pipelines, publish into the existing TA Quay image repository, or produce TA
snapshots/releases via those event-triggered builds. The full PipelineRuns and
their original path filters remain in Git for cutover. This guard does **not**
cancel already queued/running builds or prevent manually submitted PipelineRuns
and other external triggers; verify those separately if needed. It does not
change the original TA repository's CI, Konflux source binding, release path,
or HCP deployment, nor Boundary's own image pipelines.

At the coordinated CI cutover, confirm the final TA source refresh and owners'
approval, review old-repo build/release activity and any pending runs, and
confirm the new repository/component binding and image/release destination.
Then remove `false &&` from **both** TA CEL expressions in a reviewed PR;
retain/validate their event, branch, and path filters. Exercise a Boundary TA
PR build and a main-push build, check image provenance and snapshot/release
behavior, and only then retire the original TA triggers. Do not re-enable
Boundary builds while the old-repo workflow still owns the shared destination
without a coordinated isolation plan.

## Refresh from the still-active TA repository

The old repo remains the source of truth **until** owners agree on cutover.
Do not refresh from an arbitrary local feature branch or assume that the
original baseline is still current. Work in a new or existing Boundary feature
branch/worktree; leave both source checkouts and local-only files intact.

1. Coordinate a candidate source revision with TA owners. Fetch the TA
   repository's upstream `main`, record its full SHA (`NEW_TIP`), and compare
   it to the last reconciled TA SHA (`BASE`, currently
   `483f325fef305507b1e2471aa4cdaf6858cf3018`). If `main`
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
   nested `.github/`. Upstream now has `AGENTS.md`: reconcile its guidance into
   the existing component-specific `AGENTS.md` rather than overwriting it;
   do not restore the deleted original `CLAUDE.md`. Never import the old
   `openwiki/` directory or a TA `.openwikiignore`; root OpenWiki owns the
   combined wiki and has its own update workflow.
4. Reconcile the historical twelve transformed files above rather than reverting them:
   retain TA-only Prow ownership, correct Konflux source/context/path filters
   **and the pre-cutover `false &&` hold**, keep the four formatting-only fixes,
   and retain the root Renovate and component AGENTS.md reconciliation. New
   upstream skills live under `.agents/skills/` with matching `.claude/skills/`
   symlinks; preserve those paths under the component.
   Compare and review HCP Terraform
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

## Refresh of 2026-11-10

Source: TA upstream `main` at
`4f1cb9ec953b1e8c050ed0d70bae897467ae4092`, compared with initial import
`8ce39a7344b52444576fc1e44ab1f532fd0dfac4`. The upstream comparison
has **14 changed paths** (9 modified, 5 added); it has no tracked deletions.
All 288 tracked paths (including excluded generated wiki files) were
inventoried. No original-repository history or local untracked files were
imported. The original TA repository remains the development and release
source until coordinated cutover.

| Upstream changes | Destination / treatment |
| --- | --- |
| `Containerfile`, `DEVELOPMENT.md`, `Makefile`, `README.md` | Refreshed under `components/trusted-actions/`; the runtime is digest-pinned and the imported Make targets invoke GoReleaser, but these targets are **not** validated monorepo build paths. The README clarifies that GitHub releases still come from the original repository. Fixed the upstream Makefile's mismatched `build-cli` phony declaration. |
| `.gitignore`, `.goreleaser.yaml`, `VERSION` | Kept under `components/trusted-actions/`. The existing component ignore already had `/dist/`, so the upstream duplicate `dist/` entry was dropped. The component-local GoReleaser config is **not at the repository root**; root-level GoReleaser will not discover it without a follow-up to select the config and adapt nested build paths. Neither this config nor `VERSION` publishes a release on its own. |
| `.tekton/rosa-trusted-actions-{pull-request,push}.yaml` | Refreshed the changed task-bundle digests in the root pipelines; retained Boundary source annotation, nested build context/path filters, and **both `false &&` pre-cutover guards**. No Boundary-side TA event build was enabled. |
| `.github/renovate.json` | Reconciled the Hummingbird runtime digest rule into root `renovate.json`, scoped to the component Containerfile, without importing the original boilerplate preset or automerge policy. |
| `CLAUDE.md` | Did not restore the original repo startup file. Updated `components/trusted-actions/AGENTS.md` with the new build/release guidance; the original repo's OpenWiki instructions do not belong in the component. |
| `.github/workflows/{actions.lock,tag-and-release.yml,verify-lockfile.yml}` | **Not installed** as Boundary root workflows. The original tag-and-release workflow is explicitly restricted to `openshift-online/rosa-trusted-actions`, assumes a root `VERSION`/Go module, and uses unscoped `v*` tags; the lockfile and verifier govern that old workflow set. Before enabling a Boundary release, review a TA-specific tag namespace, nested working directory and GoReleaser path, GitHub permissions, lockfile scope, and old-repo release handoff with owners. Do not copy a live tag-and-release workflow as a source sync. |
| `openwiki/**` | Still excluded; root Boundary OpenWiki remains the only generated wiki. No TA `.openwikiignore` was tracked. |

The TA HCP definitions, Terraform resource files, Go source/tests, and the
existing deployment image were unchanged by the upstream delta. This refresh
is **not** a CI, release, Konflux, or Terraform source cutover. Validate
TA-only PR checks and the root OpenWiki update separately before declaring
those integrations complete. Local `make test`, `go build ./...`, root
pre-commit on changed files, and JSON/YAML parsing passed; a GoReleaser
snapshot build, actual Konflux/Prow runs, and a container build were **not**
exercised. The next upstream delta, PR #158, is reconciled below; for later
refreshes use the newer baseline stated after that section.

**GoReleaser follow-up:** The imported `.goreleaser.yaml` stays under
`components/trusted-actions/`. It will not work as-is for a Boundary-root
release invocation, which expects to find its config at the invocation root;
the original release workflow also assumes root-level source and `VERSION`.
Adapt config discovery, nested build paths, and release workflow/namespace
in a separately reviewed change. Do not move the config or declare the
imported `make build*` targets proven as part of this source refresh.

### Follow-up: upstream PR #158

[PR #158](https://github.com/openshift-online/rosa-trusted-actions/pull/158)
merged into TA `main` as `483f325fef305507b1e2471aa4cdaf6858cf3018`.
Relative to `4f1cb9ec953b1e8c050ed0d70bae897467ae4092`, it renames
`CLAUDE.md` to `AGENTS.md`, moves the `add-trusted-action` skill and local
e2e reference from `.claude/skills/` to `.agents/skills/`, adds a relative
`.claude/skills/add-trusted-action` symlink, and updates the docs/agent links.
The upstream tracked tree now has 289 paths; no old-repo wiki or local-only
files were copied.

The new upstream `AGENTS.md` is **not** a `CLAUDE.md` conversion to perform at
the monorepo boundary: TA already uses the shared filename. Its standalone
repo guidance was reviewed and reconciled into the existing component-specific
`components/trusted-actions/AGENTS.md`, not copied over Boundary's monorepo
guidance. The new skill files and relative symlink map under
`components/trusted-actions/`; the old real `.claude/skills/` files were
removed. `DEVELOPMENT.md`, `README.md`, the add-action guide, and the docs
agent now point to the new paths. The hook README was already identical to
upstream. This does not switch TA's CI, release, or HCP sources.

For the **next** refresh, compare against
`483f325fef305507b1e2471aa4cdaf6858cf3018`; there is no longer a
`CLAUDE.md` → `AGENTS.md` rename to repeat.

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

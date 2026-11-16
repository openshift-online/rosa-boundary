# Dependency Management Automation

This repository uses **Mintmaker/Renovate** (Konflux-hosted) for automated dependency version updates. The strategy began in [ROSAENG-60067](https://redhat.atlassian.net/browse/ROSAENG-60067); the Go ownership overlap was corrected in [ROSAENG-75132](https://redhat.atlassian.net/browse/ROSAENG-75132).

GitHub Dependabot alerts are a separate repository security feature. Removing Dependabot's version-update configuration does not disable alerts or change repository security settings.

## Strategy

| Tool | Ecosystems | Config File |
|------|-----------|-------------|
| **Mintmaker (Renovate)** | `gomod`, `pep621` (Python Lambda), `terraform`, `pre-commit`, `github-actions`, `custom.regex` | `renovate.json` |

Mintmaker is the sole version updater for the root Go modules and the Python Lambda. Its `gomod dependencies` group includes `github.com/aws/aws-sdk-go-v2` and its submodules alongside other Go minor/patch updates in one PR; major updates remain separate. Mintmaker also groups GitHub Actions updates.

## Mintmaker (Renovate)

Mintmaker is a Konflux-hosted service built on [Renovate](https://docs.renovatebot.com/). The documented base schedule is four hours, with PRs signed by the `red-hat-konflux` GitHub app. Configuration lives in [`renovate.json`](../renovate.json). Actual cadence, deployed Renovate version, inherited release-age policy, and service-side enforcement need service evidence; local configuration alone does not prove them.

### Python dependency updates

Mintmaker's `pep621` manager is enabled for the create-investigation Lambda's
`pyproject.toml` and `uv.lock`. It groups non-major Python updates and leaves
major updates separate. Python updates are **not automerged**, despite the
repository-wide Renovate automerge setting.

Mintmaker's Python coverage was verified in [PR #411](https://github.com/openshift-online/rosa-boundary/pull/411): it updated both the manifest and lockfile, and the Lambda build, unit tests, and integration tests passed. Dependabot's Python version-update configuration has therefore been retired. This does not affect GitHub Dependabot alerts, which remain controlled by repository security settings.

### Coding agent native binaries

The image ships four coding agents — Claude Code, OpenCode, the OpenAI Codex
CLI and pi — as native upstream release archives. Each is pinned separately by
one annotated `*_VERSION` **ENV** in `Containerfile` and tracked by one
dedicated `custom.regex` manager. All four share a single review policy:
`automerge: false`, ungrouped, `ignoreUnstable: true`, and the inherited
release-age policy with publication timestamps required. This is separate from
the six-tool SRE contract below, which uses `ARG` pins and an inventory.

| Agent | Containerfile ENV | GitHub releases source | Release tag | Required integrity |
|-------|-------------------|------------------------|-------------|--------------------|
| Claude Code | `CLAUDE_CODE_VERSION` | `anthropics/claude-code` | `v<version>` | Exact archive entry in `SHASUMS256.txt` |
| OpenCode | `OPENCODE_VERSION` | `anomalyco/opencode` | `v<version>` | Exact archive entry in `SHA256SUMS` |
| Codex CLI | `CODEX_VERSION` | `openai/codex` | `rust-v<version>` | Exact archive entry in `codex-package_SHA256SUMS` |
| pi | `PI_VERSION` | `earendil-works/pi` | `v<version>` | Exact archive entry in `SHA256SUMS` |

Each builder stage downloads one architecture-specific asset through the same
authenticated, checksum-verifying `github_dl` helper the SRE tools use. The
three new stages name the asset exactly (`--exact_asset`); Claude Code still
uses the helper's older unique-substring selector (`--platform`). Read
`Containerfile` for the current pins; do not duplicate them here.

Three of the four need an `extractVersionTemplate`, because their repositories
publish releases that must never become a pin — a prefixed tag, a sibling
product, or a prerelease stream:

- `openai/codex` tags releases `rust-v<version>` and publishes frequent
  `rust-v*-alpha.N` prereleases, so the manager extracts
  `^rust-v(?<version>\d+\.\d+\.\d+)$`.
- `anomalyco/opencode` publishes unrelated `process-daemon-v*` releases from the
  same repository, so the manager extracts `^v(?<version>\d+\.\d+\.\d+)$`.
- `earendil-works/pi` uses the same `^v(?<version>\d+\.\d+\.\d+)$` extraction so
  that only its stable `v<semver>` releases can ever be proposed.

Only Claude Code, whose repository publishes a single stable `v<semver>` release
series, relies on `semver-coerced` alone.

OpenCode moved from `sst/opencode` to the `anomalyco` organization; the old
path redirects, but the manager tracks the current canonical repository. "pi"
here is the pi coding agent published as `earendil-works/pi` (npm
`@earendil-works/pi-coding-agent`), not another project of the same name.

Updating a pin requires an image rebuild and deployment; existing tasks do not
gain the new binary automatically. Verify actual hosted Mintmaker PRs and the
deployed `claude`, `opencode`, `codex` and `pi` versions separately.

**Known gap.** Claude Code's skeleton configuration disables its auto-updater
(`DISABLE_AUTOUPDATER` in `skel/sre/.claude/settings.json`). The three agents
added later have no equivalent setting yet, so an agent that self-updates into
the investigation's home directory can diverge from its Containerfile pin at
runtime. The build-time acceptance probe cannot detect that. Suppressing each
agent's self-update path belongs with the wider agent configuration work, not
with this installation change.

### Six-tool exact-pin contract (ROSAENG-67158)

The reduced migration scope is direct installation of **ocm, ocm-backplane,
osdctl, yq, oc, and AWS CLI v2**, without the backplane-tools installer or
ocm-addons.

#### One editable pin source

At implementation time, select the latest published stable releases of these six
tools and record the lookup date in the PR. Exclude drafts, prereleases, and
release candidates; AWS must remain CLI v2. “Latest” is the selection/update
policy, not dynamic discovery on every build.

Exact defaults belong only in annotated ARGs in the root
[Containerfile](../Containerfile), next to their consuming installation steps.
Read that file for values; do not duplicate pins in docs or a second editable
manifest. Builds must consume exactly those versions, never silently substitute
a release or use a self-refreshing installer.

| Tool | Containerfile ARG | Update source | Required integrity |
|------|-------------------|---------------|--------------------|
| ocm | `OCM_VERSION` | `github-releases`: `openshift-online/ocm-cli` | Exact binary's `.sha256` asset |
| ocm-backplane | `BACKPLANE_CLI_VERSION` | `github-releases`: `openshift/backplane-cli` | Exact archive entry in `checksums.txt` |
| osdctl | `OSDCTL_VERSION` | `github-releases`: `openshift/osdctl` | Exact archive entry in `sha256sum.txt` |
| yq | `YQ_VERSION` | `github-releases`: `mikefarah/yq` | Exact binary's SHA256 entry in `checksums-bsd`; do not execute upstream checksum scripts |
| oc | `OC_VERSION` | OpenShift stable release mirror; current rule uses `custom.openshift-stable` | Pinned Red Hat signer verifies the versioned `sha256sum.txt.gpg`, then verify archive SHA256 |
| AWS CLI v2 | `AWSCLI_VERSION` | `github-tags`: `aws/aws-cli`, v2 only | Pinned AWS signer verifies the versioned ZIP's detached signature before extraction |

Preserve existing integrity checks. A computed SHA256 is useful inventory data,
not a substitute for AWS signature verification; plain GitHub checksums are not
independent publisher signatures. Missing assets or integrity metadata, invalid
signatures/checksums, unexpected signers, and wrong executable versions must fail
closed, not trigger an unsigned or different-version fallback.

Keep reviewed public trust anchors and signer fingerprints in `build/keys/`;
see [key provenance](../build/keys/PROVENANCE.txt). Do not fetch replacement keys
alongside artifacts. Key changes require reviewed provenance and negative tests.
Download/verification dependencies stay in builder stages. Reuse authenticated
GitHub downloads and secret mounts; never execute downloaded tools while token
or private-key mounts are accessible.

Do not download or vendor license texts, introduce `build/licenses/`, or add
bespoke notice extraction. Preserve files needed by normal tool distributions,
including the AWS distribution layout.

#### Update PRs

Limit tool update rules to these six ARGs, with explicit `automerge: false` and
normal human review. No installer refresh rule, removed-tool rule, approval
bypass, or second editable pin source belongs in this change.

Validate the six rules and their lookups. The oc custom datasource supplies no
reliable publication timestamp. An approved exception sets
`minimumReleaseAgeBehaviour: "timestamp-optional"` **only** for `openshift/oc`,
using `custom.regex` and `custom.openshift-stable` in the root `Containerfile`.
This allows oc updates without a timestamp instead of keeping them pending
forever. It does not override the inherited release-age interval: if the
datasource supplies a timestamp later, that interval applies normally. The other
five tools retain `timestamp-required`; all six retain human review and
`automerge: false`.

Local tests exercise rule matching and the real Renovate age gate with an
inherited three-day delay, including negative scope checks. They do not establish
deployed Mintmaker behavior; confirm service compatibility and hosted update PRs.
If the updater cannot track a tool reliably, explain that narrow limitation
rather than adding updater infrastructure.

#### Evidence boundaries

See [focused acceptance](testing.md#sre-tool-pin-migration-acceptance). Earlier draft lookup,
test, and build results do **not** validate the reduced six-tool change. Recheck
latest stable selections and rerun affected checks against the revised source.

ARM enablement, base-image changes, pipeline platform requests, promotion
redesign, operational ownership projects, and deployments are outside this
tool-installation scope. Report architecture and hosted-service limitations
honestly; neither a local build nor these docs proves ARM support, deployed
Mintmaker behavior, staging, or production validation.

### Configuration Guide

Change `renovate.json` through a reviewed PR to the default branch. The service should consume it on a subsequent Mintmaker cycle; verify the actual run rather than assuming a four-hour delivery guarantee.

Full configuration reference: [Renovate configuration options](https://docs.renovatebot.com/configuration-options/)

Mintmaker-specific documentation: [Mintmaker user guide](https://konflux.pages.redhat.com/docs/users/mintmaker/user.html)

Key settings:

- **`enabledManagers`**: Restricts which package managers Mintmaker runs and avoids enabling unintended managers.
- **`packageRules`**: Groups related updates into single PRs. The `gomod dependencies` group batches all minor/patch Go updates (including AWS SDK modules) and pin/digest updates; major Go updates are not part of this group. The `github-actions` group batches all Actions version bumps.
- **`custom.regex`**: Enables narrowly scoped custom managers for dependencies that do not have a built-in file manager.


## FAQ

### How can I manually re-trigger a Renovate run?

Mintmaker documents a four-hour base schedule; actual timing and supported retrigger behavior require service confirmation. Closing and reopening a PR is not evidence that a new dependency lookup or validation ran. Inspect the subsequent service run and PR checks.

To request an immediate run, contact the Mintmaker team or use the Konflux UI to check component status.

See: [Mintmaker scheduling](https://konflux.pages.redhat.com/docs/users/mintmaker/user.html#scheduling)

### Can dependency PRs be configured to be automatically merged?

**Mintmaker/Renovate**: Yes. Add `"automerge": true` to a `packageRules` entry in `renovate.json`. Automerge requires CI to pass and the branch to be up-to-date with the base branch. Example for non-major updates:

```json
{
  "packageRules": [
    {
      "matchUpdateTypes": ["minor", "patch"],
      "automerge": true
    }
  ]
}
```

On GitHub, the `red-hat-konflux` app must be added to a bypass list in the repository's ruleset to skip approval requirements for automerged PRs. See the [Mintmaker automerge documentation](https://konflux.pages.redhat.com/docs/users/mintmaker/user.html#automerge) for details.

This generic example does **not** apply to the six SRE tools: their required policy is explicit `automerge: false` and normal human review. Do not add an approval bypass for this migration. Confirm the effective service and repository merge policy separately; configuration alone does not prove enforcement.

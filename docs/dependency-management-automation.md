# Dependency Management Automation

This repository uses **Mintmaker/Renovate** (Konflux-hosted) for automated dependency version updates. The strategy began in [ROSAENG-60067](https://redhat.atlassian.net/browse/ROSAENG-60067); the Go ownership overlap was corrected in [ROSAENG-75132](https://redhat.atlassian.net/browse/ROSAENG-75132).

GitHub Dependabot alerts are a separate repository security feature. Removing Dependabot's version-update configuration does not disable alerts or change repository security settings.

## Strategy

| Tool | Ecosystems | Config File |
|------|-----------|-------------|
| **Mintmaker (Renovate)** | `gomod`, `pep621` (Python Lambda), `terraform`, `pre-commit`, `github-actions`, custom regex GitHub releases | `renovate.json` |

Mintmaker is the sole version updater for the root Go modules and the Python Lambda. Its `gomod dependencies` group includes `github.com/aws/aws-sdk-go-v2` and its submodules alongside other Go minor/patch updates in one PR; major updates remain separate. Mintmaker also groups GitHub Actions updates.

## Mintmaker (Renovate)

Mintmaker is a Konflux-hosted service built on [Renovate](https://docs.renovatebot.com/). It runs on a 4-hour base schedule and opens PRs signed by the `red-hat-konflux` GitHub app. Configuration lives in `renovate.json` at the repository root.

### Python dependency updates

Mintmaker's `pep621` manager is enabled for the create-investigation Lambda's
`pyproject.toml` and `uv.lock`. It groups non-major Python updates and leaves
major updates separate. Python updates are **not automerged**, despite the
repository-wide Renovate automerge setting.

Mintmaker's Python coverage was verified in [PR #411](https://github.com/openshift-online/rosa-boundary/pull/411): it updated both the manifest and lockfile, and the Lambda build, unit tests, and integration tests passed. Dependabot's Python version-update configuration has therefore been retired. This does not affect GitHub Dependabot alerts, which remain controlled by repository security settings.

### Backplane-tools release pin

`Containerfile` pins the `openshift/backplane-tools` installer to an exact GitHub
release tag. Its custom regex manager uses the `github-releases` datasource, so
Mintmaker proposes only published releases with the archives and `checksums.txt`
needed by the image build. The rule matches only the annotated
`BACKPLANE_TOOLS_VERSION` ARG in the root `Containerfile`.

Mintmaker checks approximately every four hours and retains its inherited
three-day minimum release age. It opens a normal, signed update PR for a newer
eligible release; the dependency is not automerged and requires the usual human
review and image build checks. The installer release is pinned, while
`backplane-tools install all` still resolves the individual SRE tools during the
image build.

### Configuration Guide

Edit `renovate.json` on the default branch. Changes take effect on the next Mintmaker cycle (every 4 hours).

Full configuration reference: [Renovate configuration options](https://docs.renovatebot.com/configuration-options/)

Mintmaker-specific documentation: [Mintmaker user guide](https://konflux.pages.redhat.com/docs/users/mintmaker/user.html)

Key settings:

- **`enabledManagers`**: Restricts which package managers Mintmaker runs and avoids enabling unintended managers.
- **`packageRules`**: Groups related updates into single PRs. The `gomod dependencies` group batches all minor/patch Go updates (including AWS SDK modules) and pin/digest updates; major Go updates are not part of this group. The `github-actions` group batches all Actions version bumps.
- **`custom.regex`**: Enables narrowly scoped custom managers for dependencies that do not have a built-in file manager.


## FAQ

### How can I manually re-trigger a Renovate run?

Mintmaker runs on a fixed 4-hour schedule and cannot be triggered on-demand from outside Konflux. However, you can force Renovate to re-evaluate a specific PR by closing and reopening it -- Renovate will rebase and update the PR on its next cycle.

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

Automerge should be paired with good test coverage to avoid introducing regressions from unreviewed dependency changes.

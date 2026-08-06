# Dependency Management Automation

This repository uses two complementary tools for automated dependency updates: **Dependabot** (GitHub-native) and **Mintmaker/Renovate** (Konflux-hosted). The strategy was established in [ROSAENG-60067](https://redhat.atlassian.net/browse/ROSAENG-60067) to eliminate PR duplication while maintaining coverage across all dependency ecosystems.

## Strategy

Each tool owns a distinct set of package managers with minimal overlap:

| Tool | Ecosystems | Config File |
|------|-----------|-------------|
| **Mintmaker (Renovate)** | `gomod`, `terraform`, `pre-commit`, `github-actions` | `renovate.json` |
| **Dependabot** | `pip`, `gomod` (AWS SDK grouping) | `.github/dependabot.yml` |

Mintmaker handles the bulk of code dependency updates with broad grouping (all Go minor/patch updates in one PR, all GitHub Actions in one PR). Dependabot covers the Python Lambda dependencies and provides targeted grouping for `aws-sdk-go-v2` modules, which are the highest-volume source of individual Go dependency PRs.

## Dependabot

Dependabot is a GitHub-native feature that opens PRs for version updates on a configurable schedule. Configuration lives in `.github/dependabot.yml`.

### Current Configuration

```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/lambda/create-investigation"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 2
    groups:
      all-pip:
        patterns:
          - "*"

  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 3
    groups:
      aws-sdk:
        patterns:
          - "github.com/aws/aws-sdk-go-v2*"
```

Key settings:

- **`groups`**: Batches related dependency updates into a single PR instead of one per package. The `aws-sdk` group collapses 5-6 individual `aws-sdk-go-v2` sub-package PRs into one.
- **`open-pull-requests-limit`**: Caps the number of open Dependabot PRs per ecosystem. Keeps the PR queue manageable.
- **`schedule.interval`**: How often Dependabot checks for updates (`daily`, `weekly`, or `monthly`).

### Configuration Guide

Edit `.github/dependabot.yml` on the default branch. Changes take effect on the next scheduled run.

Full configuration reference: [Dependabot configuration options](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file)

## Mintmaker (Renovate)

Mintmaker is a Konflux-hosted service built on [Renovate](https://docs.renovatebot.com/). It runs on a 4-hour base schedule and opens PRs signed by the `red-hat-konflux` GitHub app. Configuration lives in `renovate.json` at the repository root.

### Current Configuration

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "enabledManagers": [
    "gomod",
    "terraform",
    "pre-commit",
    "github-actions"
  ],
  "packageRules": [
    {
      "description": "Group all Go module patch/minor updates into a single PR",
      "matchManagers": ["gomod"],
      "matchUpdateTypes": ["minor", "patch", "pin", "digest"],
      "groupName": "gomod dependencies"
    },
    {
      "description": "Group all GitHub Actions updates into a single PR",
      "matchManagers": ["github-actions"],
      "groupName": "github-actions"
    }
  ]
}
```

Key settings:

- **`enabledManagers`**: Restricts which package managers Mintmaker runs. Without this, Mintmaker enables all default managers, which can cause overlap with Dependabot.
- **`packageRules`**: Groups related updates into single PRs. The `gomod dependencies` group batches all minor/patch Go updates; the `github-actions` group batches all Actions version bumps.

### Configuration Guide

Edit `renovate.json` on the default branch. Changes take effect on the next Mintmaker cycle (every 4 hours).

Full configuration reference: [Renovate configuration options](https://docs.renovatebot.com/configuration-options/)

Mintmaker-specific documentation: [Mintmaker user guide](https://konflux.pages.redhat.com/docs/users/mintmaker/user.html)

## FAQ

### How can I reduce the number of PRs Dependabot opens?

Three options, in order of impact:

1. **Add `groups`** to batch related dependencies into single PRs. Use `patterns` to match package name prefixes (e.g., `"github.com/aws/aws-sdk-go-v2*"`). A catch-all `"*"` pattern groups everything in an ecosystem into one PR.

2. **Lower `open-pull-requests-limit`** to cap how many PRs Dependabot keeps open per ecosystem. Default is 5. Set it to 1-3 for low-volume ecosystems.

3. **Change `schedule.interval`** from `"weekly"` to `"monthly"` to check less frequently (trade-off: larger version jumps per PR).

See: [Dependabot grouping configuration](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#groups)

### How can I manually re-trigger a Dependabot run?

Dependabot does not have an API endpoint for triggering runs. Use the GitHub UI:

1. Go to the repository on GitHub
2. Navigate to **Settings** > **Code security** > **Dependabot**
3. Under "Dependabot version updates", click **Check for updates** next to the ecosystem you want to re-trigger

Each ecosystem (pip, gomod, etc.) must be triggered separately.

### How can I manually re-trigger a Renovate run?

Mintmaker runs on a fixed 4-hour schedule and cannot be triggered on-demand from outside Konflux. However, you can force Renovate to re-evaluate a specific PR by closing and reopening it -- Renovate will rebase and update the PR on its next cycle.

To request an immediate run, contact the Mintmaker team or use the Konflux UI to check component status.

See: [Mintmaker scheduling](https://konflux.pages.redhat.com/docs/users/mintmaker/user.html#scheduling)

### Can dependency PRs be configured to be automatically merged?

**Dependabot**: Yes. Enable GitHub's auto-merge feature on the repository, then add `auto-merge` rules or use GitHub Actions to automatically approve and merge Dependabot PRs that pass CI. GitHub does not have a native Dependabot automerge config option -- it relies on branch protection rules and the repository's auto-merge setting.

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

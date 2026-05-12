# Contributing to rosa-boundary

## Pre-commit Hooks

This project uses [prek](https://github.com/j178/prek) to manage pre-commit hooks. Currently configured hooks:

- **[leaktk](https://github.com/leaktk/leaktk)** — scans staged changes for secrets and credentials before each commit

### Install prek

Pick one method ([full options](https://github.com/j178/prek#installation)):

```bash
# Standalone installer (Linux/macOS)
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/j178/prek/releases/latest/download/prek-installer.sh | sh

# Homebrew
brew install prek
```

### Install leaktk

Pick one method ([full options](https://github.com/leaktk/leaktk/blob/main/docs/install.md)):

```bash
# From source (Go required)
CGO_ENABLED=0 go install github.com/leaktk/leaktk@latest

# Homebrew (macOS)
brew install leaktk/tap/leaktk
```

### Activate hooks

From the repository root:

```bash
prek install
```

This installs a git hook shim that runs the configured hooks on every `git commit`. The leaktk hook scans only staged changes, so it won't flag secrets in files you haven't modified.

### Running hooks manually

```bash
# Run all hooks on staged files
prek run

# Run all hooks on every file in the repo
prek run --all-files

# Run a specific hook
prek run leaktk
```

### Bypassing hooks

If you need to skip hooks for a specific commit (e.g., a documentation-only change):

```bash
git commit --no-verify -m "docs: update README"
```

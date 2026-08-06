---
name: docs-drift-review
description: Audits rosa-boundary documentation against actual code, Terraform, Containerfile, shell scripts, and CLI implementations. Produces a severity-tiered drift report (Critical, Important, Informational). Use when checking docs for accuracy, after major code changes, or when documentation staleness is suspected.
---

# Documentation Drift Review

Compare every factual claim in the project's documentation against the actual source code and configuration. Produce a structured report of findings.

The repository layout is documented in `AGENTS.md` (under "Repository Layout") and `README.md`. Use those as orientation, but verify them against the filesystem.

## Severity Tiers

### CRITICAL

Inaccuracies that cause real harm if trusted:
- Configuration paths, defaults, or variable names that differ from code
- CLI flags or subcommands documented but nonexistent (or required but undocumented)
- Terraform variable defaults that differ from `variables.tf`
- IAM permissions or security model descriptions that don't match Terraform/Lambda code
- API interfaces (headers, request/response formats) that don't match handler code
- References to files, scripts, or tools that don't exist in the repository

### IMPORTANT

Partially inaccurate or incomplete -- slows people down:
- CLI subcommands that exist in code but are missing from doc tables (or vice versa)
- Environment variables documented but not read by any code (or vice versa)
- Terraform resources or outputs that exist but aren't in doc tables
- Version numbers in docs that lag behind actual pinned versions
- Build/test instructions referencing Makefile targets that don't exist
- Inconsistent naming across docs (e.g., a realm or client ID called different names in different files)

### INFORMATIONAL

Features or components that lack documentation entirely:
- Undocumented directories, build stages, or modules
- Configuration options accepted by code but not mentioned anywhere
- Test suites or CI jobs that exist but aren't described in testing docs

## Review Phases

Discover what exists first, then cross-reference documentation against it. Use the Task tool to run phases concurrently.

### Phase 1: CLI

Read the Go code under `cmd/` and `internal/` to extract all subcommands, flags, defaults, config struct fields, config file paths, cache paths, and env var conventions. Cross-reference against every `.md` file that mentions CLI behavior -- particularly subcommand tables, flag references, config path references, and default values.

### Phase 2: Container & Shell

Read the `Containerfile`, `entrypoint.sh`, and the actual contents of `skel/` and `build/`. Cross-reference against every `.md` file that mentions build stages, tool versions, environment variables, entrypoint behavior, or skeleton file contents. Pay special attention to documented `skel/` or `bashrc.d/` files that may no longer exist.

### Phase 3: Terraform

Glob all `.tf` files under `deploy/` recursively. Extract variables (with defaults and required status), outputs, resources, and provider constraints. Cross-reference against every `.md` file that lists Terraform variables, outputs, resource descriptions, or deployment instructions. Check that Lambda resource configs (runtime, memory, timeout) in Terraform match values stated in docs.

### Phase 4: Lambda

List all subdirectories under `lambda/` -- each is a Lambda function. Read handler code to extract env vars, API interface, and auth logic. Cross-reference each Lambda's Terraform resource for runtime settings. Check Lambda-specific READMEs and architecture docs for accuracy. Watch for stale descriptions of older auth models that have been replaced.

### Phase 5: Build & Test

Read all Makefiles (root, `deploy/*/Makefile`, `lambda/*/Makefile`). Cross-reference against every `.md` file that references `make` targets, test commands, CI pipelines, or CI secrets. Verify CI secret paths are consistent across docs.

### Phase 6: Auth & Identity

Check `internal/auth/`, `deploy/keycloak/`, OIDC-related Terraform, Lambda OIDC validation, and Go config defaults for auth values. Cross-reference against every `.md` file that mentions Keycloak, OIDC, realm names, client IDs, group names, or token caching. Flag any inconsistency in naming across files.

### Phase 7: Repository Layout

List the actual directory tree and compare against documented layout trees in `AGENTS.md` and `README.md`. Verify that `docs/README.md` index links point to files that exist. Note directories on disk that aren't in documented trees.

## Output

Write the final report to a markdown file in the user's temporary directory (e.g., `/tmp/docs-drift-report-YYYY-MM-DD.md`). Use the current date in the filename. Print the full path to the file when complete.

See [resources/report_template.md](resources/report_template.md) for the report template.

## Rules

1. **Read the actual code.** Do not rely on one doc to verify another. Open source files and verify claims against them.
2. **Discover, don't assume.** Always glob or list directories first. The repository evolves -- new Lambdas, Terraform files, CLI commands, and docs can appear at any time.
3. **Quote specifically.** Every finding must cite `file:line` for both the documentation and the source of truth.
4. **Don't report style issues.** Typos, formatting, and wording are out of scope unless they change technical meaning.
5. **Don't report intentional abstractions.** Only flag simplifications that would lead to incorrect actions.
6. **Be exhaustive within scope.** A clean report with zero findings is valid. Do not manufacture findings.

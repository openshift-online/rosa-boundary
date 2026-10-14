# Workflows, CI/CD & Git Security

Combined reference for CI/CD pipeline security, git/GitHub workflow security, and critical workflow checks.

---

# CI/CD Pipeline Security

## GitHub Actions Security

### Workflow Permissions

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Overly broad permissions | `permissions: write-all` or no `permissions` key | HIGH | Set `permissions: read-all` at workflow level, grant write per-job |
| Unnecessary write scopes | `contents: write` when only reads needed | MEDIUM | Audit each job's needs, remove unused write scopes |
| Missing permissions block | No explicit `permissions` declaration | MEDIUM | Add explicit `permissions:` block, start with `read-all` |

### Action Pinning

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unpinned actions | `uses: actions/checkout@v4` (tag, not SHA) | MEDIUM | Pin to SHA. Use `pinact` to auto-pin, Dependabot/Renovate to update |
| Branch references | `uses: org/action@main` | HIGH | Pin to SHA — branch refs can be moved by anyone with write access |
| Latest tag | `uses: org/action@latest` | HIGH | Pin to specific SHA |

### Dangerous Triggers

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| `pull_request_target` | Runs with repo write access on PR code | CRITICAL | Use `pull_request` instead. If needed, never checkout PR code in same job |
| `pull_request_target` + checkout PR | Checking out PR head ref in `pull_request_target` | CRITICAL | Split: one `pull_request_target` (labels only), one `pull_request` (builds/tests) |
| `workflow_dispatch` without auth | Manual trigger without required approvals | MEDIUM | Use Environments with required reviewers |

### Secret Handling

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Secrets in run commands | `echo ${{ secrets.* }}` | CRITICAL | Never echo secrets. Use `::add-mask::` if needed |
| Secrets as env for all steps | Job-level `env` when only one step needs it | MEDIUM | Scope secrets to step-level `env:` |
| Secrets in outputs | `set-output` with secret values | CRITICAL | Never put secrets in outputs |
| Secrets in artifacts | Uploading files containing secrets | HIGH | Scrub secrets before upload |
| Missing environment protection | Secrets not scoped to Environments with approval | MEDIUM | Create Environments with required reviewers and deployment branch rules |

### Script Injection

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Direct context interpolation | `run: echo "${{ github.event.issue.title }}"` | HIGH | Pass through `env:` block, use `"$VAR"` in `run:` |
| PR title/body in commands | `${{ github.event.pull_request.title }}` in `run:` | HIGH | Assign to env var first |
| Comment body in commands | `${{ github.event.comment.body }}` in `run:` | CRITICAL | Fully attacker-controlled — always use env var, validate format |

Use `actionlint` in CI to detect expression injection.

### Self-Hosted Runner Risks

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Self-hosted on public repos | `runs-on: self-hosted` in public repo | CRITICAL | Use GitHub-hosted runners, or ephemeral runners (ARC) |
| Persistent self-hosted runners | No ephemeral configuration | HIGH | Use `--ephemeral` flag or Actions Runner Controller |

## General CI/CD Patterns

### Build Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Skip verification flags | `--no-verify`, `--skip-tests` in build scripts | HIGH | Fix underlying failures instead of skipping |
| Disabled security scans | Conditional skips of security steps | HIGH | Make security scans required, no `if: false` |
| Unvalidated external inputs | Build scripts using env vars without validation | MEDIUM | Validate all inputs, use `set -euo pipefail` |

### Credential Leakage

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Credentials in CLI args | `--password`, `--token` with values | HIGH | Use stdin or env vars |
| `set -x` with credentials | Debug tracing exposes secrets | HIGH | `set +x` before credential ops |
| Credentials in build cache | Docker layers containing secrets | HIGH | Use BuildKit secrets `--mount=type=secret`, multi-stage builds |

### Supply Chain Integrity

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| No integrity checks | Downloads without checksum verification | HIGH | Verify checksums, use lock files |
| HTTP downloads | `curl http://` (not HTTPS) | HIGH | Use HTTPS, verify TLS, add `--fail` |
| Missing SLSA provenance | No provenance attestation on releases | LOW | Use `slsa-framework/slsa-github-generator` |
| Unsigned containers | No image signing | MEDIUM | Sign with cosign, verify in admission controller |

## Tekton Pipeline Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Privileged tasks | `securityContext.privileged: true` | HIGH | Use Kaniko/Buildah instead of Docker socket |
| Unbounded resources | No resource limits on task steps | MEDIUM | Add memory/CPU limits |
| Inline scripts with secrets | Secret refs in inline scripts | HIGH | Use Tekton Secrets with volume mounts |
| Excessive ServiceAccount perms | Pipeline SA with broad cluster permissions | HIGH | Minimum ClusterRole/Role bindings |

## Jenkins Pipeline Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Plaintext credentials | `withCredentials` logging values | HIGH | Never echo credentials |
| Groovy sandbox bypass | `@NonCPS` or script approval bypasses | HIGH | Use declarative pipeline, minimize `@NonCPS` |
| Shared library trust | Libraries from untrusted sources | HIGH | Pin to specific versions/commits, use internal repos only |

---

# Git & GitHub Security

## Repository Setup & Access Control

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Public repo with sensitive code | Private/internal code exposed | CRITICAL | Change visibility, audit for leaked secrets, rotate credentials |
| No branch protection on main | Unprotected default branch | HIGH | Require PR reviews, status checks, signed commits |
| Admin bypass on branch protection | Bypass setting unchecked | HIGH | Enable for admins too |
| No CODEOWNERS enforcement | Missing or not required | MEDIUM | Create CODEOWNERS, require code owner reviews |

## Authentication & Credentials

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| No 2FA enforcement | Org without required 2FA | HIGH | Enable in org settings |
| Classic PAT without expiration | No expiry set | HIGH | Set max 90-day expiration, migrate to fine-grained PATs |
| Overly broad PAT scope | `repo`, `admin:org` when not needed | HIGH | Use fine-grained PATs scoped to specific repos/permissions |
| `credential.helper store` | Plaintext at `~/.git-credentials` | CRITICAL | Use `osxkeychain` (macOS), `libsecret` (Linux), `manager` (Windows) |
| `.git-credentials` committed | Credential file in repo | CRITICAL | Remove, add to `.gitignore`, rotate all credentials, purge history |

## Branch & Tag Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Force push to shared branch | `git push --force` to main/develop | CRITICAL | Use `--force-with-lease`, enable branch protection |
| Unsigned commits on protected branch | No GPG/SSH signature | MEDIUM | Require signed commits in branch protection |
| Unsigned release tags | Tags without GPG signature | MEDIUM | `git tag -s v1.0.0` |
| Deleted branch with unmerged work | `git branch -D` with unique commits | HIGH | Use `git branch -d` (safe delete) |

## Merge, Rebase & Conflict Resolution

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Rebase of shared/pushed history | `git rebase` on pushed commits | HIGH | Never rebase pushed commits, use merge for shared branches |
| `git reset --hard` without backup | Discarding uncommitted work | HIGH | `git stash` first, or create backup branch |
| Merge without running tests | Merging without CI verification | HIGH | Enable required status checks |
| Stash containing secrets | Sensitive data in stash entries | MEDIUM | Audit with `git stash show -p`, drop stashes with secrets |

## Push & Pull Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Pushing to main directly | No PR required | HIGH | Enable branch protection requiring PRs |
| Clone over HTTP | `git clone http://` | HIGH | Use HTTPS or SSH |
| Submodule from untrusted source | External repo in `.gitmodules` | HIGH | Audit sources, pin to commits, prefer vendoring |
| Shallow clone for security scanning | `--depth 1` before secret scan | MEDIUM | Full clone for scanning (shallow misses historical secrets) |

## Commit History Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Secret in commit history | Secret "removed" but still in history | CRITICAL | Rotate immediately, purge with `git filter-repo` or BFG |
| Author spoofing | Impersonating another committer | MEDIUM | Require signed commits |
| Commit message injection | Shell metacharacters parsed by CI | MEDIUM | Never interpolate commit messages in shell commands |

## GitHub Organization Hardening

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| 2FA not required | No enforcement | HIGH | Enable in org authentication settings |
| Base permissions too broad | Default is `Write` or `Admin` | HIGH | Set to `No permission` or `Read`, grant per-team |
| Single org owner | No redundancy | HIGH | At least 2 owners |
| Outside collaborators unreviewed | External access to private repos | MEDIUM | Quarterly audit, remove inactive |
| Audit log not monitored | No alerting on security events | MEDIUM | Monitor role changes, visibility changes, branch protection changes |

## Deploy Keys, Webhooks & GitHub Apps

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Deploy key with write access | Push permissions when not needed | HIGH | Recreate as read-only, unique per repo |
| Deploy key shared across repos | Same key in multiple repos | HIGH | Generate unique key per repo |
| Webhook without secret | No `X-Hub-Signature-256` verification | HIGH | Set secret, verify signature on every delivery |
| Webhook over HTTP | Unencrypted payload URL | HIGH | Use HTTPS |
| GitHub App with excessive permissions | Unnecessary `Administration` or `Contents: Write` | MEDIUM | Grant minimum required |

## Git Configuration Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| `credential.helper store` | Plaintext credentials | CRITICAL | Switch to secure helper |
| `http.sslVerify false` | TLS disabled | CRITICAL | Remove setting, fix certificate issue |
| Pre-commit hooks disabled | No `.pre-commit-config.yaml` | MEDIUM | Install hooks for secret scanning and linting |
| Git aliases hiding dangerous commands | Alias for `push --force` | MEDIUM | Audit aliases, use safe alternatives (`--force-with-lease`) |

---

# Critical Workflows

## Release & Deployment Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Debug build submitted | `debuggable=true` or missing release signing | CRITICAL | Verify release config: `isDebuggable=false`, `isMinifyEnabled=true` |
| Test/staging URLs in production | Hardcoded staging endpoints | CRITICAL | Use build-time env injection, verify base URL before submission |
| Test credentials in release | Demo accounts, sandbox tokens shipped | HIGH | CI grep for test/sandbox patterns before upload |
| Unsigned or ad-hoc signing | Missing distribution certificate | CRITICAL | Use proper distribution profile, enroll in Play App Signing |
| Missing ProGuard/R8 | `minifyEnabled=false` in release | HIGH | Enable minification and shrink resources |
| Upload key in repo | `*.keystore`/`*.jks` committed | CRITICAL | Remove, add to `.gitignore`, use CI secret storage |
| Signing config hardcoded | `storePassword` in build.gradle | CRITICAL | Use env vars via `System.getenv()` |
| 100% rollout without monitoring | No staged percentage | HIGH | Start 1-5% → 25% → 50% → 100% with monitoring |

## Merge Conflict Security

When conflicts occur in security-critical files, apply extra scrutiny:

| File/Area | Risk | What to Watch |
|-----------|------|--------------|
| Auth middleware / route guards | CRITICAL | Auth checks not dropped, duplicated, or reordered |
| Input validation / sanitization | HIGH | Validation rules not lost |
| `.gitignore` | HIGH | Secret file patterns not removed |
| Lock files | HIGH | Never manually edit — delete and regenerate |
| Security headers (CSP, CORS) | HIGH | Merged policies may be overly permissive |
| Permission/RBAC definitions | HIGH | Merged roles may grant unintended permissions |

Common mistakes: accepting "both" on auth middleware (CRITICAL), accepting "theirs" losing validation (HIGH), combining CORS/CSP by union (HIGH), keeping shorter `.gitignore` (HIGH).

## Hotfix & Emergency Deployment

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| CI checks bypassed | `--no-verify`, `[skip ci]` | CRITICAL | Never skip CI for production — fix the pipeline instead |
| Code review skipped | Direct push without PR | HIGH | Require at least 1 reviewer even for hotfixes |
| Temporary hardcoded credentials | Inline creds "to be changed later" | CRITICAL | Use existing secret manager — "temporary" becomes permanent |
| Hotfix not merged back | Fix on production but not main/develop | HIGH | Always merge back to all active branches |

## Rollback Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Destructive migration without rollback | `DROP TABLE`/`DROP COLUMN` with no down migration | CRITICAL | Write reversible migration, use expand-contract for destructive ops |
| Data loss on rollback | Irreversible data deletion | HIGH | Backup table before destructive migration, test rollback in staging |
| Session/token incompatibility | Old sessions invalid in new version | HIGH | Backward-compatible session format, support N-1 during rollout |
| API contract break between versions | Breaking changes during rollout | HIGH | API versioning, old and new must coexist |

## Feature Flag Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Auth behind feature flag | Security gated by flag | CRITICAL | Security checks must be unconditional — never behind flags |
| Client-side flag for security decisions | Security logic from client-provided flag value | HIGH | Evaluate security flags server-side only |
| Stale flag gating security | Flag >90 days old on security behavior | HIGH | Remove flag, make code unconditional |
| Flag default is insecure | Permissive when evaluation fails | HIGH | Fail closed, not open |

## Pre-Release Security Gate

| Check | Tool/Method | Severity if Skipped |
|-------|------------|-------------------|
| Secret scan | `detect-secrets`, `gitleaks`, `truffleHog` | CRITICAL |
| Dependency audit | `npm audit`, `pip-audit`, `govulncheck`, `trivy fs` | HIGH |
| SAST scan | `semgrep`, `gosec`, `bandit`, `eslint-plugin-security` | HIGH |
| Container image scan | `trivy image`, `grype` | HIGH |
| License compliance | `license-checker`, `pip-licenses` | MEDIUM |
| SBOM generation | `syft`, `cyclonedx-cli` | MEDIUM |
| Database migration test | Run + rollback on staging copy | HIGH |

### Release Artifact Signing

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unsigned release artifacts | No signature on binaries/containers | HIGH | Sign with cosign/GPG/Sigstore, verify in deployment |
| Missing provenance | No SLSA provenance | MEDIUM | Use `slsa-github-generator` |
| Signing key in repo | Key committed to VCS | CRITICAL | Remove, rotate, store in CI vault or HSM |

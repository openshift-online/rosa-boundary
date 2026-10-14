# Remediation Playbooks

Condensed remediation guidance for every finding category. For each finding, apply the 4-step pattern: **Fix** (code change) → **Verify** (confirm fix) → **Prevent** (automation) → **Harden** (defense-in-depth).

---

## Secrets & Credentials

| Finding | Fix | Verify | Prevent | Harden |
|---------|-----|--------|---------|--------|
| Hardcoded secret | Move to env var or secret manager | `git grep` for pattern; confirm app works with env var | `detect-secrets`, `git-secrets`, GitHub secret scanning | Rotate credential, purge from git history with `git filter-repo` |
| Secret in git history | `bfg --replace-text` or `git filter-repo --invert-paths` | `git log --all -p \| grep` should find 0 matches | Same as above | Rotate credential, audit access logs, team re-clones repo |

## Injection Vulnerabilities

| Finding | Fix | Verify | Prevent | Harden |
|---------|-----|--------|---------|--------|
| SQL injection | Replace string interpolation with parameterized queries | Test with injection payload — should return error, not data | `bandit -t B608` (Python), `gosec -include=G201,G202` (Go), `eslint-plugin-security` (JS) | Use ORM as default, enable query logging in staging, least-privilege DB user |
| XSS | Use `textContent` instead of `innerHTML`; sanitize with DOMPurify if HTML required | Test with `<script>alert(1)</script>` — should see escaped output | CSP header, `eslint-plugin-no-unsanitized` | CSP with nonce-based scripts, `X-Content-Type-Options: nosniff` |
| Command injection | Use subprocess with array args (not shell=True) | Test with `; rm -rf /` in input — should fail safely | `bandit -t B602-B607` (Python), `gosec -include=G204` (Go) | Input allowlists, sandbox execution, AppArmor/SELinux profiles |

## Authentication & Authorization

| Finding | Fix | Verify | Prevent | Harden |
|---------|-----|--------|---------|--------|
| Missing authentication | Add global auth middleware, explicitly skip for public routes | Unauthenticated request returns 401 | Integration tests verify all endpoints require auth | Rate limiting, request logging with user identity |
| IDOR / broken object-level auth | Add ownership check — filter by `user_id` alongside resource ID | Cross-user access returns 404, not the resource | Authorization tests with multi-user scenarios | UUIDs instead of sequential IDs, rate limit to prevent enumeration |

## Performance & DoS

| Finding | Fix | Verify | Prevent | Harden |
|---------|-----|--------|---------|--------|
| Missing rate limiting | Add rate limit middleware (tiered: strict on auth, lighter on reads) | Rapid requests return 429 after limit | Rate limiting in API gateway as first line of defense | Distributed rate limiting (Redis-backed), bot detection, DDoS protection |
| Unbounded query results | Add pagination with capped `per_page` (e.g., max 100) | Request without limit returns paginated results; excessive limit is capped | Lint rule flagging `SELECT` without `LIMIT` | Cursor-based pagination, DB statement timeout |

## Infrastructure & Configuration

| Finding | Fix | Verify | Prevent | Harden |
|---------|-----|--------|---------|--------|
| Overly permissive IAM | Replace `Action: *` / `Resource: *` with specific actions and ARNs | IAM Policy Simulator shows `implicitDeny` for unneeded actions | `trivy config`, `checkov -d .` in CI | CloudTrail, IAM Access Analyzer, permission boundaries |
| Container running as root | Add `USER` instruction, use multi-stage build, add `HEALTHCHECK` | `docker run --rm image whoami` prints non-root user | K8s Pod Security Standards (`enforce: restricted`) | Distroless/scratch base images, read-only root filesystem, drop all capabilities |

## CI/CD Pipeline

| Finding | Fix | Verify | Prevent | Harden |
|---------|-----|--------|---------|--------|
| Script injection (GH Actions) | Pass context through `env:` block, not inline `${{ }}` in `run:` | Test PR with title containing shell metacharacters — logs show literal string | `actionlint` in CI | Explicit `permissions: read-all`, pin actions to SHA, use environments with reviewers |
| Unpinned GitHub Actions | Pin to full SHA with version comment: `uses: action@SHA # vN.N` | `grep "uses:" \| grep -v "@[a-f0-9]\{40\}"` returns empty | `pinact` for auto-pinning, Renovate/Dependabot for updates | Review action source before pinning, org-level action allow lists |

## Data Protection

| Finding | Fix | Verify | Prevent | Harden |
|---------|-----|--------|---------|--------|
| PII in logs | Add structured logging with redaction processor for sensitive fields | `grep` logs for PII patterns — should find only `REDACTED` | Log sanitization middleware, CI scan for PII in log statements | Data classification, log access controls, retention policies, encryption at rest |
| CSV/Excel injection | Prefix cells starting with `=+\-@\t\r` with `'` | Export payload `=HYPERLINK(...)` — opens as text, not link | Sanitization in export utility, unit tests with injection payloads | `Content-Disposition: attachment`, consider PDF for sensitive exports |

## Critical Workflows

| Finding | Fix | Verify | Prevent | Harden |
|---------|-----|--------|---------|--------|
| Debug build shipped | Halt rollout, rebuild with release config | `aapt dump badging` shows no `debuggable` flag; release signing verified | CI pre-upload validation script | Separate debug/release configs, app attestation (Play Integrity / App Attest) |
| Merge conflict dropped security check | Restore lost validation/auth code by comparing against both parents | Auth/security tests pass; all protected routes have auth middleware | CODEOWNERS for security files, post-merge security test suite | Global auth middleware (harder to accidentally remove) |
| Hotfix bypassed CI | Run CI retroactively on deployed commit | Secret scan + dependency audit + tests pass on hotfix commit | Branch protection — no bypass for admins, block `[skip ci]` | Fast-path CI for hotfixes (<5 min), post-deploy retroactive CI requirement |
| Stale feature flag gating security | Remove flag wrapper, make security code unconditional | Auth works without flag; no references to removed flag remain | Lint rule detecting flags wrapping auth code, quarterly flag audit | Policy: security checks never behind feature flags |
| Missing rollback migration | Write DOWN migration, test round-trip in staging | Migrate up → down → up succeeds with data integrity | CI check ensuring every migration has a rollback | Expand-contract pattern for destructive ops, backup pre-migration state |

## Git & GitHub

| Finding | Fix | Verify | Prevent | Harden |
|---------|-----|--------|---------|--------|
| Force push overwrote shared history | Recover from reflog: `git push origin origin/main@{1}:main --force-with-lease` | All expected commits present; team members pull restored branch | Branch protection: `allow_force_pushes=false` | Admin bypass disabled, pre-push hook warning, audit log monitoring |
| Unsigned commits merged | If recent/unshared: amend with `-S`; if shared: enforce going forward | `git log --show-signature` shows valid signatures | Branch protection: `required_signatures=true`; global `commit.gpgsign=true` | Signed commit CI check, SSH signing (simpler than GPG) |
| Deploy key with write access | Delete key, audit access logs, recreate as read-only | `gh api repos/.../keys` confirms `read_only=true`; push attempt fails | Quarterly deploy key audit, document read-only-default policy | Rotate every 90 days, unique per repo, use GitHub Apps when possible |

---

## Quick Reference: Fix by Category

| Category | Fastest Fix | Prevention Tool |
|----------|------------|-----------------|
| SQL Injection | Parameterized queries | `bandit`, `gosec`, `eslint-plugin-security` |
| XSS | `textContent` instead of `innerHTML` | CSP header, `eslint-plugin-no-unsanitized` |
| Hardcoded Secrets | Move to env vars | `detect-secrets`, `git-secrets`, GitHub secret scanning |
| Missing Auth | Global auth middleware | Integration tests, route authorization tests |
| IDOR | Add ownership check | Authorization tests with multi-user scenarios |
| Missing Rate Limiting | `express-rate-limit` / `slowapi` | Load testing in CI |
| Unpinned Dependencies | Pin exact versions | `Renovate`, `Dependabot`, lock files |
| Container as Root | Add `USER` instruction | `trivy`, K8s Pod Security Standards |
| Script Injection (CI) | Use `env:` not `${{ }}` in `run:` | `actionlint` |
| Overly Permissive IAM | Replace `*` with specific actions | `tfsec`, `checkov`, IAM Access Analyzer |
| CSV Injection | Prefix cells with `'` | Sanitization in export utility |
| Debug Build Shipped | Rebuild with release config | CI pre-upload validation |
| Merge Conflict Dropped Auth | Restore lost check | CODEOWNERS, post-merge security tests |
| Hotfix Bypassed CI | Run CI retroactively | Branch protection (no bypass) |
| Force Push to Shared Branch | Recover from reflog | Branch protection (no force push) |
| Deploy Key Write Access | Recreate as read-only | Quarterly audit, use GitHub Apps |

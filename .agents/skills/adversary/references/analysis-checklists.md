# Analysis Checklists

Combined reference for groundwork phases, code analysis, documentation analysis, and verification procedures.

---

# Groundwork Procedures

## Phase 0: Discovery

### Step 0.1: Run Discovery Scripts

```bash
bash scripts/detect-stack.sh $PROJECT_ROOT
bash scripts/repo-stats.sh $PROJECT_ROOT
bash scripts/find-images.sh $PROJECT_ROOT
```

Parse output to populate: technology stack, repository health metrics, documentation assets inventory.

### Step 0.2: Determine Reading Scope

Using detected tech stack and [reading-strategy-and-patterns.md](reading-strategy-and-patterns.md):
1. Build file reading queue by priority: entry points → config → routes → models → middleware → business logic → infra → tests → docs
2. Apply skip rules: generated, vendored, binary, lock files
3. Apply framework-specific patterns from [reading-strategy-and-patterns.md](reading-strategy-and-patterns.md)
4. Cap at 200 files for deep reading; summarize remaining by directory

### Step 0.3: Read All In-Scope Files

For each file, note: component membership, dependencies/imports, entry points/exports, security-relevant patterns (auth, validation, crypto, error handling).

## Phase 0.5: Structured Analysis

Perform analysis across four dimensions using checklists below, then run the verification gate.

---

# Code Analysis Checklist

## Agent A: Architecture Analysis

| # | Item | What to Identify | Evidence Sources |
|---|------|-----------------|-----------------|
| A1 | Component boundaries | Modules, responsibilities, public APIs | Directory structure, exports |
| A2 | Layer identification | Presentation, business, data access, infra | Import direction patterns |
| A3 | Entry points | All external input paths | `main.*`, routes, CLI parsers, cron |
| A4 | Execution flows | Request lifecycle end-to-end | Route → middleware → handler → service → repo |
| A5 | Trust boundaries | Where data crosses privilege levels | Public→auth, user input→DB, external→internal |
| A6 | Shared state | Globals, singletons, caches, sessions | Module-level vars, cache init |
| A7 | Error propagation | Error flow across boundaries | Try/catch patterns, error middleware |
| A8 | Dependency graph | Inter-module dependencies | Import statements, DI |
| A9 | External boundaries | External services, APIs, databases | HTTP clients, SDK inits, connection pools |
| A10 | Configuration flow | How config enters and propagates | Env vars, config files, feature flags |

**Security feed:** Trust boundaries (A5) → Phase 4 adversarial testing. Entry points (A3) → Phase 1 scope. Shared state (A6) → race conditions, cache poisoning. External boundaries (A9) → SSRF, exfiltration paths.

## Agent B: Code Patterns

| # | Item | What to Identify | Evidence Sources |
|---|------|-----------------|-----------------|
| B1 | Naming conventions | Variable/function/class/file patterns | Statistical sampling |
| B2 | Error handling | Try/catch patterns, error types, recovery | Error code blocks |
| B3 | Logging practices | Levels, structured vs unstructured, what's logged | Log statements |
| B4 | Input validation | Schema, manual, or framework validation | Request handlers |
| B5 | Testing patterns | Framework, coverage approach, mocks | Test files |
| B6 | Configuration management | Loading, validation, access | Config modules |
| B7 | Concurrency patterns | Threading, async/await, locks | Sync primitives |
| B8 | Resource management | Connection handling, cleanup | Open/close pairs, defer/finally |

**Security feed:** Error handling deviations (B2) → info disclosure. Logging sensitive data (B3) → credential exposure. Missing validation (B4) → injection vectors. Concurrency issues (B7) → TOCTOU, race conditions.

## Agent C: API + Data Analysis

| # | Item | What to Identify | Evidence Sources |
|---|------|-----------------|-----------------|
| C1 | API endpoints | Method, path, auth, rate limiting | Route defs, OpenAPI specs |
| C2 | Request/response schemas | Validation rules, response shapes | DTOs, serializers |
| C3 | Data models | Entities, relationships, constraints | ORM models, SQL schemas |
| C4 | Sensitive data fields | PII, credentials, financial data | Field names, type annotations |
| C5 | External integrations | Third-party APIs, webhooks, queues | HTTP clients, SDK usage |
| C6 | Data flow mapping | Sensitive data paths (input→storage) | Handler → service → repo chain |
| C7 | Pagination & limits | How large result sets are handled | Query builders |
| C8 | File handling | Upload/download, storage, size limits | Multipart handlers |
| C9 | Caching strategy | What's cached, TTL, invalidation | Cache middleware |
| C10 | Database queries | Raw vs parameterized, ORM usage | Query construction |

**Security feed:** Unauthed endpoints (C1) → missing auth. Sensitive paths (C6) → exfiltration mapping. Raw queries (C10) → injection. Missing pagination (C7) → DoS.

## Agent D: DevOps + Git Analysis

| # | Item | What to Identify | Evidence Sources |
|---|------|-----------------|-----------------|
| D1 | CI/CD pipeline stages | Build, test, lint, security, deploy | Workflow files |
| D2 | Security gates | SAST, DAST, dependency, secret scan | CI config |
| D3 | Container configuration | Base images, runtime user, ports | Dockerfiles |
| D4 | Infrastructure as code | What infra is code-managed | Terraform, Helm, K8s |
| D5 | Environment management | Dev/staging/prod differences | Env configs |
| D6 | Secret management | Storage and injection method | CI secrets, vault configs |
| D7 | Deployment strategy | Blue/green, canary, rolling | Deploy configs |
| D8 | Git workflow | Branch strategy, review requirements | Protection rules, CODEOWNERS |
| D9 | Monitoring | Logging, metrics, tracing, alerting | APM configs |
| D10 | Rollback capability | How rollbacks work, state compat | Migration files, deploy scripts |

**Security feed:** Missing gates (D2) → no SAST/secret scan. Root containers (D3) → privilege escalation. No rollback (D10) → can't revert security patches.

---

# Documentation Analysis

## Documentation Discovery

Check these locations for docs:
- **Primary:** `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`
- **Extended:** `docs/`, `ARCHITECTURE.md`, `adr/`, `openapi.yaml`, `runbooks/`
- **Inline:** Docstrings, JSDoc, code comments, type annotations

Flag but do not access: Confluence, Notion, Google Docs, Jira (require authentication).

## Quality Assessment

Score each source 0-3 on: Accuracy, Completeness, Currency, Accessibility, Security relevance.

## Security Documentation Audit

Missing items generate findings in the security report:

| Document | Finding Severity if Missing |
|----------|---------------------------|
| Auth flow documentation | MEDIUM |
| Authorization model (RBAC/ABAC) | MEDIUM |
| API security per-endpoint | MEDIUM |
| Incident response procedures | LOW |
| Secrets management docs | LOW |
| Data classification policy | LOW |

## Staleness Detection

Compare doc and code modification timestamps via `git log -1 --format="%ai"`:
- 3-6 months gap: Warning (LOW)
- 6+ months gap: Stale (MEDIUM)
- Doc references removed code: Broken (MEDIUM)

## Correlation Matrix

Map each doc section to code modules bidirectionally. Identify: undocumented code, code-less documentation, security documentation gaps, stale references.

## Cross-Project Analysis (Multiple Projects Only)

Detect overlap via: similar API endpoints, shared module names, same data models, shared deps at different versions. Classify as: shared dependency, duplicate implementation, complementary, potential conflict.

---

# Verification Checklist

Mandatory quality gate — no claim appears in the final report without verification.

## Principles

1. Every claim cites a specific file path (and line number where applicable)
2. Unverifiable claims marked `UNVERIFIED`
3. Statistics must be reproducible
4. Architecture claims traceable through import chains

## Claim Categories

| Category | Verification Method | Pass Criteria | Fail Action |
|----------|-------------------|---------------|-------------|
| File existence | `find . -name "file" -path "*/dir/*"` | File exists at stated path | Correct path or remove |
| Code pattern | `grep -rn "symbol" src/` | Symbol/pattern exists as described | Correct or remove |
| API endpoint | `grep -rn "router\.(get\|post)" src/routes/` | Route exists with stated method/path | Correct or remove |
| Dependency | `grep "package" manifest` | Dependency exists with stated version | Correct or remove |
| Statistic | Re-run counting command | Within 5% of claimed value | Update to verified value |
| Architecture | Verify import chains with grep | Imports exist as described | Correct description |
| Documentation | `find` + read file content | Doc exists with described content | Correct or mark stale |

## Red Flags

- Referenced file doesn't exist → search by name, correct or remove
- Statistics differ by >20% → re-run with correct parameters
- Function/class not found → possible hallucination, search similar names
- Doc references removed code → flag as stale documentation

## Verification Workflow

1. Collect all claims from analysis outputs
2. Categorize each claim
3. Run verification using specified method
4. Classify: PASS, CORRECTED (auto-fix minor), UNVERIFIED, FAIL (disproven)
5. Update corrected claims, remove failed claims
6. Generate verification summary

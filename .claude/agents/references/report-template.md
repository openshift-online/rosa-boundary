# Security Report Template

Use this template to structure the final output of an adversary scan.

## Standard Report Template

```markdown
## Security Review

**Scan Date:** {TIMESTAMP}
**Scan Mode:** {Pending Changes Review | Full Project Audit | Targeted Scan}
**Project Type:** {Web App | API Service | Mobile App | Microservice | CLI Tool | Library | IaC | Mixed}
**Tech Stack:** {detected languages, frameworks, and tools}
**Files Reviewed:** {TOTAL_COUNT} ({CRITICAL_COUNT} critical, {HIGH_COUNT} high risk)
**Domains Analyzed:** {DOMAINS_LIST}

### Summary

| Severity | Count |
|----------|-------|
| CRITICAL | {N} |
| HIGH | {N} |
| MEDIUM | {N} |
| LOW | {N} |

{If no findings: **No security issues identified in the reviewed changes.**}

### Findings

{For each finding, in severity order:}

**[SEVERITY] {TITLE}**

- **File:** `{FILE_PATH}:{LINE_NUMBER}`
- **Category:** `{DOMAIN} - {SUBCATEGORY}`
- **Issue:** {CLEAR_DESCRIPTION}
- **Impact:** {WHAT_AN_ATTACKER_COULD_ACHIEVE}
- **Affected Roles:** {Web Dev | App Dev | API Dev | DevOps | DBA | Mobile Dev | All}

**Remediation:**

**Step 1 — Immediate Fix:** {code change with before/after}
**Step 2 — Verify:** {verification command + expected result}
**Step 3 — Prevent Recurrence:** {linting rule, CI check, or architectural change}
**Step 4 — Harden Further:** {additional defense-in-depth measures}

---

### Domains Not Analyzed

- {DOMAIN}: {REASON}

### Security Posture

**Overall Risk:** {CRITICAL | HIGH | MEDIUM | LOW | CLEAN}
**Top Priority:** {the single most important thing to fix}
**Quick Wins:** {1-3 low-effort fixes with high impact}
**Architecture Notes:** {any systemic patterns that need addressing}
```

## Severity Levels

| Severity | Definition | SLA |
|----------|-----------|-----|
| **CRITICAL** | Exploitable with immediate risk — credential exposure, auth bypass, injection with user input | Fix within 24h |
| **HIGH** | Likely exploitable — missing auth, command injection vector, overly permissive IAM | Fix within 7d |
| **MEDIUM** | Defense-in-depth gap — unpinned images, missing encryption, broad network rules | Fix within 30d |
| **LOW** | Minor hardening — verbose errors, missing headers, non-optimal permissions | Fix within 90d |

## Category Taxonomy

### Infrastructure
`Infrastructure - IAM Misconfiguration` | `- Network Exposure` | `- Encryption Gap` | `- Secrets in Plaintext` | `- Unpinned Image Tag` | `- Container Security` | `- Storage Security`

### Application
`Application - Injection Vulnerability` | `- Credential Handling` | `- Input Validation` | `- Unpinned Dependency Version` | `- Error Handling` | `- Unsafe Deserialization` | `- Cryptographic Weakness`

### Web Application
`Web - Cross-Site Scripting (XSS)` | `- CSRF` | `- Missing Security Headers` | `- Insecure Cookie Configuration` | `- CORS Misconfiguration` | `- Client-Side Storage Exposure` | `- Missing Subresource Integrity` | `- Broken Access Control`

### API
`API - Missing Authentication` | `- Broken Object-Level Authorization (BOLA)` | `- Missing Rate Limiting` | `- Input Validation Gap` | `- Excessive Data Exposure` | `- Missing Pagination` | `- File Upload Vulnerability` | `- GraphQL Security` | `- WebSocket Security`

### Auth & Authorization
`Auth - Weak Password Hashing` | `- Session Management Flaw` | `- JWT Vulnerability` | `- OAuth/OIDC Misconfiguration` | `- Missing MFA` | `- RBAC Violation` | `- Account Enumeration` | `- API Key Exposure`

### Database
`Database - SQL Injection` | `- NoSQL Injection` | `- Excessive Privileges` | `- Missing Encryption` | `- Unsafe Migration` | `- Connection Security` | `- Missing Row-Level Security`

### Performance & Scaling
`Performance - Missing Rate Limiting` | `- Unbounded Query Results` | `- Resource Exhaustion Risk` | `- Missing Timeouts` | `- Cache Security` | `- CDN Misconfiguration` | `- Load Balancer Security` | `- Connection Pool Risk` | `- CSV/Excel Injection`

### CI/CD
`CI/CD - Pipeline Integrity` | `- Credential Leakage` | `- Supply Chain Integrity` | `- Workflow Permissions` | `- Script Injection` | `- Action Pinning` | `- Self-Hosted Runner Risk`

### Supply Chain
`Supply Chain - Suspiciously New Version` | `- Bulk Dependency Change` | `- Low Scorecard Rating` | `- Unmaintained Dependency` | `- Dangerous Upstream Workflow` | `- Suspected Typosquatting` | `- Known Compromise`

### Container & Kubernetes
`Container - Running as Root` | `- Unpinned Base Image` | `- Secrets in Image` | `Kubernetes - Privileged Container` | `- RBAC Misconfiguration` | `- Missing Network Policy` | `- Host Access` | `- Missing Security Context`

### Mobile
`Mobile - Insecure Data Storage` | `- Missing Certificate Pinning` | `- WebView Vulnerability` | `- Deep Link Hijacking` | `- Binary Security` | `- Cleartext Traffic`

### Cloud Native
`Cloud - IAM Misconfiguration` | `- Public Storage` | `- Serverless Security` | `- Missing Encryption` | `- Network Exposure` | `- Service Account Key Exposure`

### Agent & Skill
`Agent - Overly Broad Tool Access` | `- Missing Safety Guardrails` | `- Data Exfiltration Risk` | `Skill - Unrestricted Bash` | `- Instruction Injection` | `- Privilege Boundary Violation` | `MCP - Untrusted Endpoint` | `- Credential Exposure`

### Critical Workflows
`Release - Debug Build in Production` | `- Test Credentials Shipped` | `- Missing Signing` | `Merge - Security Check Dropped` | `- Lock File Integrity` | `Hotfix - CI Bypass` | `Rollback - No Down Migration` | `- State Incompatibility` | `Feature Flag - Security Gate` | `- Stale Security Flag`

### Git & GitHub
`Git - Force Push to Protected Branch` | `- Unsigned Commits` | `- Credential Storage` | `- Submodule Risk` | `GitHub - Branch Protection Gap` | `- Deploy Key Exposure` | `- Webhook Secret Missing` | `- Missing 2FA` | `- PAT Scope/Expiration`

### Secrets
`Secrets - Cloud Credential` | `- API Token` | `- Private Key` | `- Connection String` | `- Generic Secret`

---

## Groundwork-Enhanced Report Template

When groundwork mode is active, use header `## Groundwork + Security Review` and add `**Groundwork Scope:** {files_read} files read, {functions_analyzed} functions analyzed, {endpoints_mapped} API endpoints mapped` to metadata.

Insert these sections before Security Findings:

```markdown
### Architecture Overview
**Components:** {N}  **Layers:** {list}  **Trust Boundaries:** {N}  **Entry Points:** {N}

#### Component Map
| Component | Responsibility | Dependencies | Entry Points |

#### Trust Boundaries
| Boundary | From (trust level) | To (trust level) | Data Crossing |

### Code Patterns
**Conventions:** Naming, Error Handling, Logging, Input Validation, Testing
**Deviations Found:** {N} ({N} with security implications)

| File:Line | Convention | Deviation | Security Implication |

### API Surface
| # | Method | Path | Auth | Rate Limited | Input Validated | Handler |
**Auth Coverage:** {N}/{total}  **Rate Limited:** {N}/{total}  **Input Validated:** {N}/{total}

### Documentation Correlation (if docs provided)
| Code Module | Doc Page | Coverage | Last Code Change | Last Doc Update | Status |
**Security Documentation Gaps:** | Missing Document | Category | Severity |

### Cross-Project Overlap (if multiple projects)
| User Story | Project A | Project B | Overlap Type | Evidence |

### Verification Summary
**Total Claims:** {N}  **Verified:** {N}  **Auto-Corrected:** {N}  **Failed:** {N}
| # | Claim | Category | Source File | Status | Notes |
```

### Groundwork Finding Categories

| Category | Default Severity | Elevation Criteria |
|----------|-----------------|-------------------|
| `Architecture - Trust Boundary Gap` | MEDIUM | → HIGH if no security control at boundary |
| `Architecture - Missing Component Isolation` | MEDIUM | → HIGH if shared state enables privilege escalation |
| `Code Pattern - Convention Deviation` | LOW | → HIGH/CRITICAL if deviation causes a vulnerability |
| `Code Pattern - Logging Sensitive Data` | HIGH | Maintain |
| `API Surface - Missing Auth Requirement` | HIGH | Maintain |
| `API Surface - Inconsistent Validation` | MEDIUM | Maintain |
| `Documentation - Security Doc Gap` | LOW-MEDIUM | → MEDIUM for auth/incident response gaps |
| `Cross-Project - Shared Vulnerability` | Escalate +1 | Systemic issue |
| `Cross-Project - Divergent Security Posture` | HIGH | Maintain |

### Groundwork Categories
`Architecture - Trust Boundary Gap` | `- Missing Component Isolation` | `- Circular Dependency` | `- Shared State Risk`
`Code Pattern - Convention Deviation` | `- Inconsistent Error Handling` | `- Missing Input Validation Pattern` | `- Logging Sensitive Data`
`API Surface - Undocumented Endpoint` | `- Missing Auth Requirement` | `- Inconsistent Validation` | `- Missing Rate Limiting`
`Documentation - Security Doc Gap` | `- Stale Documentation` | `- Missing Runbook` | `- Broken Reference`
`Cross-Project - Shared Vulnerability` | `- Version Inconsistency` | `- Divergent Security Posture` | `- Duplicate Implementation`

---

## HTML Report Generation (Groundwork Mode Only)

After producing the markdown report, generate both a static HTML report and live dashboard data.

### Static HTML Report

1. Read the template from [../assets/report-template.html](../assets/report-template.html)
2. Replace all `{{VARIABLE}}` placeholders with report data
3. Write the completed HTML to `/tmp/groundwork-report.html`

### JSON Report Data (for Live Dashboard)

Write report data as JSON to `/tmp/groundwork-report.json`:

```json
{
  "project_name": "", "scan_date": "", "scan_mode": "", "tech_stack": "",
  "overall_risk": "", "overall_risk_class": "", "files_reviewed": 0,
  "endpoints_count": 0, "findings_total": 0,
  "sections": {
    "executive_summary": "", "architecture": "", "code_patterns": "",
    "api_surface": "", "data_models": "", "dependencies": "",
    "devops": "", "git_health": "", "security_findings": "",
    "supply_chain": "", "adversarial": "", "doc_correlation": "",
    "cross_project": "", "remediation": "", "verification": "",
    "security_posture": ""
  }
}
```

Each section value should contain rendered HTML. Use `.finding` div structure with `data-severity` attributes for severity filtering in the dashboard.

### Inform the User

- Static report: `/tmp/groundwork-report.html`
- Live dashboard: `python3 scripts/serve-dashboard.py` → `http://localhost:8450`
- Dashboard auto-refreshes with new data if already running

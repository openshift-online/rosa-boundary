# Supply Chain Analysis Reference

Detailed procedures for dependency analysis, OpenSSF Scorecard evaluation, and supply chain threat intelligence.

## Dependency Files to Watch

| Ecosystem | Files | Version Pinning Expectation | Remediation |
|-----------|-------|---------------------------|-------------|
| Go | `go.mod`, `go.sum` | Module versions enforced by Go tooling | Use `go get package@v1.2.3`. Commit `go.sum` for integrity verification |
| Python | `requirements.txt`, `pyproject.toml`, `uv.lock`, `Pipfile.lock` | Exact pins (`==`) in production requirements | Use `pip freeze > requirements.txt` or `uv lock` for exact pins |
| Node.js | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | Exact versions in lock files | Run `npm install --save-exact`. Commit lock files. Use `npm ci` in CI |
| Terraform | `*.tf` (provider/module `source` blocks), `.terraform.lock.hcl` | Version constraints with lock file | Use `version = "~> 1.2.0"` constraints. Run `terraform init` to generate lock file |
| Containers | `Dockerfile`, `Containerfile` | Exact image tags or SHA digests | Pin: `FROM node:20.11.0@sha256:abc...`. Avoid `:latest` |
| Helm | `Chart.yaml` (dependency entries), `Chart.lock` | Pinned chart versions | Pin versions in `Chart.yaml`. Run `helm dependency build` to generate `Chart.lock` |
| Ruby | `Gemfile`, `Gemfile.lock` | Exact versions in lock file | Run `bundle lock`. Always commit `Gemfile.lock` |
| Rust | `Cargo.toml`, `Cargo.lock` | Lock file pinning | Run `cargo update`. Commit `Cargo.lock` for binaries/applications |
| Java | `pom.xml`, `build.gradle` | Exact versions | Use exact versions in `pom.xml`. Use Gradle dependency locking |
| .NET | `*.csproj`, `packages.lock.json` | Lock file pinning | Enable `RestorePackagesWithLockFile` in project. Commit `packages.lock.json` |

## Tag Pinning Rules

The `:latest` tag and equivalent unpinned version specifiers are **never acceptable**. Flag every occurrence.

| Context | Violation Examples | Expected | Remediation |
|---------|-------------------|----------|-------------|
| Dockerfile `FROM` | `FROM nginx:latest`, `FROM nginx` (implicit latest) | `FROM nginx:1.27.0` or `FROM nginx@sha256:...` | Pin to specific version. Get digest: `docker manifest inspect nginx:1.27.0` |
| Helm `image.tag` | `tag: latest`, `tag: ""` | `tag: "v1.2.3"` | Set explicit tag in `values.yaml`. Use `.Chart.AppVersion` as default |
| Terraform container image | `image = "nginx:latest"` | `image = "nginx:1.27.0"` | Pin version in Terraform variable |
| Kubernetes manifests | `image: nginx:latest` | `image: nginx:1.27.0` | Pin in manifest. Use admission webhook to reject `:latest` |
| Python dependencies | `requests`, `requests>=2.0` | `requests==2.31.0` | Pin with `==`. Use `pip-compile` or `uv lock` for transitive pinning |
| Node.js dependencies | `"lodash": "*"`, `"lodash": "latest"` | `"lodash": "4.17.21"` | Use `npm install --save-exact`. Set `save-exact=true` in `.npmrc` |
| GitHub Actions | `uses: actions/checkout@main` | `uses: actions/checkout@sha256hash` | Use `pinact` to auto-pin. Use Dependabot for updates |

Report as **MEDIUM** severity under `Infrastructure - Unpinned Image Tag` or `Application - Unpinned Dependency Version`.

## Suspiciously New Package Versions

Newly published package versions (released within the last 7 days) are a supply chain risk.

### How to Check

For each added or updated dependency in the diff:

1. **Determine the publish date** of the specific version:
   - **Go**: WebSearch for `"$MODULE@$VERSION"` on pkg.go.dev or the module's release page
   - **Python**: WebSearch for `"$PACKAGE_NAME $VERSION"` on pypi.org — check the version history page
   - **Node.js**: WebSearch for `"$PACKAGE_NAME $VERSION"` on npmjs.com — check the publish date
   - **Terraform providers/modules**: Check the Terraform Registry or GitHub releases page
   - **Container images**: Check the registry (Docker Hub, quay.io, ECR) for the tag's push date
   - **Helm charts**: Check the chart repository or GitHub releases

2. **Compare against today's date**: If published within the last 7 days, flag it.

3. **Report** as **MEDIUM** under `Supply Chain - Suspiciously New Version` with:
   - The package name and version
   - The publish date
   - A note to hold until more community vetting or verify legitimacy

**Remediation:** Wait 7-14 days before adopting brand-new versions unless urgently needed. Monitor the package's issue tracker for reports. Verify the release was made by the expected maintainer.

### What NOT to Do

- Do not flag version bumps to versions older than 7 days
- Do not flag dependencies that were not changed in the diff
- If the publish date cannot be determined, note the uncertainty but do not block

## Bulk Dependency Changes

A diff that changes more than 10 package versions at once is a supply chain risk.

### How to Check

1. **Count changed dependencies**: From the diff, count added, removed, or version-changed entries across all dependency files. Count each package once even if it appears in multiple files.

2. **If count exceeds 10**: Flag as **HIGH** under `Supply Chain - Bulk Dependency Change` with:
   - Total number of dependencies changed
   - Breakdown by ecosystem (e.g., "8 Go modules, 5 Python packages")
   - Recommendation to split into smaller, reviewable chunks

3. **Escalate scrutiny**: When bulk change is detected, apply the Suspiciously New Package Versions check to **every** changed dependency, not just added ones.

**Remediation:** Split large dependency updates into smaller, reviewable PRs. Use Dependabot/Renovate to automate individual package updates. Review each changed package individually.

### Exceptions

- **Lock file regeneration**: If only lock files changed (`go.sum`, `uv.lock`, `package-lock.json`) and the manifest file has no version changes, report as **LOW** instead of HIGH.
- **Automated tooling**: If PR title/description indicates Dependabot, Renovate, or similar tools, note the context but still flag for review.

## OpenSSF Scorecard Evaluation

For any **newly added** dependency (not version bumps of existing ones), evaluate the upstream repository's security posture.

### When to Run

Only for dependencies that appear **for the first time** in a dependency file. Skip version bumps of existing dependencies.

### How to Query

Before constructing the URL, validate that `{owner}` and `{repo}` values contain only alphanumeric characters, hyphens, underscores, dots, and forward slashes. Reject any values containing spaces, quotes, semicolons, or shell metacharacters.

```bash
curl -s "https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}"
```

### Mapping Packages to Repositories

| Ecosystem | How to Find Source Repo |
|-----------|----------------------|
| Go | Module path starting with `github.com/` maps directly |
| Python | PyPI page `repository` or `homepage` URL |
| Node.js | `repository` field on npm page |
| Terraform | Module `source` block contains GitHub reference |
| Container images | Registry page for source repository link |

If the source repository is not on GitHub or cannot be determined, skip the Scorecard check and note it.

### Interpreting Results

The API returns an aggregate `score` (0-10) and individual `checks`.

**Flag these conditions:**

| Condition | Severity | Category | Remediation |
|-----------|----------|----------|-------------|
| Aggregate score < 3 | **HIGH** | `Supply Chain - Low Scorecard Rating` | Evaluate alternatives with higher scores. If no alternative, pin to verified commit hash and document accepted risk |
| Aggregate score 3-5 | **MEDIUM** | `Supply Chain - Low Scorecard Rating` | Note the risk. Monitor for improvements. Consider forking and maintaining if critical |
| `Maintained` check score = 0 | **HIGH** | `Supply Chain - Unmaintained Dependency` | Look for maintained fork. If none, evaluate effort to maintain internally. Don't depend on abandoned projects |
| `Dangerous-Workflow` check score < 5 | **HIGH** | `Supply Chain - Dangerous Upstream Workflow` | The upstream CI could be compromised. Pin to specific commit. Monitor for suspicious releases |
| `Branch-Protection` check score = 0 | **MEDIUM** | `Supply Chain - Weak Upstream Controls` | Upstream has no branch protection — any contributor could push directly to main. Pin strictly |
| `Code-Review` check score = 0 | **MEDIUM** | `Supply Chain - Weak Upstream Controls` | No code review requirement. Changes could be malicious. Pin and audit releases manually |
| `Signed-Releases` check score = 0 | **LOW** | `Supply Chain - Unsigned Releases` | Releases aren't cryptographically signed. Verify by commit hash instead |

### What NOT to Do

- Do not block on API failures — note the gap and move on
- Do not flag dependencies with aggregate score >= 6
- Do not run Scorecard on version bumps of existing dependencies

## Threat Intelligence Search

For each added or updated package, search for recent supply chain threats:

### Search Queries

```
"$PACKAGE_NAME" supply chain attack
"$PACKAGE_NAME" malware compromise
"$PACKAGE_NAME" typosquatting
"$PACKAGE_NAME" backdoor
```

### Assessment

- For relevant results, determine whether the version being introduced is affected
- If a search returns no results, that is a clean signal, not an error
- Focus on direct dependencies explicitly changed in the diff, not transitive dependencies

**Remediation if threat found:** Immediately remove the affected package. Audit any builds that used it. Check for indicators of compromise in deployment environment. Report to the package registry.

## Typosquatting Detection

Check if any newly added package names are suspiciously similar to well-known packages:

| Indicator | Example | Action | Remediation |
|-----------|---------|--------|-------------|
| Character substitution | `requets` vs `requests` | Flag as HIGH | Verify correct package name. Remove if typosquat. Report to registry |
| Hyphen/underscore swap | `python-dateutil` vs `python_dateutil` | Verify correct package | Check which is the canonical name on the registry |
| Scope confusion (npm) | `@evil/lodash` vs `lodash` | Flag as HIGH | Always use the canonical unscoped package unless the scope is your organization |
| Extra/missing characters | `colorsss` vs `colors` | Flag as HIGH | Remove immediately. This is a common typosquatting pattern |

Report as **HIGH** under `Supply Chain - Suspected Typosquatting`.

## Dependency Update Automation

**Remediation — Set up automated dependency updates:**

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
    open-pull-requests-limit: 10
    groups:
      minor-and-patch:
        update-types: [minor, patch]

  - package-ecosystem: docker
    directory: /
    schedule:
      interval: weekly

  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```

```json
// renovate.json (alternative to Dependabot)
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended", "security:openssf-scorecard"],
  "vulnerabilityAlerts": { "enabled": true },
  "packageRules": [
    { "matchUpdateTypes": ["major"], "dependencyDashboardApproval": true }
  ]
}
```

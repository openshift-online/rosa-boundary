# Secret Detection Reference

Patterns and procedures for identifying hardcoded secrets, API keys, tokens, and credentials.

## High-Confidence Secret Patterns

These patterns have low false-positive rates and should always be flagged.

### Cloud Provider Credentials

| Secret Type | Regex Pattern | Severity | Remediation |
|-------------|---------------|----------|-------------|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` | CRITICAL | Rotate key in AWS IAM console immediately. Use IAM roles with STS temporary credentials instead |
| AWS Secret Access Key | `(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}` | CRITICAL | Delete the key in IAM. Use `aws configure` with `credential_process` for dynamic credentials |
| AWS Session Token | `(?i)aws_session_token\s*[:=]\s*[A-Za-z0-9/+=]+` | CRITICAL | These are temporary but still sensitive. Rotate the source credentials that generated them |
| GCP Service Account Key | `"type"\s*:\s*"service_account"` (in JSON files) | CRITICAL | Delete the key in GCP Console. Use Workload Identity Federation instead of downloaded keys |
| Azure Client Secret | `(?i)azure[_-]?client[_-]?secret\s*[:=]\s*["'][^"']+["']` | CRITICAL | Rotate in Azure AD. Use Managed Identity for Azure resources, certificate auth for external apps |
| Azure Storage Key | `(?i)AccountKey\s*=\s*[A-Za-z0-9/+=]{86,88}==` | CRITICAL | Regenerate storage keys. Use SAS tokens with minimum permissions and expiration |

### API Tokens & Keys

| Secret Type | Regex Pattern | Severity | Remediation |
|-------------|---------------|----------|-------------|
| GitHub Token (classic) | `ghp_[A-Za-z0-9]{36,}` | CRITICAL | Revoke at github.com/settings/tokens. Use fine-grained PATs or GitHub Apps instead |
| GitHub Token (fine-grained) | `github_pat_[A-Za-z0-9_]{82}` | CRITICAL | Revoke at github.com/settings/tokens. Recreate with minimum required permissions |
| GitHub OAuth | `gho_[A-Za-z0-9]{36,}` | CRITICAL | Revoke the OAuth app authorization. Regenerate client secret |
| GitLab Token | `glpat-[A-Za-z0-9_-]{20,}` | CRITICAL | Revoke at GitLab Profile → Access Tokens. Use project/group tokens with limited scope |
| Slack Bot Token | `xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}` | CRITICAL | Regenerate at api.slack.com/apps. Rotate OAuth tokens for the workspace |
| Slack Webhook | `hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}` | HIGH | Regenerate webhook URL in Slack app config. Use bot tokens for better access control |
| PagerDuty API Key | `(?i)pagerduty.*[:=]\s*["']?[A-Za-z0-9+/]{20}["']?` | HIGH | Regenerate in PagerDuty settings. Use OAuth for integrations |
| SendGrid API Key | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` | CRITICAL | Delete and recreate at app.sendgrid.com/settings/api_keys with minimum scope |
| Stripe API Key | `[sr]k_(live\|test)_[A-Za-z0-9]{24,}` | CRITICAL | Roll keys at dashboard.stripe.com/apikeys. Use restricted keys with minimum permissions |
| Twilio Auth Token | `(?i)twilio.*[:=]\s*["']?[a-f0-9]{32}["']?` | HIGH | Regenerate at twilio.com/console. Use API keys instead of account auth token |

### Private Keys & Certificates

| Secret Type | Regex Pattern | Severity | Remediation |
|-------------|---------------|----------|-------------|
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | CRITICAL | Regenerate the key pair. Revoke associated certificates. Never commit private keys |
| EC Private Key | `-----BEGIN EC PRIVATE KEY-----` | CRITICAL | Same as RSA — regenerate and revoke |
| OpenSSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` | CRITICAL | Generate new key: `ssh-keygen -t ed25519`. Remove old public key from all authorized_keys files |
| PGP Private Key | `-----BEGIN PGP PRIVATE KEY BLOCK-----` | CRITICAL | Revoke the key on keyservers. Generate new PGP key pair |
| PKCS8 Private Key | `-----BEGIN PRIVATE KEY-----` | CRITICAL | Regenerate key pair. Reissue certificates. Update all services using this key |
| Certificate (not secret but verify) | `-----BEGIN CERTIFICATE-----` | LOW | Not a secret itself, but verify the corresponding private key isn't also committed |

### Database & Connection Strings

| Secret Type | Regex Pattern | Severity | Remediation |
|-------------|---------------|----------|-------------|
| PostgreSQL connection | `postgres://[^:]+:[^@]+@` | CRITICAL | Change password. Use `DATABASE_URL` env var. Use IAM auth for cloud databases |
| MySQL connection | `mysql://[^:]+:[^@]+@` | CRITICAL | Change password. Use env var or secret manager |
| MongoDB connection | `mongodb(\+srv)?://[^:]+:[^@]+@` | CRITICAL | Change password. Use SCRAM-SHA-256 auth. Rotate via Atlas or mongosh |
| Redis with password | `redis://:[^@]+@` | CRITICAL | Change Redis password. Use ACL users in Redis 6+ |
| Generic connection string | `(?i)(password\|passwd\|pwd)\s*[:=]\s*["'][^"']{8,}["']` | HIGH | Move to env var or secret manager. Never hardcode credentials |
| JDBC with password | `jdbc:[a-z]+://.*password=[^&\s]+` | CRITICAL | Use connection pooling with secret manager. Use IAM database auth where available |

### Generic Patterns (Higher False Positive Rate)

| Pattern | Context Needed | Severity | Remediation |
|---------|---------------|----------|-------------|
| `(?i)(api[_-]?key\|apikey)\s*[:=]\s*["'][A-Za-z0-9]{16,}["']` | Check if it's a real value, not a placeholder | HIGH | Move to env var. If placeholder, mark with `# nosecret` comment explaining why |
| `(?i)(secret\|token)\s*[:=]\s*["'][A-Za-z0-9+/=]{20,}["']` | Verify not a test/mock value | HIGH | Move to env var or secret manager |
| `(?i)bearer\s+[A-Za-z0-9._-]{20,}` | Could be in examples/docs | HIGH | Remove from code. Use dynamic token acquisition at runtime |
| `(?i)authorization.*[:=]\s*["']Basic\s+[A-Za-z0-9+/=]+["']` | Base64-encoded credentials | HIGH | Decode and rotate the credentials. Use token-based auth instead of Basic auth |

## Files to Prioritize

Scan these file patterns first — they are most likely to contain secrets:

| Priority | File Patterns |
|----------|--------------|
| Critical | `.env`, `.env.*`, `credentials.*`, `secrets.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx` |
| High | `config.*`, `settings.*`, `application.yml`, `application.properties`, `docker-compose*.yml` |
| Medium | `*.tf`, `*.tfvars`, `*.cfg`, `*.ini`, `*.conf`, `*.toml` |
| Low | Source code files, test files |

**Files that should NEVER be committed:**
```
.env
.env.local
.env.production
credentials.json
service-account-key.json
*.pem (private keys)
*.key
*.p12
*.pfx
.htpasswd
```

**Remediation — .gitignore setup:**
```bash
# Add to .gitignore
cat >> .gitignore << 'EOF'
.env
.env.*
!.env.example
credentials.*
secrets.*
*.pem
*.key
*.p12
*.pfx
.htpasswd
service-account-key.json
EOF
```

## False Positive Guidance

### Common False Positives

| Pattern | False Positive Indicator | Action |
|---------|------------------------|--------|
| `AKIA...` | In AWS SDK test fixtures, mock files | Check file path for `test`, `mock`, `fixture`, `example` |
| `-----BEGIN...-----` | Public certificates, test certs | Verify it's `PRIVATE KEY`, not `CERTIFICATE` or `PUBLIC KEY` |
| Generic `password = "..."` | Placeholder values | Check for `changeme`, `TODO`, `REPLACE`, `xxxxxxx`, `example` |
| Connection strings | Docker Compose local dev | Check if the file is clearly dev-only (e.g., `docker-compose.dev.yml`) |
| Base64 strings | Configuration data, non-secret encoded values | Verify context suggests it is a credential |

### Placeholder Values to Ignore

These are common placeholder patterns that should NOT be flagged:
```
changeme
CHANGE_ME
REPLACE_ME
your-*-here
xxx+
000+
example
placeholder
TODO
<.*>
\$\{.*\}
```

### Test/Mock Files to Deprioritize

If a secret pattern is found in these paths, reduce severity by one level:
- `**/test/**`, `**/tests/**`, `**/*_test.*`, `**/*_test_*`
- `**/mock/**`, `**/mocks/**`, `**/fixtures/**`
- `**/example/**`, `**/examples/**`, `**/sample/**`
- `**/testdata/**`, `**/fake*`

## Reporting Secrets

When reporting a found secret:

1. **Do NOT include the full secret value** in the report — truncate to first 4-8 characters
2. Include the file path and line number
3. Specify the secret type (from the tables above)
4. Recommend:
   - Immediately rotating the credential
   - Removing it from version history (`git filter-repo` or BFG)
   - Using environment variables or a secret manager instead
   - Adding the file pattern to `.gitignore`

## Prevention Setup

```bash
# Option 1: git-secrets (AWS-focused)
git secrets --install
git secrets --register-aws

# Option 2: detect-secrets (Yelp, multi-provider)
pip install detect-secrets
detect-secrets scan > .secrets.baseline
# Add pre-commit hook

# Option 3: gitleaks
brew install gitleaks  # or download from GitHub
gitleaks detect --source .

# Option 4: truffleHog
pip install trufflehog
trufflehog git file://. --only-verified

# GitHub-native: Enable secret scanning in repo Settings → Code security
```

## Secret Manager Migration Guide

| From | To | Steps |
|------|----|-------|
| Hardcoded string | Environment variable | 1. Add to `.env` (gitignored). 2. Read with `os.environ["KEY"]`. 3. Set in CI/CD secrets |
| Environment variable | AWS Secrets Manager | 1. Create secret: `aws secretsmanager create-secret`. 2. Read at runtime via SDK. 3. Grant IAM access |
| Environment variable | HashiCorp Vault | 1. Store: `vault kv put secret/app key=value`. 2. Read via API or agent. 3. Set up auth method |
| Environment variable | GCP Secret Manager | 1. Create: `gcloud secrets create`. 2. Add version. 3. Read via SDK with IAM permissions |
| Environment variable | Azure Key Vault | 1. Create secret in Key Vault. 2. Reference via `@Microsoft.KeyVault(SecretUri=...)` in App Service |

## OpenShift & Kubernetes Secrets Management

Kubernetes `Secret` objects use base64 encoding — this is **not encryption**. Treat K8s secrets as plaintext unless encryption at rest is configured.

### Checks

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unencrypted K8s Secret in manifest | `kind: Secret` with `data:` or `stringData:` containing credentials | HIGH | Enable encryption at rest via `EncryptionConfiguration`. Use SealedSecrets or ExternalSecrets Operator for GitOps workflows |
| Secret committed to Git | `kind: Secret` YAML/JSON files in version control | CRITICAL | Remove from Git history (`git filter-repo`). Replace with SealedSecrets for safe Git storage |
| Broad Secret RBAC access | `resources: ["secrets"]` with `verbs: ["get", "list", "watch"]` at cluster scope | HIGH | Scope to namespace with `Role` (not `ClusterRole`). Use `resourceNames` to restrict to specific secrets |
| Missing encryption at rest | Cluster without `EncryptionConfiguration` for `secrets` resource | MEDIUM | Configure `EncryptionConfiguration` with `aescbc` or `secretbox` provider on the API server |

### GitOps-Safe Secret Management

| Solution | When to Use | Setup |
|----------|-------------|-------|
| **SealedSecrets** | GitOps workflows where encrypted secrets must live in Git | Install `kubeseal` CLI and SealedSecrets controller. Encrypt with `kubeseal --format yaml < secret.yaml > sealed-secret.yaml`. Only the cluster can decrypt |
| **ExternalSecrets Operator** | Secrets stored in external providers (AWS SM, Vault, GCP SM, Azure KV) | Install ESO. Create `SecretStore` pointing to provider. Create `ExternalSecret` referencing provider keys. ESO syncs secrets into K8s `Secret` objects |
| **HashiCorp Vault + CSI** | Dynamic secrets with automatic rotation | Install Vault CSI Provider. Mount secrets as volumes via `SecretProviderClass`. Vault handles rotation and lease management |

### OpenShift-Specific Token Handling

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Hardcoded OpenShift OAuth token | `sha256~[A-Za-z0-9_-]{43}` | CRITICAL | Revoke token via `oc delete oauthaccesstoken`. Use `oc login` with service account tokens for automation |
| Service account token in source | `eyJhbGciOiJSUzI1NiIs...` (JWT format in non-config files) | HIGH | Use projected service account tokens with expiration. Mount via `serviceAccountToken` volume |
| Pull secret in code | `cloud.openshift.com` auth JSON with `auths` key | CRITICAL | Store as K8s `Secret` of type `kubernetes.io/dockerconfigjson`. Reference from `ServiceAccount.imagePullSecrets` |

> **Cross-reference:** For container-level secret exposure checks (build args, ENV, COPY), see [infrastructure-containers-cloud.md](infrastructure-containers-cloud.md) (Dockerfile Security section).

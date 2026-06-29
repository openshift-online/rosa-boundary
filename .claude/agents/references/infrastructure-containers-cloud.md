# Infrastructure, Container & Cloud Security

Combined reference for infrastructure-as-code, container/Kubernetes, and cloud-native security checks.

---

# Infrastructure Security (IaC)


Detailed checks for Terraform, ArgoCD, Helm, and other infrastructure-as-code files.

## Terraform Security Checks

### IAM & Access Control

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Wildcard actions | `"Action": "*"` or `"Action": ["*"]` | CRITICAL | Replace with specific actions needed: `"Action": ["s3:GetObject", "s3:PutObject"]`. Use IAM Access Analyzer to right-size |
| Wildcard resources | `"Resource": "*"` with non-read actions | HIGH | Scope to specific ARNs: `"Resource": "arn:aws:s3:::my-bucket/*"` |
| Missing condition constraints | `assume_role_policy` without `Condition` block | MEDIUM | Add conditions: `"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-xxx"}}` |
| Overly broad principals | `"Principal": "*"` or `"Principal": {"AWS": "*"}` | CRITICAL | Restrict to specific accounts/roles: `"Principal": {"AWS": "arn:aws:iam::123:role/app"}` |
| Inline policies over managed | Large inline `policy` blocks vs `aws_iam_policy_attachment` | LOW | Extract to managed policies with `aws_iam_policy`. Easier to audit, reuse, and track |
| PassRole without constraints | `iam:PassRole` without resource scoping | HIGH | Restrict PassRole to specific role ARNs: `"Resource": "arn:aws:iam::*:role/specific-role"` |

**Grep patterns:**
```
"Action"\s*:\s*"\*"
"Resource"\s*:\s*"\*"
"Principal"\s*:\s*"\*"
iam:PassRole
```

**IaC scanning setup:**
```bash
# tfsec (now part of Trivy)
trivy config --severity HIGH,CRITICAL .

# checkov
pip install checkov
checkov -d . --framework terraform

# Add to CI
# GitHub Actions:
# - uses: aquasecurity/trivy-action@master
#   with:
#     scan-type: config
#     severity: HIGH,CRITICAL
```

### Network Exposure

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Open ingress to world | `cidr_blocks = ["0.0.0.0/0"]` on non-443/80 ports | HIGH | Restrict to known IP ranges: `cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12"]`. Use security group references for internal traffic |
| Open egress to world | Egress `0.0.0.0/0` without justification | MEDIUM | Restrict egress to required destinations. Use VPC endpoints for AWS services |
| Missing VPC endpoints | S3/DynamoDB access without `aws_vpc_endpoint` | MEDIUM | Create VPC endpoints: `aws_vpc_endpoint` with type `Gateway` for S3/DynamoDB |
| Public subnets for internal resources | `map_public_ip_on_launch = true` for non-public workloads | HIGH | Use private subnets for internal workloads. Route through NAT gateway for internet access |
| SSH open to world | Port 22 with `0.0.0.0/0` CIDR | CRITICAL | Remove SSH access. Use SSM Session Manager or bastion hosts with restricted IPs |
| RDP open to world | Port 3389 with `0.0.0.0/0` CIDR | CRITICAL | Remove RDP access. Use VPN or AWS Systems Manager for remote access |

### Encryption

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unencrypted EBS volumes | `aws_ebs_volume` without `encrypted = true` | HIGH | Add `encrypted = true`. Enable account-level default encryption: `aws_ebs_encryption_by_default` |
| Unencrypted RDS | `aws_db_instance` without `storage_encrypted = true` | HIGH | Add `storage_encrypted = true`. Use KMS CMK for cross-account access |
| S3 without encryption | `aws_s3_bucket` without server-side encryption config | HIGH | Add `aws_s3_bucket_server_side_encryption_configuration` with `sse_algorithm = "aws:kms"` |
| Missing KMS key rotation | `aws_kms_key` without `enable_key_rotation = true` | MEDIUM | Add `enable_key_rotation = true` to all KMS key resources |
| Unencrypted Elasticache | `aws_elasticache_replication_group` without `at_rest_encryption_enabled` | HIGH | Add `at_rest_encryption_enabled = true` and `transit_encryption_enabled = true` |

### S3 Bucket Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Public access not blocked | Missing `aws_s3_bucket_public_access_block` | HIGH | Add public access block with all four settings set to `true`. Enable at account level via S3 settings |
| ACL set to public | `acl = "public-read"` or `"public-read-write"` | CRITICAL | Remove public ACL. Use bucket policies for controlled access. Use CloudFront for public content |
| Missing bucket logging | No `logging` configuration | MEDIUM | Add `aws_s3_bucket_logging` targeting a dedicated logging bucket |
| Missing versioning | No `versioning { enabled = true }` for state/data buckets | MEDIUM | Add `aws_s3_bucket_versioning` with `status = "Enabled"`. Add lifecycle rules for old versions |

### State & Secrets

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Hardcoded secrets in .tf | `password =`, `secret =`, `api_key =` with literal values | CRITICAL | Use `variable` with no default. Pass via `TF_VAR_*` env vars or `-var-file`. Use `data.aws_secretsmanager_secret_version` |
| Remote state without encryption | `backend "s3"` without `encrypt = true` | HIGH | Add `encrypt = true` to backend config. Use KMS key for encryption |
| Sensitive outputs unmasked | `output` blocks without `sensitive = true` for credentials | HIGH | Add `sensitive = true` to outputs containing secrets. Terraform will mask the value in logs |
| .tfvars with secrets | Credential values in committed `.tfvars` files | CRITICAL | Add `*.tfvars` to `.gitignore`. Use `TF_VAR_*` environment variables instead |

## ArgoCD Security Checks

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Cluster-admin RBAC | `policy.csv` granting `*` on all resources | CRITICAL | Scope to specific projects and resources: `p, role:dev, applications, *, dev-project/*, allow` |
| Plaintext secrets in Application manifests | Secret values in `spec.source.helm.parameters` | CRITICAL | Use SealedSecrets, External Secrets Operator, or Vault. Never put secrets in ArgoCD Application manifests |
| Auto-sync without prune protection | `automated.prune: true` without safeguards | MEDIUM | Add `automated.selfHeal: true` with `syncOptions: [PrunePropagationPolicy=foreground]`. Use sync windows for production |
| Unknown/external repos | `spec.source.repoURL` pointing to untrusted sources | HIGH | Restrict allowed repos in ArgoCD settings. Use organization's Git server only |

## Helm Chart Security Checks

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Secrets in values.yaml | Plaintext passwords, tokens, keys in default values | CRITICAL | Remove default secrets. Use external secret injection. Document required secrets in values schema |
| Tiller-era patterns | `tiller` references (Helm 2 security anti-pattern) | MEDIUM | Migrate to Helm 3. Remove all Tiller references and RBAC |
| Missing network policies | No `NetworkPolicy` template in chart | MEDIUM | Add NetworkPolicy template with configurable ingress/egress rules |
| Hardcoded image tags | `image.tag` defaulting to `latest` | MEDIUM | Default to a specific version in `values.yaml`. Use `appVersion` from `Chart.yaml` |

## Compliance Touchpoints

| Framework | Relevant Checks | Remediation |
|-----------|----------------|-------------|
| CIS AWS Foundations | IAM root access, CloudTrail logging, VPC flow logs | Enable CloudTrail in all regions. Enable VPC flow logs. Disable root access keys |
| PCI-DSS | Encryption at rest and in transit, access logging, network segmentation | Encrypt all data stores. Enable TLS everywhere. Segment cardholder data environment |
| SOC 2 | Access controls, encryption, audit logging | Implement RBAC. Enable CloudTrail. Set up change management process |

Flag these as informational when detected — full compliance scanning is out of scope.

---

# Container & Kubernetes Security


Security checks for Dockerfiles, container configurations, Kubernetes manifests, and Helm templates.

## Dockerfile Security

### Image & Build Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unpinned base image | `FROM image` or `FROM image:latest` | MEDIUM | Pin to specific version: `FROM node:20.11.0-slim`. For maximum security, pin to digest: `FROM node@sha256:abc...` |
| No digest pinning for critical images | `FROM image:tag` without `@sha256:` for production | LOW | Add digest: `FROM node:20.11.0@sha256:abc...`. Get digest with `docker manifest inspect` |
| Running as root | No `USER` instruction or `USER root` as final stage | HIGH | Add non-root user: `RUN addgroup -S app && adduser -S app -G app` then `USER app` before `ENTRYPOINT` |
| ADD instead of COPY | `ADD` for local files (ADD has tar extraction and URL fetch side effects) | MEDIUM | Replace `ADD` with `COPY` for local files. Only use `ADD` for tar auto-extraction |
| Secrets in build args | `ARG PASSWORD`, `ARG API_KEY`, `ARG TOKEN` | CRITICAL | Use BuildKit secrets: `RUN --mount=type=secret,id=api_key cat /run/secrets/api_key`. Or use multi-stage builds where secrets only exist in build stage |
| Secrets in ENV | `ENV PASSWORD=`, `ENV SECRET_KEY=` with literal values | CRITICAL | Pass secrets at runtime: `docker run -e PASSWORD="$PASSWORD"`. Never bake secrets into image layers |
| Secrets in COPY | Copying `.env`, `credentials`, `*.pem`, `*.key` files | HIGH | Add to `.dockerignore`. Use runtime volume mounts or secret managers for credentials |
| Package manager cache | `apt-get install` without `rm -rf /var/lib/apt/lists/*` | LOW | Chain in one RUN: `RUN apt-get update && apt-get install -y pkg && rm -rf /var/lib/apt/lists/*` |
| Missing HEALTHCHECK | No `HEALTHCHECK` instruction | LOW | Add: `HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health \|\| exit 1` |

**Grep patterns for Dockerfiles:**
```
^FROM\s+\S+\s*$
^FROM\s+\S+:latest
^ADD\s+(?!https?://)
^ARG\s+.*(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)
^ENV\s+.*(PASSWORD|SECRET|TOKEN|KEY)=
USER\s+root\s*$
```

### Multi-Stage Build Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Dev tools in final image | `gcc`, `make`, `curl`, `wget` installed but not in build stage | MEDIUM | Use multi-stage builds. Install dev tools only in `AS build` stage. Copy only artifacts to final stage |
| Debug tools in final image | `strace`, `gdb`, `tcpdump` in final stage | MEDIUM | Remove debug tools from final image. Use ephemeral debug containers in Kubernetes instead |
| Unnecessary COPY from build | Copying build artifacts that include source code | LOW | Copy only compiled output: `COPY --from=build /app/dist ./dist` not `COPY --from=build /app .` |

### Containerfile Best Practices

| Check | Description | Severity | Remediation |
|-------|-------------|----------|-------------|
| COPY --chown | Use `COPY --chown=user:group` instead of `RUN chown` after COPY | LOW | Replace `COPY . . && RUN chown -R app:app .` with `COPY --chown=app:app . .` |
| Writable root filesystem | No indication of read-only root fs intent | MEDIUM | Use read-only root fs in K8s: `readOnlyRootFilesystem: true`. Mount writable `/tmp` as emptyDir |
| Excessive layers | More than 15 RUN instructions that could be combined | LOW | Combine related RUN instructions with `&&`. Each RUN creates a layer |
| SHELL instruction | Using SHELL to change to a less secure shell | MEDIUM | Keep default shell. If custom shell needed, ensure it's a hardened alternative |

**Container scanning setup:**
```bash
# Trivy (comprehensive scanner)
trivy image --severity HIGH,CRITICAL myapp:latest

# Hadolint (Dockerfile linter)
hadolint Dockerfile

# Add to CI
# docker build -t myapp . && trivy image myapp:latest --exit-code 1 --severity HIGH,CRITICAL
```

## Kubernetes Manifest Security

### Pod Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Privileged containers | `securityContext.privileged: true` | CRITICAL | Remove `privileged: true`. Use specific capabilities instead if needed |
| Running as root | Missing `runAsNonRoot: true` or `runAsUser: 0` | HIGH | Add `securityContext: { runAsNonRoot: true, runAsUser: 1000 }` |
| Writable root filesystem | Missing `readOnlyRootFilesystem: true` | MEDIUM | Add `securityContext: { readOnlyRootFilesystem: true }`. Mount writable dirs as emptyDir volumes |
| All capabilities | `capabilities.add: ["ALL"]` | CRITICAL | Drop all and add only what's needed: `capabilities: { drop: ["ALL"], add: ["NET_BIND_SERVICE"] }` |
| Dangerous capabilities | `add: ["SYS_ADMIN"]`, `add: ["NET_ADMIN"]` without justification | HIGH | Remove unless absolutely required. Document justification. Use Pod Security Standards to enforce |
| Missing capability drops | No `capabilities.drop: ["ALL"]` | MEDIUM | Add `securityContext: { capabilities: { drop: ["ALL"] } }` to all containers |
| Host network | `hostNetwork: true` | HIGH | Remove `hostNetwork`. Use Services and Ingress for network exposure |
| Host PID | `hostPID: true` | HIGH | Remove `hostPID`. If monitoring is needed, use dedicated monitoring agents |
| Host IPC | `hostIPC: true` | HIGH | Remove `hostIPC`. Use K8s native inter-container communication |
| hostPath volumes | `hostPath` volume mounts (especially `/`, `/etc`, `/var/run/docker.sock`) | CRITICAL | Replace with emptyDir, PVCs, or ConfigMaps. Never mount host filesystem |
| Docker socket mount | Mounting `/var/run/docker.sock` | CRITICAL | Use Kaniko, Buildkit, or Podman for in-cluster builds instead of Docker socket |

**Grep patterns:**
```
privileged:\s*true
hostNetwork:\s*true
hostPID:\s*true
hostIPC:\s*true
hostPath:
/var/run/docker.sock
capabilities:
runAsUser:\s*0
```

**Recommended security context for all workloads:**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

### Resource Controls

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing resource limits | No `resources.limits` (CPU and/or memory) | MEDIUM | Add limits: `resources: { limits: { memory: "512Mi", cpu: "500m" }, requests: { memory: "256Mi", cpu: "250m" } }` |
| Missing resource requests | No `resources.requests` | LOW | Add requests matching typical usage. Requests affect scheduling, limits prevent noisy neighbors |
| Excessive resource limits | Memory limits > 8Gi or CPU limits > 4 without justification | LOW | Right-size based on actual usage from metrics. Start small and increase based on monitoring |
| Missing LimitRange | Namespace without LimitRange (if deploying namespace configs) | LOW | Add LimitRange to set default limits for pods without explicit resources |

### RBAC Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Cluster-admin binding | `ClusterRoleBinding` to `cluster-admin` | CRITICAL | Create custom ClusterRole with minimum permissions. Never bind cluster-admin to application service accounts |
| Wildcard verbs | `verbs: ["*"]` in Role/ClusterRole | HIGH | List specific verbs needed: `verbs: ["get", "list", "watch"]` |
| Wildcard resources | `resources: ["*"]` in Role/ClusterRole | HIGH | List specific resources: `resources: ["pods", "services"]` |
| Wildcard API groups | `apiGroups: ["*"]` in Role/ClusterRole | HIGH | List specific API groups: `apiGroups: ["", "apps"]` |
| Secrets access | `resources: ["secrets"]` with `verbs: ["get", "list"]` broadly scoped | MEDIUM | Scope secrets access to specific namespaces with Role (not ClusterRole). Use `resourceNames` to restrict to specific secrets |
| Escalation privileges | `verbs: ["escalate"]` or `verbs: ["bind"]` | HIGH | Remove unless required for cluster operators. These allow privilege escalation |
| Service account token auto-mount | Missing `automountServiceAccountToken: false` | LOW | Add `automountServiceAccountToken: false` to pods that don't need K8s API access |

### Network Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing NetworkPolicy | No NetworkPolicy for the namespace/workload | MEDIUM | Create default-deny NetworkPolicy, then allow specific traffic. Start with `ingress: []` (deny all) |
| Allow-all ingress | NetworkPolicy with empty `ingress` (allows all) | HIGH | Add specific ingress rules with podSelector and namespaceSelector |
| Allow-all egress | NetworkPolicy with empty `egress` (allows all) | MEDIUM | Restrict egress to required endpoints. Allow DNS (port 53) and specific service IPs |
| External service exposure | `Service` type `LoadBalancer` or `NodePort` without justification | MEDIUM | Use ClusterIP with Ingress controller. Use internal LoadBalancer for private access |
| Missing Ingress TLS | `Ingress` without `tls` section | HIGH | Add TLS: `tls: [{hosts: ["app.example.com"], secretName: app-tls}]`. Use cert-manager for auto-renewal |

### Service Mesh & mTLS

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| mTLS disabled | `PeerAuthentication` with `DISABLE` mode | HIGH | Set `mode: STRICT` for production namespaces |
| Permissive mTLS | `PeerAuthentication` with `PERMISSIVE` mode in production | MEDIUM | Migrate to STRICT after verifying all clients support mTLS |
| Sidecar bypass | `sidecar.istio.io/inject: "false"` without justification | MEDIUM | Remove bypass annotation. If required, document justification and add compensating controls |

## Helm Chart Security

### Values Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Default passwords | `password:`, `secret:`, `token:` with non-empty default values | CRITICAL | Set defaults to empty string. Use `required` in templates. Inject secrets via `--set` or external secret operator |
| Image tag latest | `image.tag` defaulting to `latest` or empty | MEDIUM | Default to specific version. Use `.Chart.AppVersion` as default |
| Privileged by default | `securityContext.privileged` defaulting to `true` | CRITICAL | Default to `false`. Require explicit opt-in with documentation of why |
| Root by default | `securityContext.runAsUser` defaulting to `0` | HIGH | Default to `1000`. Set `runAsNonRoot: true` |

### Chart Dependencies

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unpinned chart versions | `version: "*"` or missing version in Chart.yaml dependencies | MEDIUM | Pin to specific versions: `version: "1.2.3"`. Run `helm dependency update` to generate Chart.lock |
| Untrusted repositories | Dependencies from non-official Helm repos | MEDIUM | Use official repos (bitnami, stable). Verify chart source and maintainer. Mirror charts to internal registry |
| Missing Chart.lock | Dependencies defined but no Chart.lock committed | MEDIUM | Run `helm dependency build` and commit `Chart.lock` |

## OpenShift-Specific Checks

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| SecurityContextConstraints | Custom SCCs granting excessive privileges | HIGH | Use `restricted` SCC when possible. Create custom SCCs with minimum required privileges |
| anyuid SCC | SCC allowing `RunAsAny` for user strategy | HIGH | Use `MustRunAsRange` or `MustRunAsNonRoot`. Only allow anyuid for verified requirements |
| Route without TLS | `Route` without `tls.termination` | HIGH | Add `tls: { termination: edge }` or `termination: reencrypt` for end-to-end TLS |
| Missing OAuth proxy | Web-facing services without authentication proxy | MEDIUM | Deploy OAuth proxy sidecar for authentication. Use OpenShift OAuth or external IdP |
| Secret without encryption at rest | `kind: Secret` in cluster without `EncryptionConfiguration` | MEDIUM | Configure encryption at rest for secrets. Use `aescbc` or `secretbox` provider in `EncryptionConfiguration` |
| Plaintext secrets in GitOps | `kind: Secret` YAML committed to Git repositories | HIGH | Use SealedSecrets (`kubeseal`) or ExternalSecrets Operator. Never commit unencrypted secrets to Git |

> **Cross-reference:** For hardcoded credential pattern scanning and OpenShift token handling, see [secret-detection.md](secret-detection.md) (OpenShift & Kubernetes Secrets Management section). For the adversary skill's container/K8s checks, see the adversary skill's `references/container-kubernetes-security.md`.

---

# Cloud-Native Security


Security checks for AWS, GCP, Azure services, serverless functions, managed databases, object storage, and cloud-native architectures.

## AWS Security

### IAM

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Root account usage | Code using root account credentials | CRITICAL | Create IAM users/roles. Enable MFA on root. Use root only for billing and account-level changes |
| Long-lived access keys | `AKIA*` keys in code or config | CRITICAL | Use IAM roles with temporary credentials (STS). Use OIDC federation for CI/CD |
| Overly permissive policies | `"Action": "*"` or `"Resource": "*"` | HIGH | Follow least privilege. Use IAM Access Analyzer to right-size permissions. Start with zero permissions and add as needed |
| Missing condition keys | Policies without condition constraints | MEDIUM | Add conditions: `aws:SourceIp`, `aws:PrincipalOrgID`, `aws:RequestedRegion` |
| Cross-account trust without ExternalId | AssumeRole without `sts:ExternalId` condition | HIGH | Require ExternalId in cross-account trust policies to prevent confused deputy attacks |

**Remediation — Least-privilege IAM policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetObject",
      "s3:PutObject"
    ],
    "Resource": "arn:aws:s3:::my-bucket/uploads/*",
    "Condition": {
      "StringEquals": {
        "aws:PrincipalOrgID": "o-1234567890"
      }
    }
  }]
}
```

### S3

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Public bucket | `acl: "public-read"` or missing public access block | CRITICAL | Enable S3 Block Public Access at account level. Use bucket policies for specific access |
| Missing encryption | No server-side encryption configured | HIGH | Enable SSE-S3 (default) or SSE-KMS. Enable bucket default encryption |
| Missing access logging | No S3 access logging configured | MEDIUM | Enable server access logging to a separate logging bucket |
| Missing versioning | Versioning not enabled on data buckets | MEDIUM | Enable versioning on buckets containing important data. Add lifecycle rules for old versions |
| Overly permissive bucket policy | `"Principal": "*"` in bucket policy | CRITICAL | Restrict principals to specific accounts/roles. Use VPC endpoints for private access |

### Lambda / Serverless

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Secrets in environment variables | Plaintext secrets in Lambda env vars | HIGH | Use AWS Secrets Manager or SSM Parameter Store. Reference secrets at runtime, not deploy time |
| Overly permissive execution role | Lambda with `AdministratorAccess` | CRITICAL | Create function-specific IAM roles with minimum permissions. Use one role per function |
| Missing VPC for data access | Lambda accessing databases outside VPC | HIGH | Place Lambdas in VPC when accessing private resources. Use VPC endpoints for AWS services |
| No reserved concurrency | Lambda without concurrency limits (cost/DoS risk) | HIGH | Set reserved concurrency based on expected load. Prevents cost explosion from attack traffic |
| Missing input validation | Lambda handler without event validation | HIGH | Validate event schema. Use Powertools for validation. Reject malformed events early |
| Cold start auth bypass | Auth middleware failing during cold start | HIGH | Initialize auth before handler registration. Use provisioned concurrency for critical auth functions |

**Remediation — Secure Lambda function (Python):**
```python
import json
import boto3
from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.utilities.validation import validate

logger = Logger()
tracer = Tracer()

# Load secrets from Secrets Manager (cached across invocations)
secrets_client = boto3.client('secretsmanager')
_db_secret = None

def get_db_secret():
    global _db_secret
    if _db_secret is None:
        response = secrets_client.get_secret_value(SecretId='prod/db/credentials')
        _db_secret = json.loads(response['SecretString'])
    return _db_secret

@logger.inject_lambda_context
@tracer.capture_lambda_handler
def handler(event, context):
    # Validate input
    validate(event=event, schema=INPUT_SCHEMA)

    # Use secrets from Secrets Manager
    db_creds = get_db_secret()
    # ...process...
```

### Other AWS Services

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| SQS without encryption | SQS queue without SSE | MEDIUM | Enable SQS SSE with KMS or SQS-managed keys |
| SNS without encryption | SNS topic without encryption | MEDIUM | Enable SNS SSE. Restrict publish/subscribe to specific principals |
| DynamoDB without encryption | DynamoDB table without encryption at rest | MEDIUM | Enable encryption (default since 2023, verify for older tables) |
| CloudWatch logs without encryption | Log groups without KMS encryption | LOW | Enable KMS encryption for log groups containing sensitive data |
| RDS publicly accessible | `publicly_accessible: true` on RDS instance | CRITICAL | Set `publicly_accessible: false`. Use VPC private subnets. Access via VPN/bastion |
| ElastiCache without auth | Redis/Memcached without authentication | HIGH | Enable AUTH token for Redis. Use IAM auth for Redis 7+. Place in private subnet |

## GCP Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Service account key in code | JSON service account key file committed | CRITICAL | Use Workload Identity Federation. Delete the key file. Rotate compromised keys |
| Overly permissive IAM | `roles/owner` or `roles/editor` on service accounts | HIGH | Use predefined roles with minimum permissions. Create custom roles for specific needs |
| Public Cloud Storage bucket | `allUsers` or `allAuthenticatedUsers` access | CRITICAL | Remove public access. Use Uniform bucket-level access. Set organization policy to prevent public access |
| Cloud Functions without auth | HTTP functions without authentication | HIGH | Require authentication: `--no-allow-unauthenticated`. Use IAM invoker role |
| Cloud SQL without SSL | Database connections without SSL enforcement | HIGH | Enforce SSL connections. Use Cloud SQL Proxy for secure connections |
| Missing VPC Service Controls | Sensitive APIs accessible outside perimeter | MEDIUM | Create VPC Service Controls perimeter for sensitive projects |
| Firewall rules allowing 0.0.0.0/0 | VPC firewall open to all IPs | HIGH | Restrict source IPs to known ranges. Use service accounts for internal service communication |

**Remediation — GCP Workload Identity (replacing service account keys):**
```yaml
# GitHub Actions workflow
jobs:
  deploy:
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: 'projects/123/locations/global/workloadIdentityPools/github/providers/my-repo'
          service_account: 'deploy@project.iam.gserviceaccount.com'
```

## Azure Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Client secret in code | Azure AD client secret hardcoded | CRITICAL | Use Managed Identity for Azure resources. Use certificate-based auth for external apps |
| Storage account public access | Blob container with public access | CRITICAL | Disable public access at storage account level. Use SAS tokens or Managed Identity |
| Missing Key Vault usage | Secrets in app settings instead of Key Vault | HIGH | Store secrets in Azure Key Vault. Reference from app settings with `@Microsoft.KeyVault(SecretUri=...)` |
| SQL Database with public endpoint | Azure SQL without private endpoint | HIGH | Use Private Link/Private Endpoint. Disable public network access |
| NSG allowing all inbound | Network Security Group with `0.0.0.0/0` inbound | HIGH | Restrict inbound rules to specific source IPs/subnets. Use Application Security Groups |
| Missing diagnostic settings | No diagnostic logging on critical resources | MEDIUM | Enable diagnostic settings. Send logs to Log Analytics workspace. Set up alerts |

## Serverless Framework Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| `*` in IAM statements | `serverless.yml` with `iamRoleStatements: [{ Effect: Allow, Action: *, Resource: * }]` | CRITICAL | Specify exact actions and resources per function |
| Environment variables with secrets | Secrets in `serverless.yml` environment section | HIGH | Use `${ssm:/path/to/secret}` or `${env:VAR}` with CI/CD secrets |
| Missing API Gateway authorization | HTTP endpoints without authorizer | HIGH | Add Lambda authorizer or Cognito user pool authorizer to all endpoints |
| Missing CORS restrictions | `cors: true` (allows all origins) | MEDIUM | Specify allowed origins: `cors: { origins: ['https://app.example.com'] }` |
| Verbose error responses | Default Lambda error responses exposing stack traces | MEDIUM | Custom error handler that returns generic messages. Log detailed errors server-side |

## Container Registry Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Public container registry | ECR/GCR/ACR with public access | HIGH | Use private registries. Enable image scanning. Restrict pull access to specific IAM roles |
| Missing image scanning | No vulnerability scanning on pushed images | MEDIUM | Enable automatic scanning: ECR scan on push, GCR Container Analysis, ACR Defender |
| Missing image signing | Images not signed before deployment | MEDIUM | Sign images with cosign/Notation. Verify signatures in admission controller |
| Stale images in registry | Images not cleaned up (cost and stale vulnerability risk) | LOW | Implement lifecycle policies: keep last N tags, delete untagged after 7 days |

## Infrastructure as Code (Pulumi/CDK/Terraform)

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Hardcoded secrets in IaC | Secret values in Pulumi/CDK/Terraform code | CRITICAL | Use secret managers: `pulumi.secret()`, `cdk.SecretValue.secretsManager()`, `data.aws_secretsmanager_secret` |
| State file with secrets | Terraform state containing plaintext secrets | HIGH | Use remote state with encryption. Enable state locking. Restrict state access |
| Missing drift detection | No mechanism to detect infrastructure drift | MEDIUM | Run `terraform plan` in CI. Use AWS Config rules or equivalent for drift detection |
| Missing tagging | Resources without ownership/environment tags | LOW | Enforce tagging policies. Require at minimum: `environment`, `team`, `service` tags |

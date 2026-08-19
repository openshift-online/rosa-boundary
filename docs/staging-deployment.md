# Staging Deployment via HCP Terraform

The staging deployment of rosa-boundary runs in a dedicated AWS account (`rosa-boundary-stage`, `150100906299`) managed entirely through [HCP Terraform](https://app.terraform.io/app/hp-platform-engineering) (Terraform Cloud). Infrastructure changes are proposed, reviewed, and applied through the same PR workflow used for code changes -- no manual `terraform apply` runs.

This document covers the architecture of the HCP Terraform integration, how changes flow from code to deployed infrastructure, how users gain access, and the workspace layout.

## Table of Contents

- [Three-Layer Workspace Architecture](#three-layer-workspace-architecture)
- [How a Code Change Becomes Live](#how-a-code-change-becomes-live)
- [Workspaces](#workspaces)
- [AWS Dynamic Credentials](#aws-dynamic-credentials)
- [User Access](#user-access)
- [Workspace Variables](#workspace-variables)
- [Externally Managed Tags and Settings](#externally-managed-tags-and-settings)
- [Deletion Protection](#deletion-protection)
- [Two-PR Pattern for New Workspaces](#two-pr-pattern-for-new-workspaces)
- [Key Differences from Local Development](#key-differences-from-local-development)
- [References](#references)

---

## Three-Layer Workspace Architecture

The staging deployment follows the three-layer architecture defined by the [infra-platform](https://github.com/openshift-online/infra-platform) repository. Each layer manages the layer below it through HCP Terraform's API:

```
Layer 1 (Bootstrap)                    Layer 2 (Meta-workspace)              Layer 3 (Workloads)
infra-platform repo                    rosa-boundary repo                    rosa-boundary repo

┌──────────────────────┐               ┌──────────────────────┐
│   rosa-bootstrap     │──run trigger──│ meta-rosa-rosa-      │──run trigger──┐
│                      │               │ boundary             │               │
│ hcp-terraform/       │               │                      │               │
│  tenants/rosa/       │               │ hcp-terraform/       │               │
│                      │               │  rosa-boundary/      │               │
│ Creates:             │               │                      │               │
│  - rosa-boundary     │               │ Creates:             │               │
│    project           │               │                      │               │
│  - meta-rosa project │               │                      │               │
│  - ai-sd-sre team    │               │                      │               │
│  - deletion policy   │               │                      │               │
└──────────────────────┘               └──────────┬───────────┘               │
                                                  │                           │
                                   ┌──────────────┼──────────────┐            │
                                   │              │              │            │
                                   ▼              ▼              ▼            │
                          ┌──────────────┐ ┌────────────┐ ┌──────────────┐    │
                          │ stage-aws-   │ │ stage-     │ │ stage-       │◄───┘
                          │ creds        │ │ network    │ │ regional     │
                          │              │ │            │ │              │
                          │ hcp-terraform│ │ deploy/    │ │ deploy/      │
                          │ /aws-creds/  │ │ network/   │ │ regional/    │
                          │ rosa-boundary│ │            │ │              │
                          │ -stage/      │ │ VPC,       │ │ ECS, EFS,    │
                          │              │ │ subnets,   │ │ Lambda, IAM, │
                          │ OIDC + IAM   │ │ NAT, S3    │ │ KMS, S3,     │
                          │ for dynamic  │ │ endpoint   │ │ CloudWatch   │
                          │ credentials  │ │            │ │              │
                          └──────────────┘ └────────────┘ └──────────────┘
```

| Layer | Repository | Working Directory | Purpose |
|-------|-----------|-------------------|---------|
| **L1 -- Bootstrap** | `openshift-online/infra-platform` | `hcp-terraform/tenants/rosa/` | Creates projects, teams, meta-workspaces, and policies |
| **L2 -- Meta-workspace** | `openshift-online/rosa-boundary` | `hcp-terraform/rosa-boundary/` | Creates and configures the workload workspaces |
| **L3 -- Workloads** | `openshift-online/rosa-boundary` | `deploy/network/`, `deploy/regional/`, `hcp-terraform/aws-creds/rosa-boundary-stage/` | Actual AWS infrastructure |

Changes cascade downward via run triggers: a successful apply at L1 triggers L2, and L2 triggers L3 workspaces.

---

## How a Code Change Becomes Live

### Infrastructure Changes (Terraform)

All three workload workspaces are VCS-connected to the `openshift-online/rosa-boundary` GitHub repository. The flow from code change to deployed infrastructure is:

1. **Open a PR** against `openshift-online/rosa-boundary` from an upstream branch (not a fork -- see note below).
2. **Speculative plan runs automatically** on any workspace whose `working_directory` contains changed files. HCP Terraform posts the plan output as a PR check.
3. **Review and merge** the PR through normal GitHub review.
4. **VCS trigger fires** on merge to `main`, queuing a plan on the affected workspace(s).
5. **Apply behavior** depends on the workspace:
   - `rosa-boundary-stage-network` and `rosa-boundary-stage-aws-creds`: **auto-apply** -- the plan applies automatically after a successful plan.
   - `rosa-boundary-stage-regional`: **manual apply** -- a team member must confirm the apply in the HCP Terraform UI. This is intentional because the regional workspace manages the production-path infrastructure (ECS, Lambda, IAM).

> **Fork PRs do not trigger speculative plans.** HCP Terraform only runs plans for PRs from branches on the connected repository (`openshift-online/rosa-boundary`), not from forks. External contributors must have their changes pushed to an upstream branch for speculative plans to run.

### Container Image Updates

The staging deployment references container images from Quay.io, built by Konflux:

- **rosa-boundary container**: `quay.io/redhat-user-workloads/rosa-tenant/rosa-boundary:<commit-sha>`
- **Lambda container**: `quay.io/redhat-user-workloads/rosa-tenant/create-investigation-lambda:<commit-sha>`

To deploy a new container image version:

1. Merge the container/Lambda code change to `main`. Konflux builds and pushes the image.
2. Update the image tag in `hcp-terraform/rosa-boundary/main.tf` (the `container_image`, `lambda_image_tag` variables in the `rosa-boundary-stage-regional` workspace definition).
3. Open a PR with the tag update. The speculative plan shows the ECS task definition or Lambda function changing.
4. Merge. The regional workspace queues a plan, and a team member confirms the apply.

### Workspace Definition Changes (L2)

Changes to workspace configuration itself (adding variables, changing auto-apply settings, adding new workspaces) are made in `hcp-terraform/rosa-boundary/main.tf`. These changes follow the same PR flow but execute against the `meta-rosa-rosa-boundary` workspace, which manages the workload workspaces via the HCP Terraform API.

---

## Workspaces

All workspaces live in the **`rosa-boundary`** project within the **`hp-platform-engineering`** HCP Terraform organization. They use **Terraform 1.15.8** and are connected to the `openshift-online/rosa-boundary` GitHub repository.

### rosa-boundary-stage-network

| Attribute | Value |
|-----------|-------|
| **Working directory** | `deploy/network/` |
| **Auto-apply** | Yes |
| **Purpose** | VPC, subnets, NAT gateway, S3 gateway endpoint |
| **Variable sets** | `rosa-boundary-rosa-boundary-stage-default-aws-dynamic-creds` |

Manages the network foundation for the staging account: a `/20` VPC (`10.80.0.0/20`) with two public and two private subnets across `us-east-1a` and `us-east-1b`, a single NAT gateway with a static Elastic IP (`54.243.179.5`), and an S3 gateway VPC endpoint. The private subnets are consumed by the regional workspace for ECS Fargate task placement.

### rosa-boundary-stage-aws-creds

| Attribute | Value |
|-----------|-------|
| **Working directory** | `hcp-terraform/aws-creds/rosa-boundary-stage/` |
| **Auto-apply** | Yes |
| **Purpose** | AWS OIDC provider and IAM roles for dynamic credentials |
| **Variable sets** | `rosa-boundary-tfe-creds`, `rosa-boundary-rosa-boundary-stage-default-aws-dynamic-creds` |

Creates the IAM OIDC provider for `app.terraform.io` and the plan/apply IAM roles that allow HCP Terraform workspaces to authenticate to AWS without static access keys. This workspace is self-managing -- it lists itself in its own role group so its own dynamic credentials grant it permission to manage the OIDC provider and roles.

This workspace additionally requires the `rosa-boundary-tfe-creds` variable set (a `TFE_TOKEN`) because it uses the `tfe` provider to create and manage the dynamic credentials variable set.

### rosa-boundary-stage-regional

| Attribute | Value |
|-----------|-------|
| **Working directory** | `deploy/regional/` |
| **Auto-apply** | No (manual confirmation required) |
| **Purpose** | Core infrastructure: ECS, EFS, Lambda, IAM, KMS, S3, CloudWatch |
| **Variable sets** | `rosa-boundary-rosa-boundary-stage-default-aws-dynamic-creds` |

The primary workload workspace. Deploys the ECS Fargate cluster, EFS filesystem, S3 audit bucket, Lambda functions (create-investigation, reap-tasks), IAM roles and policies, OIDC providers for user authentication, KMS keys, CloudWatch log groups, EventBridge rules, and security groups.

This workspace has `auto_apply = false` and `auto_apply_run_trigger = false`, meaning every apply requires manual confirmation in the HCP Terraform UI. This provides an explicit approval gate before changes reach the staging infrastructure.

### meta-rosa-rosa-boundary (L2)

| Attribute | Value |
|-----------|-------|
| **Project** | `meta-rosa` |
| **Working directory** | `hcp-terraform/rosa-boundary/` |
| **Purpose** | Creates and manages the three workload workspaces above |
| **Variable sets** | `rosa-admin-creds`, `rosa-notification-url` |

This is the meta-workspace (L2). It uses the private `terraform-tfe-workspaces` module to declaratively manage the workload workspaces, their VCS connections, variable assignments, and variable set attachments. Changes to this workspace propagate to workload workspaces via run triggers.

---

## AWS Dynamic Credentials

HCP Terraform authenticates to the `rosa-boundary-stage` AWS account (`150100906299`) using OIDC federation -- no static AWS access keys are stored anywhere.

### How It Works

1. An IAM OIDC provider in the AWS account trusts `app.terraform.io` as an identity provider.
2. Dedicated IAM roles (`plan` and `apply`) have trust policies scoped to the specific HCP Terraform organization, project, and workspace, and further restricted by run phase (`plan` or `apply`).
3. A variable set (`rosa-boundary-rosa-boundary-stage-default-aws-dynamic-creds`) containing `TFC_AWS_PROVIDER_AUTH=true`, `TFC_AWS_PLAN_ROLE_ARN`, and `TFC_AWS_APPLY_ROLE_ARN` is attached to all three workload workspaces.
4. The AWS Terraform provider automatically reads these environment variables and authenticates via `sts:AssumeRoleWithWebIdentity` -- no changes needed in workload Terraform code.

The plan role defaults to `ReadOnlyAccess` and the apply role defaults to `AdministratorAccess`.

### Configuration

The dynamic credentials setup is defined in `hcp-terraform/aws-creds/rosa-boundary-stage/main.tf` using the private `terraform-tfe-aws-dynamic-creds` module:

```hcl
module "aws_dynamic_creds" {
  source  = "app.terraform.io/hp-platform-engineering/aws-dynamic-creds/tfe"
  version = "0.0.15"

  organization     = "hp-platform-engineering"
  aws_account_name = "rosa-boundary-stage"

  role_groups = {
    default = {
      projects = {
        rosa-boundary = {
          workspace_names = [
            "rosa-boundary-stage-aws-creds",
            "rosa-boundary-stage-network",
            "rosa-boundary-stage-regional",
          ]
        }
      }
    }
  }
}
```

To grant dynamic credentials to a new workspace, add it to the `workspace_names` list and apply.

---

## User Access

### SSO Login

The `hp-platform-engineering` HCP Terraform organization uses **Red Hat SSO** (`auth.redhat.com`) for authentication. Team membership is assigned automatically based on Rover group membership via the SAML `Role` attribute.

To log in:

1. Go to [app.terraform.io](https://app.terraform.io)
2. Click **Sign in with SSO**
3. Enter organization name: `hp-platform-engineering`
4. Authenticate with Red Hat credentials

### Team Access

The `ai-sd-sre` team is created by the L1 bootstrap configuration. Anyone in the `ai-sd-sre` Rover group who logs in via SSO is automatically added to the HCP Terraform `ai-sd-sre` team.

The team has `admin` access to:

| Scope | Access Level |
|-------|-------------|
| `rosa-bootstrap` workspace (L1) | Admin |
| `meta-rosa` project (contains L2 meta-workspace) | Admin |
| `rosa-boundary` project (contains L3 workload workspaces) | Admin |

Admin access allows viewing and triggering runs, modifying variables, managing workspace settings, and confirming applies.

### Re-login After Changes

HCP Terraform caches team and project memberships at SSO login time. If new projects or workspaces are created, users must **log out and log back in** for their session to pick up the new access.

### CLI Authentication

For local Terraform operations that need access to the private module registry (validation, lock file generation):

```bash
terraform login app.terraform.io
```

This opens a browser for SSO authentication and stores a token in `~/.terraform.d/credentials.tfrc.json`.

---

## Workspace Variables

Workspace variables for the staging deployment are defined as code in `hcp-terraform/rosa-boundary/main.tf`, not set manually in the HCP Terraform UI. This keeps variable values version-controlled and reviewable through PRs.

### rosa-boundary-stage-regional Variables

| Variable | Value | Notes |
|----------|-------|-------|
| `aws_account_id` | `150100906299` | Provider deployment guard |
| `aws_region` | `us-east-1` | |
| `stage` | `stage` | |
| `vpc_id` | `vpc-008ef33919b443f10` | From network workspace |
| `subnet_ids` | `["subnet-0042826174855e520", "subnet-0f9392e3159168d6f"]` | Private subnets from network workspace |
| `container_image` | `quay.io/redhat-user-workloads/rosa-tenant/rosa-boundary:<sha>` | Konflux-built, pinned to commit SHA |
| `keycloak_issuer_url` | `https://auth.redhat.com/auth/realms/EmployeeIDP` | Red Hat SSO (EmployeeIDP) |
| `keycloak_thumbprint` | *(sensitive)* | SHA1 thumbprint of IdP TLS certificate |
| `required_groups` | `["ai-sd-sre"]` | OIDC groups authorized to create investigations |
| `abac_tag_key` | `uuid` | ECS task tag key for ABAC isolation |
| `lambda_package_type` | `Image` | Container image packaging (required for HCP Terraform remote execution) |
| `lambda_image_repository` | `redhat-user-workloads/rosa-tenant/create-investigation-lambda` | Quay repository path |
| `lambda_image_tag` | `<sha>` | Konflux-built, pinned to commit SHA |
| `default_tags` | *(account-specific)* | Organization-standard FinOps tags applied via provider `default_tags`; see [Externally Managed Tags and Settings](#externally-managed-tags-and-settings) |
| `ignored_tag_keys` | *(account-specific)* | Tag keys excluded from Terraform reconciliation; see [Externally Managed Tags and Settings](#externally-managed-tags-and-settings) |
| `log_retention_days` | *(account-specific)* | Must match the retention enforced by the account's external integrations |

### rosa-boundary-stage-network

| Variable | Value | Notes |
|----------|-------|-------|
| `default_tags` | *(account-specific)* | Organization-standard FinOps tags applied via provider `default_tags`; see [Externally Managed Tags and Settings](#externally-managed-tags-and-settings) |
| `ignored_tag_keys` | *(account-specific)* | Tag keys excluded from Terraform reconciliation; see [Externally Managed Tags and Settings](#externally-managed-tags-and-settings) |

Other variables use the defaults defined in `deploy/network/variables.tf`, which target the staging account (`150100906299`) and region (`us-east-1`) directly.

### rosa-boundary-stage-aws-creds

This workspace uses the defaults defined in its `variables.tf` and does not have additional variables set through the meta-workspace.

---

## Externally Managed Tags and Settings

AWS accounts managed through app-interface have external integrations (AppSRE, FinOps) that apply their own resource tags and enforce settings such as CloudWatch log retention. When Terraform is unaware of these externally managed values, it reports drift on every plan and attempts to reconcile them — removing tags it didn't apply or reverting enforced settings to their Terraform defaults.

The Terraform configurations (`deploy/regional/` and `deploy/network/`) handle this through three mechanisms, all controlled by workspace variables defined in the meta-workspace (`hcp-terraform/rosa-boundary/main.tf`):

### Provider Default Tags

The `default_tags` variable (`map(string)`, default `{}`) is passed to the AWS provider's `default_tags` block. Tags defined here are automatically applied to every AWS resource Terraform manages, without requiring per-resource tag assignments.

Use this for tags where Terraform is the **authoritative source** — tags this deployment owns and should enforce on every apply.

### Ignored Tag Keys

The `ignored_tag_keys` variable (`list(string)`, default `[]`) is passed to the AWS provider's `ignore_tags` block. Tag keys listed here are excluded from Terraform's reconciliation entirely — Terraform will not report drift for these tags and will not attempt to remove them.

Use this for tags that are managed by external systems (FinOps integrations, app-interface, AWS Config rules) or tags that do not yet have an authoritative value in this deployment.

### Enforced Settings

Some infrastructure-level settings (such as CloudWatch log retention) are enforced by the account's external integrations. When an enforced value differs from the Terraform variable default, the workspace variable must be set to match the externally enforced value. Otherwise, every plan will show drift as Terraform attempts to revert the setting.

These values are set as workspace variables in the meta-workspace alongside `default_tags` and `ignored_tag_keys`.

### Adding a New Environment

When onboarding a new AWS account or environment:

1. Identify which tags the account's external integrations apply to resources.
2. Determine which of those tags this deployment should own (`default_tags`) versus ignore (`ignored_tag_keys`).
3. Check whether settings like log retention are enforced at values different from the Terraform defaults, and set workspace variables accordingly.
4. After the meta-workspace applies the new variables, confirm the regional workspace plan shows no residual drift.

---

## Deletion Protection

All workspaces and projects are covered by a mandatory OPA (Open Policy Agent) policy named `rosa-deletion-protection`. This policy blocks `delete` actions on Terraform-managed resources unless a time-limited approval entry is added to the `_deletion_approvals` variable in `terraform.auto.tfvars`.

An approval entry requires:

- `address`: the full Terraform resource address being deleted (e.g., `module.vpc.aws_subnet.private[0]`)
- `expires_at`: an RFC 3339 timestamp after which the approval expires

The policy is scoped to the `meta-rosa` project, the `rosa-boundary` project, and the `rosa-bootstrap` workspace.

---

## Two-PR Pattern for New Workspaces

HCP Terraform requires that a VCS-connected workspace complete at least one run before it accepts webhook-triggered runs (including speculative plans on PRs). This means every new workspace follows a two-PR sequence:

1. **First PR**: Merge the working directory (even a minimal `terraform { required_version = "..." }`) to the default branch.
2. **Second PR**: Add the workspace definition pointing at that directory.

Without this, the workspace has nothing to plan against when it is first created, and subsequent PRs never receive speculative plans.

This pattern applies at every layer -- bootstrap workspaces, meta-workspaces, and workload workspaces.

---

## Key Differences from Local Development

| Aspect | Local (dev) | HCP Terraform (staging) |
|--------|-------------|------------------------|
| **Execution** | `make plan` / `make apply` from `deploy/regional/` | Remote execution in HCP Terraform |
| **State** | Local `.tfstate` or S3 backend | HCP Terraform remote state |
| **Variables** | `.env` + `terraform.tfvars` (gitignored) | Defined as code in `hcp-terraform/rosa-boundary/main.tf` |
| **AWS credentials** | Local AWS CLI profile or env vars | OIDC dynamic credentials via variable set |
| **Lambda packaging** | ZIP (built locally by `make apply` via `build-lambda`) | Container image from Quay (HCP Terraform cannot run local build scripts) |
| **Apply gate** | Immediate | Manual confirmation required for regional workspace |
| **Backend config** | `cloud.tf` or local state | Set externally by meta-workspace; no `cloud.tf` in workload directories |
| **Container image** | ECR (manually pushed) | Quay (Konflux pipeline, pinned by commit SHA) |

The `Makefile` and `.env` workflow in `deploy/regional/` remains a local-development convenience. HCP Terraform does not use them -- it runs `terraform init` and `terraform plan/apply` directly in the working directory with variables supplied through workspace configuration and variable sets.

---

## References

### Repository Paths

| Path | Purpose |
|------|---------|
| `hcp-terraform/rosa-boundary/main.tf` | L2 meta-workspace: workspace definitions, variables, VCS connections |
| `hcp-terraform/rosa-boundary/cloud.tf` | Points meta-workspace at `meta-rosa-rosa-boundary` |
| `hcp-terraform/aws-creds/rosa-boundary-stage/main.tf` | Dynamic credentials: OIDC provider, IAM roles, variable set |
| `deploy/network/` | L3: VPC, subnets, NAT, S3 endpoint |
| `deploy/regional/` | L3: ECS, EFS, Lambda, IAM, KMS, S3, CloudWatch |

### External References

| Resource | Location |
|----------|----------|
| HCP Terraform organization | [app.terraform.io/app/hp-platform-engineering](https://app.terraform.io/app/hp-platform-engineering) |
| L1 bootstrap (rosa tenant) | [infra-platform: `hcp-terraform/tenants/rosa/main.tf`](https://github.com/openshift-online/infra-platform/blob/main/hcp-terraform/tenants/rosa/main.tf) |
| Tenant onboarding guide | [infra-platform: `hcp-terraform/tenants/README.md`](https://github.com/openshift-online/infra-platform/blob/main/hcp-terraform/tenants/README.md) |
| Dynamic credentials guide | [infra-platform: `docs/aws-dynamic-creds.md`](https://github.com/openshift-online/infra-platform/blob/main/docs/aws-dynamic-creds.md) |
| SSO login guide | [infra-platform: `docs/hcp-terraform-sso.md`](https://github.com/openshift-online/infra-platform/blob/main/docs/hcp-terraform-sso.md) |
| AWS account (app-interface) | [app-interface: `data/aws/rosa-boundary-stage/account.yml`](https://gitlab.cee.redhat.com/service/app-interface/-/blob/master/data/aws/rosa-boundary-stage/account.yml) |
| Staging account access | `rh-aws-saml-login rh-control --assume-uid 150100906299` |

### Related Jira

| Key | Summary | Status |
|-----|---------|--------|
| [ROSAENG-61425](https://issues.redhat.com/browse/ROSAENG-61425) | T1: HCP Terraform tenant onboarding | Closed |
| [ROSAENG-61426](https://issues.redhat.com/browse/ROSAENG-61426) | T2: VPC stack and workspace configuration | Closed |
| [ROSAENG-61427](https://issues.redhat.com/browse/ROSAENG-61427) | T3: Deploy regional stack via HCP Terraform | Closed |
| [ROSAENG-61428](https://issues.redhat.com/browse/ROSAENG-61428) | T4: Validate backplane connectivity | Open |

# Deployment

## Overview

Infrastructure is split into two Terraform roots that must be applied in order:

| Root         | Path                  | Scope                                                                                                      | Apply cadence    |
|--------------|-----------------------|------------------------------------------------------------------------------------------------------------|------------------|
| **global**   | `terraform/global/`   | Account-wide: IAM, Secrets Manager, ACM validation CNAME                                                   | Once per account |
| **regional** | `terraform/regional/` | One deployment per AWS region: VPC, ALB, ECS, EC2, EBS, S3 bucket, CloudWatch, Route 53 PHZ, regional ACM certificate | Once per region  |

The regional root reads IAM ARNs, the Secrets Manager ARN, and the public
hosted zone ID directly from the global workspace's Terraform state via
`terraform_remote_state`. No values need to be copied by hand. The S3 bucket
is created directly in each regional workspace — `s3_bucket_name_suffix` must
match the value set in the global workspace so its IAM wildcard ARN covers
the bucket.

### Resource ownership and multi-region fan-out

```mermaid
flowchart LR
    subgraph GLOBAL["terraform/global — apply ONCE per AWS account"]
        direction TB
        IAM["IAM roles & policies<br/>ecs_instance, task, task_execution,<br/>cwl_to_firehose, firehose_audit_logs<br/><i>(task_app / firehose policies grant S3 access<br/>via wildcard ARN ACCOUNT-ENV-SUFFIX-*)</i>"]
        SECRETS["Secrets Manager secret<br/>ocm_client_secret, ocm_token,<br/>backplane_client_secret"]
        DNSG["ACM validation CNAME<br/>(public hosted zone, optional)"]
    end
    style GLOBAL fill:#e8f0fe,stroke:#4285f4

    subgraph R1["terraform/regional — workspace #1 (us-east-1)"]
        direction TB
        NET1["VPC, subnets, IGW, NAT,<br/>route tables, security groups"]
        ALB1["ALB + listeners + target group"]
        ECS1["ECS cluster, EC2 host + EBS volume,<br/>task definition, service"]
        S31["S3 bucket<br/>ACCOUNT-ENV-SUFFIX-us-east-1"]
        AUDIT1["CloudWatch log group → Firehose<br/>→ S3 (audit-logs/)"]
        DNS1["Private Hosted Zone +<br/>regional ACM certificate"]
    end
    style R1 fill:#e6f4ea,stroke:#34a853

    subgraph R2["terraform/regional — workspace #2 (eu-central-1)<br/>same code, new HCP workspace + tfvars"]
        direction TB
        NET2["VPC, subnets, IGW, NAT,<br/>route tables, security groups"]
        ALB2["ALB + listeners + target group"]
        ECS2["ECS cluster, EC2 host + EBS volume,<br/>task definition, service"]
        S32["S3 bucket<br/>ACCOUNT-ENV-SUFFIX-eu-central-1"]
        AUDIT2["CloudWatch log group → Firehose<br/>→ S3 (audit-logs/)"]
        DNS2["Private Hosted Zone +<br/>regional ACM certificate"]
    end
    style R2 fill:#e6f4ea,stroke:#34a853

    R3["workspace #N …<br/>new region = new tfvars + HCP workspace,<br/>no global re-apply needed"]
    style R3 fill:#fef7e0,stroke:#f9ab00

    GLOBAL -. "terraform_remote_state<br/>(IAM ARNs, secret ARN)" .-> R1
    GLOBAL -. "terraform_remote_state<br/>(IAM ARNs, secret ARN)" .-> R2
    GLOBAL -. "terraform_remote_state" .-> R3
    IAM -. "wildcard ARN covers<br/>every region's bucket" .-> S31
    IAM -. "wildcard ARN covers<br/>every region's bucket" .-> S32
```

- **Blue (global)** — created once, shared by every region: IAM roles/policies,
  the app secret, and (optionally) the ACM validation CNAME.
- **Green (regional)** — created per region: networking, ALB, ECS compute, the
  region's own S3 bucket, the Firehose audit-log pipeline, and DNS/TLS.
- **Yellow** — adding region N+1 only touches `terraform/regional`: a new
  tfvars file / HCP Terraform workspace. `global` is never re-applied — its
  IAM wildcard ARN (`ACCOUNT-ENVIRONMENT-SUFFIX-*`) already covers any
  region's bucket by construction.

See [docs/networking.md](networking.md) for the DNS and TLS architecture.

---

## Table of Contents

1. [HCP Terraform (CI/CD)](#hcp-terraform-cicd)
2. [Local Testing](#local-testing)
3. [Verification](#verification)
4. [Adding a New Region](#adding-a-new-region)

---

## HCP Terraform (CI/CD)

The existing workspaces are managed by the Boundary repository's
[`hcp-terraform/rosa-trusted-actions/main.tf`](../../../hcp-terraform/rosa-trusted-actions/main.tf).
The meta-workspace and both workload workspaces were rebound in place from the
archived Trusted Actions repository. Inspect the current Git-managed settings
**and live HCP runs/settings** before planning or approving changes: the
cutover temporarily set `auto_apply` and `auto_apply_run_trigger` to `false`,
then [restored both to `true`](https://github.com/openshift-online/rosa-boundary/pull/517)
after successful workspace runs. Do not assume an old runbook describes
today's apply gate; the first meta cutover run auto-applied unexpectedly.

### Workspace summary

| Workspace                     | Working directory    | Must apply before       |
|-------------------------------|----------------------|-------------------------|
| `rosa-trusted-actions-global` | `components/trusted-actions/terraform/global`   | all regional workspaces |
| `rosa-trusted-actions-stage`  | `components/trusted-actions/terraform/regional` | —                       |

### Apply order

```
1. rosa-trusted-actions-global   (creates S3, IAM, Secrets, CNAME)
         │
         └─ run trigger fires automatically
                  ↓
2. rosa-trusted-actions-stage    (reads global outputs via remote state)
```

The `source_workspaces` setting queues a stage run after a successful global
apply. Whether that queued run applies automatically depends on the current
`auto_apply_run_trigger` setting and effective HCP configuration. The global
workspace permits the stage workspace to read its remote state via
`remote_state_consumer_workspaces`. Review global and stage plans separately;
the meta plan alone does not establish whether AWS resources will change.

### Workspace variables

The [workspace definitions](../../../hcp-terraform/rosa-trusted-actions/main.tf)
are the source of truth for Git-managed stage variables. In particular, the
stage workspace now supplies the complete `app_config` file rather than only
individual Backplane/OCM settings. Both workspaces have AWS dynamic credential
attachments and the global workspace shares state with stage. Keep sensitive
credentials in approved sensitive variables/variable sets; never commit them
or edit the Git-managed workspace variables directly in HCP. Regional IAM
ARNs and the Secrets Manager ARN come from global remote state. The regional
workspace owns its own S3 bucket.

---

## Local Testing

For testing against an AWS account directly (without HCP Terraform), each root
is applied with the Terraform CLI using a local state backend. The only
complication is that `terraform/regional/remote_state.tf` points to the HCP
Terraform remote backend by default. Terraform's **override file** feature
solves this without touching any source file: a gitignored
`local_override.tf` placed in `terraform/regional/` replaces the remote
backend with a local one that reads from the global state file on disk.

### Step 1 — apply global

```bash
cd terraform/global

terraform init

terraform apply \
  -var="aws_region=us-east-1" \
  -var="environment=stage" \
  -var="s3_bucket_name_suffix=rosa-trusted-actions" \
  -var="internal_fqdn=rosa-trusted-actions.internal.company.com" \
  -var="backplane_client_secret=$BACKPLANE_CLIENT_SECRET" \
  -var="ocm_client_secret=$OCM_CLIENT_SECRET" \
  -var="ocm_token=$OCM_TOKEN"
```

Or use a var-file (never commit secrets):

```hcl
# terraform/global/terraform.tfvars  (gitignored)
aws_region            = "us-east-1"
environment           = "stage"
s3_bucket_name_suffix = "rosa-trusted-actions"
internal_fqdn         = "rosa-trusted-actions.internal.company.com"
```

```hcl
# $HOME/.config/rosa-ta/secrets.tfvars  (outside the repo)
backplane_client_secret = "..."
ocm_client_secret       = "..."
ocm_token               = "..."
```

```bash
terraform apply \
  -var-file=terraform.tfvars \
  -var-file=$HOME/.config/rosa-ta/secrets.tfvars
```

### Step 2 — create the regional override file

Create this file **once** on your machine. It is gitignored and never
committed. It overrides the `data "terraform_remote_state" "global"` block in
`remote_state.tf` to use the local state file produced by Step 1 instead of
the HCP Terraform remote backend.

```hcl
# terraform/regional/local_override.tf — LOCAL TESTING ONLY. Gitignored.
data "terraform_remote_state" "global" {
  backend = "local"
  config = {
    path = "../global/terraform.tfstate"
  }
}
```

### Step 3 — apply regional

```bash
cd ../regional

terraform init

terraform apply \
  -var="aws_region=us-east-1" \
  -var="environment=stage" \
  -var="s3_bucket_name_suffix=rosa-trusted-actions" \
  -var="vpc_id=vpc-008ef33919b443f10" \
  -var='private_subnet_ids=["subnet-0042826174855e520","subnet-0f9392e3159168d6f"]' \
  -var='public_subnet_ids=["subnet-01821c41d92b0f8b1","subnet-0f52e06526c080dfa"]' \
  -var="container_image=quay.io/redhat-user-workloads/rosa-tenant/rosa-trusted-actions@sha256:<digest>" \
  -var="backplane_url=https://api.stage.backplane.openshift.com" \
  -var="backplane_client_id=trusted-actions" \
  -var="internal_fqdn=rosa-trusted-actions.internal.company.com"
```

Or with var-files:

```hcl
# terraform/regional/terraform.tfvars  (gitignored)
aws_region            = "us-east-1"
environment           = "stage"
s3_bucket_name_suffix = "rosa-trusted-actions"
vpc_id                = "vpc-008ef33919b443f10"
private_subnet_ids    = ["subnet-0042826174855e520", "subnet-0f9392e3159168d6f"]
public_subnet_ids     = ["subnet-01821c41d92b0f8b1", "subnet-0f52e06526c080dfa"]
container_image       = "quay.io/redhat-user-workloads/rosa-tenant/rosa-trusted-actions@sha256:<digest>"
backplane_url         = "https://api.stage.backplane.openshift.com"
backplane_client_id   = "trusted-actions"
internal_fqdn         = "rosa-trusted-actions.internal.company.com"
```

```bash
terraform apply -var-file=terraform.tfvars
```

### How the override works

Terraform processes files ending in `_override.tf` after all other files in
the directory and merges their blocks on top. A `data` block with the same
type and name as one in a regular file **completely replaces** it. The source
file `remote_state.tf` is never modified — the override exists only in the
local working copy and is gitignored.

```
remote_state.tf          →  data "terraform_remote_state" "global" { backend = "remote" ... }
local_override.tf        →  data "terraform_remote_state" "global" { backend = "local"  ... }
                                                                      ↑ wins at apply time
```

### Teardown

Destroy regional before global (global owns IAM roles that regional's ECS
tasks depend on at runtime).

```bash
cd terraform/regional && terraform destroy -var-file=terraform.tfvars
cd ../global          && terraform destroy \
  -var-file=terraform.tfvars \
  -var-file=$HOME/.config/rosa-ta/secrets.tfvars
```

---

## Verification

```bash
# From terraform/regional/ after apply
cd terraform/regional

# Tasks running
aws ecs list-tasks \
  --cluster rosa-trusted-actions \
  --region us-east-1 \
  --query 'taskArns'

# Health check — must be run from inside the VPC (bastion, SSM session, or ECS exec)
curl $(terraform output -raw internal_fqdn)/health
# {"status":"healthy","version":"..."}

# Container logs
aws logs filter-log-events \
  --log-group-name "$(terraform output -raw cloudwatch_log_group)" \
  --region us-east-1 \
  --filter-pattern "started"
```

---

## Adding a New Region

1. Reuse the existing global workspace and review its output/state sharing;
   its IAM policy covers regional buckets by name. Do not create a duplicate
   global stack for each region.

2. Create a new HCP Terraform workspace entry in
   `hcp-terraform/rosa-trusted-actions/main.tf` following the
   `rosa-trusted-actions-stage` block. Set `working_directory =
   "components/trusted-actions/terraform/regional"` and provide the
   region-specific variables, including `app_config`.

3. Add the new workspace name to the global definition's
   `remote_state_consumer_workspaces` so it can read global remote state.

4. Set the new workspace's `source_workspaces` to the global workspace.

5. Review the resulting HCP plans and effective apply settings with the
   deployment owners before applying. `terraform_remote_state` then reads
   the global outputs.

For local testing of the new region, follow the [Local Testing](#local-testing)
steps with the appropriate `aws_region`, `vpc_id`, and subnet variables for
that region. The same `local_override.tf` file works unchanged — it points to
the shared `terraform/global/terraform.tfstate` regardless of which region is
being tested.

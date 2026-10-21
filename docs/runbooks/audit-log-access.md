# Audit Log Access for Boundary Investigations

## Overview

This runbook explains how to access rosa-boundary audit logs stored in S3 without requiring
administrator credentials. Audit logs include CloudWatch session logs and workspace artifacts
synced from EFS after each investigation task stops.

## Access Model

Audit access is controlled by the `rosa-boundary-audit-reader` IAM role, which provides:

- **Read-only S3 access** to investigation artifacts across all regions
- **No admin permissions** to the AWS account
- **Scoped to rosa-boundary buckets** following the pattern `{account-id}-rosa-boundary-{env}-*`

Available environments:
- **Stage**: Account 150100906299 (`rosa-boundary-stage`)
- **Production**: Account 514903006123 (`rosa-boundary-prod`)

## Prerequisites

1. **Kerberos ticket**: Run `kinit` to obtain a valid ticket
2. **rh-aws-saml-login**: Installed and configured (available from internal tooling)
3. **AWS CLI**: Installed for S3 operations

## Add Yourself to the Audit Reader Role

Access is granted through explicit user assignment in `app-interface`. To add yourself:

### 1. Find Your User File

User files are located at `data/teams/{team}/users/{kerberos-id}.yml` in the `app-interface` repository.

Common team directories:
- `data/teams/sd-sre/users/` — SD-SRE team members
- `data/teams/ocm/users/` — OCM team members

Example: If your Kerberos ID is `jdoe` and you're on the OCM team, your file is:
```
data/teams/ocm/users/jdoe.yml
```

### 2. Add the Role Reference

Edit your user file and add the role reference under `roles`:

```yaml
---
$schema: /access/user-1.yml
labels:
  github_username: <your-github>
name: <Your Name>
org_username: jdoe
roles:
  # ... existing roles ...
  - $ref: /teams/sd-sre/roles/rosa-boundary-audit-reader.yml
```

### 3. Create a Merge Request

```bash
cd /path/to/app-interface
git checkout -b add-audit-access-jdoe
# Make the changes to your user file
git add data/teams/ocm/users/jdoe.yml
git commit -m "Add rosa-boundary-audit-reader role to jdoe"
git push origin add-audit-access-jdoe
```

Open the MR in GitLab and wait for:
- **IC Review** approval
- **AppSRE** merge

### 4. Wait for Reconciliation

After the MR merges, `qontract-reconcile` will provision the IAM role assignments.
This typically takes a few minutes. You can test access immediately after reconciliation completes.

## Authenticate to AWS

### Stage Environment

```bash
rh-aws-saml-login rosa-boundary-stage/150100906299-rosa-boundary-audit-reader
```

### Production Environment

```bash
rh-aws-saml-login rosa-boundary-prod/514903006123-rosa-boundary-audit-reader
```

**Important**: Do **not** use the `--assume-uid` flag with these scoped roles. That flag is for
administrator access patterns and will fail with AccessDenied.

## Retrieve Audit Logs

### List Investigations for a Cluster

```bash
CLUSTER_ID="rosa-stage-01"
REGION="us-east-1"
ACCOUNT="150100906299"
ENV="stage"
BUCKET="${ACCOUNT}-rosa-boundary-${ENV}-${REGION}"

# List all investigations for this cluster
aws s3 ls "s3://${BUCKET}/${CLUSTER_ID}/" --region "${REGION}"
```

### List Tasks for an Investigation

```bash
INVESTIGATION_ID="INC-12345"

# List all task snapshots (grouped by date/task-id)
aws s3 ls "s3://${BUCKET}/${CLUSTER_ID}/${INVESTIGATION_ID}/" --recursive --region "${REGION}"
```

### Download Bash History

```bash
TASK_ID="14e118838eaa4780968abbb4e4bef749"
DATE="20261021"  # YYYYMMDD format

# View bash history inline
aws s3 cp "s3://${BUCKET}/${CLUSTER_ID}/${INVESTIGATION_ID}/${DATE}/${TASK_ID}/.bash_history" - \
  --region "${REGION}"
```

### Download All Artifacts for an Investigation

```bash
# Sync to local directory
mkdir -p ~/audit-review/${INVESTIGATION_ID}
aws s3 sync "s3://${BUCKET}/${CLUSTER_ID}/${INVESTIGATION_ID}/" \
  ~/audit-review/${INVESTIGATION_ID}/ \
  --region "${REGION}"
```

## Artifact Structure

Investigation artifacts are stored in S3 with the following path pattern:

```
s3://{account-id}-rosa-boundary-{env}-{region}/{cluster-id}/{investigation-id}/{YYYYMMDD}/{task-id}/
```

Example:
```
s3://150100906299-rosa-boundary-stage-us-east-1/rosa-stage-01/INC-12345/20261021/14e118838eaa4780968abbb4e4bef749/
├── .bash_history
├── .profile
├── workspace/
│   ├── notes.txt
│   └── investigation-data/
└── logs/
```

**Note**: Credential mounts (`.config/ocm` and `.kube`) are **excluded** from S3 sync and will
not appear in audit artifacts.

## CloudWatch Session Logs

CloudWatch session logs are **not** accessible with the audit reader role. To access session logs,
you need separate CloudWatch Logs read permissions. Contact your team's AWS administrator to
request access if needed.

Session logs are stored in:
- SSM session log group: Configured per deployment
- Container log group: Configured per deployment

Obtain the exact log group names from the deployment's Terraform outputs or regional README.

## Complete Example Workflow

```bash
# 1. Authenticate to stage
rh-aws-saml-login rosa-boundary-stage/150100906299-rosa-boundary-audit-reader

# 2. Set variables
export AWS_ACCOUNT="150100906299"
export ENV="stage"
export REGION="us-east-1"
export CLUSTER_ID="rosa-stage-01"
export INVESTIGATION_ID="INC-12345"
export BUCKET="${AWS_ACCOUNT}-rosa-boundary-${ENV}-${REGION}"

# 3. List all artifacts for the investigation
aws s3 ls "s3://${BUCKET}/${CLUSTER_ID}/${INVESTIGATION_ID}/" --recursive --region "${REGION}"

# 4. Identify the task ID and date from the output
export TASK_ID="14e118838eaa4780968abbb4e4bef749"
export DATE="20261021"

# 5. Preview bash history
aws s3 cp "s3://${BUCKET}/${CLUSTER_ID}/${INVESTIGATION_ID}/${DATE}/${TASK_ID}/.bash_history" -

# 6. Download all artifacts locally
mkdir -p ~/audit-review/${INVESTIGATION_ID}
aws s3 sync "s3://${BUCKET}/${CLUSTER_ID}/${INVESTIGATION_ID}/" \
  ~/audit-review/${INVESTIGATION_ID}/ \
  --region "${REGION}"

# 7. Review artifacts
ls -la ~/audit-review/${INVESTIGATION_ID}/
```

## Multi-Region Access

The audit reader role grants access to buckets in all AWS regions where rosa-boundary is deployed:

- `us-east-1` (US East - N. Virginia)
- `us-east-2` (US East - Ohio)
- `us-west-1` (US West - N. California)
- `us-west-2` (US West - Oregon)

Always specify the `--region` flag matching the bucket's region. If unsure, check with the
cluster operator or try the primary region (`us-east-1`) first.

## Retention and Security

- **Retention**: Audit artifacts follow the deployment's retention policy (consult your security team)
- **Access logs**: All S3 access is logged via CloudTrail
- **Downloaded artifacts**: Protect local copies according to your organization's data handling policies
- **Sensitive data**: Audit logs may contain cluster identifiers, investigation IDs, and command history
  - Do not share outside authorized personnel
  - Store downloaded artifacts on encrypted volumes
  - Delete local copies when audit is complete

## Related Documentation

- [Investigation Workflow](investigation-workflow.md) — Creating and managing investigations
- [User Access Guide](user-access-guide.md) — Initial CLI setup and configuration
- [AWS IAM Policies](../configuration/aws-iam-policies.md) — IAM policy details

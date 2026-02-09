# ROSA Boundary Regional Infrastructure

Terraform configuration for deploying ROSA Boundary container infrastructure on AWS Fargate, including S3 audit storage with WORM compliance, EFS persistent storage, and IAM roles with Bedrock access.

## Prerequisites

- **Terraform** >= 1.5
- **AWS CLI** configured with appropriate credentials
- **VPC** with at least 2 subnets (for high availability)
- **Container image** pushed to a container registry (ECR, Docker Hub, etc.)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      AWS Account                        │
│                                                         │
│  ┌────────────┐    ┌──────────────┐   ┌─────────────┐ │
│  │ ECS Cluster│───>│ Fargate Task │<──│ ECS Exec    │ │
│  └────────────┘    └──────┬───────┘   │ (SSM)       │ │
│                           │            └─────────────┘ │
│                           │                             │
│            ┌──────────────┼──────────────┐              │
│            │              │              │              │
│            ▼              ▼              ▼              │
│      ┌─────────┐    ┌─────────┐   ┌──────────┐        │
│      │   EFS   │    │   S3    │   │ Bedrock  │        │
│      │/home/sre│    │ Audit   │   │(Claude)  │        │
│      └─────────┘    └─────────┘   └──────────┘        │
│      (persistent)   (WORM mode)    (AI)                │
└─────────────────────────────────────────────────────────┘
```

## Resources Created

- **S3 Bucket**: WORM-compliant audit bucket for investigation artifacts
- **EFS Filesystem**: Encrypted persistent storage for `/home/sre`
- **ECS Cluster**: Fargate cluster with Container Insights
- **ECS Task Definition**: Complete task definition with EFS mount
- **IAM Roles**: Execution role and task role with Bedrock, S3, ECS Exec permissions
- **Security Groups**: For Fargate tasks and EFS mount targets
- **CloudWatch Log Group**: For container logs

## Quick Start

### 1. Setup Infrastructure

```bash
# Copy the example configuration
cp terraform.tfvars.example terraform.tfvars

# Edit terraform.tfvars with your VPC ID, subnets, and container image
vi terraform.tfvars

# Initialize and apply Terraform
terraform init
terraform plan
terraform apply
```

### 2. Push Container Image to ECR

```bash
# Create ECR repository (if not exists)
aws ecr create-repository --repository-name rosa-boundary

# Login to ECR
aws ecr get-login-password --region us-east-2 | \
  podman login --username AWS --password-stdin YOUR_ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com

# Tag and push image
podman tag rosa-boundary:latest-amd64 YOUR_ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com/rosa-boundary:latest
podman push YOUR_ACCOUNT_ID.dkr.ecr.us-east-2.amazonaws.com/rosa-boundary:latest

# Update terraform.tfvars with ECR image URI and re-apply
terraform apply
```

### 3. Investigation Lifecycle Management

Use the Lambda-based OIDC workflow for investigation creation:

```bash
cd ../../tools/

# Create investigation with OIDC authentication
./create-investigation-lambda.sh <cluster-id> <investigation-id> [oc-version]

# Example
./create-investigation-lambda.sh rosa-prod-abc inv-12345 4.18

# The script will:
# 1. Authenticate via Keycloak (browser popup)
# 2. Call Lambda to create investigation
# 3. Assume role with tag-based permissions
# 4. Wait for task to be running
# 5. Display connection command
```

See [`tools/sre-auth/README.md`](../../tools/sre-auth/README.md) for authentication details and [Investigation Lifecycle](#investigation-lifecycle) below for architecture.

## Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `project` | string | `"rosa-boundary"` | Project name for resource naming |
| `stage` | string | `"dev"` | Environment stage (dev, staging, prod) |
| `retention_days` | number | `90` | S3 object lock retention period (1-3650 days) |
| `container_image` | string | **required** | Container image URI |
| `container_cpu` | number | `512` | Fargate CPU units (256, 512, 1024, 2048, 4096) |
| `container_memory` | number | `1024` | Fargate memory in MB (512-30720) |
| `vpc_id` | string | **required** | VPC ID for Fargate tasks |
| `subnet_ids` | list(string) | **required** | Subnet IDs (minimum 2 for HA) |
| `log_retention_days` | number | `7` | CloudWatch log retention period |
| `tags` | map(string) | `{}` | Additional tags for resources |

## Outputs

| Output | Description |
|--------|-------------|
| `bucket_name` | S3 audit bucket name |
| `bucket_arn` | S3 audit bucket ARN |
| `ecs_cluster_name` | ECS cluster name |
| `ecs_cluster_arn` | ECS cluster ARN |
| `task_definition_arn` | ECS task definition ARN |
| `task_definition_family` | ECS task definition family name |
| `task_role_arn` | ECS task IAM role ARN |
| `execution_role_arn` | ECS execution IAM role ARN |
| `efs_filesystem_id` | EFS filesystem ID |
| `efs_access_point_id` | EFS access point ID |
| `security_group_id` | Fargate security group ID |
| `efs_security_group_id` | EFS security group ID |
| `cloudwatch_log_group` | CloudWatch log group name |

## Investigation Lifecycle

The infrastructure uses a per-investigation isolation model with EFS access points and dedicated task definitions.

### Path Structure

- **EFS**: `/$cluster_id/$investigation_id/` → Mounted to `/home/sre` in container
- **S3**: `s3://bucket/$cluster_id/$investigation_id/$date/$task_id/`

**Example:**
- EFS: `/rosa-prod-abc/INV-12345/` (shared across all tasks for this investigation)
- S3: `s3://bucket/rosa-prod-abc/INV-12345/20251215/d0910f05.../` (unique per task)

### Lambda-Based Workflow

The recommended workflow uses OIDC authentication and Lambda for investigation creation:

1. **Authenticate**: User authenticates via Keycloak (browser PKCE flow)
2. **Create Investigation**: Lambda validates token, creates IAM role, EFS access point, and task
3. **Assume Role**: Script assumes returned role with tag-based permissions
4. **Connect**: User connects to running task via ECS Exec

See [`tools/create-investigation-lambda.sh`](../../tools/create-investigation-lambda.sh) for the end-to-end script.

### Connecting to Running Tasks

Use `tools/join-investigation.sh` to connect to existing tasks:

```bash
cd ../../tools/

# Join by task ID
./join-investigation.sh <task-id>
```

**Inside the container (as sre user):**
```bash
whoami                    # sre
pwd                       # /home/sre
claude --version          # 2.0.69
oc version --client       # 4.18.x (locked to investigation)
echo $CLUSTER_ID          # rosa-prod-abc
echo $INVESTIGATION_ID    # INV-12345

# Do your investigation work
# All files in /home/sre persist to EFS
```

**What happens during investigation:**
1. All files in `/home/sre` persist to EFS
2. Isolated workspace per investigation
3. OC version locked to investigation specification

**S3 Path Example:**
```
s3://641875867446-rosa-boundary-dev-us-east-2/rosa-prod-abc/INC-12345/20251215/d0910f05.../
```

### Stopping Tasks

Tasks can be stopped with the AWS CLI:

```bash
# Stop task (triggers S3 sync via entrypoint signal handler)
aws ecs stop-task \
  --cluster rosa-boundary-dev \
  --task <task-id> \
  --reason "Investigation complete"
```

The container's entrypoint script traps SIGTERM and syncs `/home/sre` to S3 before exit.

### Cleanup

Investigation cleanup requires manual deletion of resources:

```bash
# 1. List and stop any running tasks
aws ecs list-tasks --cluster rosa-boundary-dev --family <task-family>
aws ecs stop-task --cluster rosa-boundary-dev --task <task-id>

# 2. Deregister task definition revisions
aws ecs list-task-definitions --family-prefix <task-family>
aws ecs deregister-task-definition --task-definition <task-definition-arn>

# 3. Delete EFS access point
aws efs delete-access-point --access-point-id <fsap-id>
```

**Note:** EFS data remains on the filesystem. S3 data is retained per WORM policy.

---

## SSM Session Logging

All ECS Exec sessions are automatically streamed to CloudWatch Logs in real-time with KMS encryption.

### Session Log Structure

```
CloudWatch Log Group: /ecs/rosa-boundary-dev/ssm-sessions
  Log Streams: ecs-execute-command-<SESSION_ID>
    - Real-time command I/O capture
    - Session metadata in log events
```

### What's Logged

- **All commands typed** by the user
- **All command output** (stdout/stderr)
- **Session metadata**: Start time, end time, user identity, task ID
- **Encrypted with KMS** in transit and at rest

### Separate from Container Audit

SSM session logs capture real-time terminal activity, while container audit sync captures final state:

| Location | Content | When Captured |
|----------|---------|---------------|
| `/ecs/.../ssm-sessions` (CloudWatch) | Terminal I/O transcript | Real-time streaming during session |
| `$cluster/$investigation/$date/$taskid/` (S3) | `/home/sre` directory | On container exit |

### Viewing Session Logs

```bash
# List recent log streams
aws logs describe-log-streams \
  --log-group-name "/ecs/rosa-boundary-dev/ssm-sessions" \
  --order-by LastEventTime --descending \
  --max-items 10

# View session logs (real-time streaming)
aws logs tail "/ecs/rosa-boundary-dev/ssm-sessions" --follow

# Get logs for specific session
aws logs get-log-events \
  --log-group-name "/ecs/rosa-boundary-dev/ssm-sessions" \
  --log-stream-name "ecs-execute-command-<SESSION_ID>"

# Filter logs by time range
aws logs filter-log-events \
  --log-group-name "/ecs/rosa-boundary-dev/ssm-sessions" \
  --start-time $(date -d '1 hour ago' +%s)000
```

### Privacy Note

Session logs contain complete terminal output including any credentials or sensitive data typed during the session. Review logs before sharing.

---

## Environment Variables

### Automatically Set (by Lambda or task definition)

- `CLUSTER_ID` - ROSA cluster identifier
- `INVESTIGATION_ID` - Investigation tracking ID
- `OC_VERSION` - OpenShift CLI version (locked per investigation)
- `S3_AUDIT_BUCKET` - S3 bucket name for audit logs
- `CLAUDE_CODE_USE_BEDROCK=1` - Enable Claude Code via Bedrock

### Auto-Detected at Runtime

- `AWS_REGION` - Detected from ECS task metadata

### Optional Manual Overrides

- `S3_AUDIT_ESCROW` - Override auto-generated S3 path
- `AWS_CLI` - AWS CLI variant (`fedora` or `official`)

## S3 Bucket WORM Compliance

The S3 bucket is configured with **Object Lock in Compliance mode**:

- **Retention period**: Configurable via `retention_days` variable
- **Mode**: COMPLIANCE (cannot be deleted before retention expires)
- **Versioning**: Required and enabled
- **Encryption**: AES256 server-side encryption
- **Public access**: Blocked

**Important**: Once an object is written, it cannot be deleted or modified until the retention period expires, even by the root account.

## EFS Persistent Storage

The EFS filesystem provides persistent storage for `/home/sre`:

- **Encryption**: At rest encryption enabled
- **Performance**: General Purpose mode with bursting throughput
- **Access Point**: Configured for sre user (uid=1000, gid=1000)
- **Lifecycle**: Transitions to Infrequent Access after 30 days
- **Mount path**: `/home/sre` in the container

Claude Code configuration and investigation artifacts persist across task restarts when using the same EFS filesystem.

## IAM Permissions

### Task Execution Role

Used by ECS to pull images and write logs:

- `AmazonECSTaskExecutionRolePolicy` (AWS managed)
- Secrets Manager read access (for future token injection)

### Task Role

Used by the container at runtime:

- **S3**: Write access to the audit bucket
- **Bedrock**: InvokeModel, InvokeModelWithResponseStream, ListInferenceProfiles
- **SSM**: ECS Exec permissions for interactive access

## Connecting to Running Tasks

### Direct Connection

```bash
# List running tasks
aws ecs list-tasks --cluster rosa-boundary-dev --desired-status RUNNING

# Connect as sre user
aws ecs execute-command \
  --cluster rosa-boundary-dev \
  --task <task-id> \
  --container rosa-boundary \
  --interactive \
  --command '/usr/bin/su - sre'

# Or connect as root first
aws ecs execute-command \
  --cluster rosa-boundary-dev \
  --task <task-id> \
  --container rosa-boundary \
  --interactive \
  --command '/bin/bash'
```

### Viewing Logs

```bash
# Via AWS CLI
aws logs tail /ecs/rosa-boundary-dev --follow

# Via CloudWatch Console
# Navigate to CloudWatch > Log groups > /ecs/rosa-boundary-dev
```

## Cost Considerations

Estimated monthly costs (us-east-1, on-demand pricing):

- **Fargate**: ~$30-50/month (512 CPU, 1024 MB, running 24/7)
- **EFS**: ~$5-10/month (assuming 10 GB storage)
- **S3**: Variable based on storage and retention
- **CloudWatch Logs**: ~$0.50-2/month (7 day retention)
- **Bedrock**: Pay per API call (varies by model and usage)

**Note**: Actual costs depend on usage patterns. Consider using Fargate Spot for non-production environments.

## Cleanup

To destroy all resources:

```bash
# Empty the S3 bucket first (WORM compliance prevents Terraform from deleting objects)
aws s3 rm s3://$(terraform output -raw bucket_name) --recursive

# Then destroy infrastructure
terraform destroy
```

**Warning**: Objects in compliance mode cannot be deleted until retention expires. You may need to wait or contact AWS support to delete the bucket.

## Troubleshooting

### Task fails to start

- Check CloudWatch logs: `/ecs/rosa-boundary-dev`
- Verify container image is accessible
- Ensure security groups allow outbound traffic

### EFS mount fails

- Verify mount targets are in the same subnets as Fargate tasks
- Check security group allows NFS (port 2049) from Fargate SG
- Ensure EFS mount targets are available (check AWS console)

### Bedrock access denied

- Verify task role has Bedrock permissions
- Check if Claude models are available in your AWS region
- Confirm model IDs match those available in Bedrock

### S3 sync fails

- Verify task role has S3 write permissions
- Check bucket name in `S3_AUDIT_ESCROW` environment variable
- Review container logs for AWS SDK errors

## Security Best Practices

1. **Use private subnets**: Run Fargate tasks in private subnets with NAT gateway
2. **Rotate credentials**: Use IAM roles instead of access keys
3. **Enable CloudTrail**: Monitor all S3 and Bedrock API calls
4. **Restrict Bedrock access**: Limit to specific model IDs if needed
5. **Use Secrets Manager**: Store OpenShift tokens in Secrets Manager (not S3)

## License

See parent repository LICENSE file.

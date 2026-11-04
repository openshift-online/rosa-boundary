# Create Investigation Lambda

AWS Lambda function that validates Keycloak OIDC tokens, manages per-user IAM roles with tag-based authorization, creates EFS access points, and launches ECS Fargate tasks for ROSA cluster investigations.

## Overview

This Lambda implements a secure workflow for creating investigation tasks:

1. **OIDC Authentication**: Validates JWT tokens from Keycloak using JWKS
2. **Group Authorization**: Verifies user membership in `sre-team` group
3. **IAM Role Management**: Creates per-user IAM roles with tag-based ECS Exec permissions
4. **EFS Isolation**: Creates unique access points for each investigation
5. **Task Launch**: Starts Fargate tasks with ECS Exec enabled and proper tagging

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `KEYCLOAK_URL` | Keycloak server URL | `https://keycloak.example.com` |
| `KEYCLOAK_REALM` | Keycloak realm name | `rosa-boundary` |
| `KEYCLOAK_CLIENT_ID` | Expected OIDC audience claim | `rosa-boundary-sre` |
| `OIDC_PROVIDER_ARN` | ARN of OIDC identity provider in IAM | `arn:aws:iam::123456789012:oidc-provider/keycloak.example.com` |
| `ECS_CLUSTER` | ECS cluster name | `rosa-boundary-cluster` |
| `TASK_DEFINITION` | Base task definition name/ARN | `rosa-boundary-base:1` |
| `SUBNETS` | Comma-separated subnet IDs | `subnet-abc123,subnet-def456` |
| `SECURITY_GROUP` | Security group ID for tasks | `sg-abc12345` |
| `EFS_FILESYSTEM_ID` | EFS filesystem ID for home directories | `fs-abc12345` |

### Optional

| Variable | Description | Default |
|----------|-------------|---------|
| `REQUIRED_GROUP` | Required Keycloak group for authorization | `sre-team` |
| `S3_AUDIT_BUCKET` | S3 bucket name for audit logs | _(none)_ |

## API Request Format

### Endpoint

```
POST /create-investigation
```

### Headers

```
Authorization: Bearer <OIDC_TOKEN>
Content-Type: application/json
```

### Request Body

```json
{
  "investigation_id": "incident-20260128-001",
  "cluster_id": "rosa-prod-001",
  "oc_version": "4.19"
}
```

**Fields:**
- `investigation_id` (required): Unique identifier for the investigation
- `cluster_id` (required): ROSA cluster identifier
- `oc_version` (optional): OpenShift CLI version (default: `4.20`)

## API Response Format

### Success (200)

```json
{
  "message": "Investigation task created successfully",
  "role_arn": "arn:aws:iam::123456789012:role/rosa-boundary-user-a1b2c3d4",
  "role_created": true,
  "task_arn": "arn:aws:ecs:us-east-1:123456789012:task/rosa-boundary-cluster/abc123...",
  "access_point_id": "fsap-abc123...",
  "investigation_id": "incident-20260128-001",
  "cluster_id": "rosa-prod-001",
  "owner": "jdoe@example.com",
  "oc_version": "4.19"
}
```

### Error Responses

#### 400 Bad Request
```json
{
  "error": "Missing required fields: investigation_id, cluster_id"
}
```

#### 401 Unauthorized
```json
{
  "error": "Invalid or expired token"
}
```

#### 403 Forbidden
```json
{
  "error": "User not authorized: missing sre-team group membership",
  "groups": ["developers", "viewers"]
}
```

#### 500 Internal Server Error
```json
{
  "error": "Internal server error",
  "details": "Failed to create EFS access point: ..."
}
```

## IAM Role Creation

### Role Naming

Roles are named using a deterministic hash of the OIDC `sub` claim:

```
rosa-boundary-user-{sha256(sub)[:8]}
```

Example: `rosa-boundary-user-a1b2c3d4`

### Trust Policy

Roles trust the Keycloak OIDC provider with subject and audience matching:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/keycloak.example.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "keycloak.example.com:sub": "auth0|abc123...",
          "keycloak.example.com:aud": "rosa-boundary-sre"
        }
      }
    }
  ]
}
```

### Permissions Policy

Users can only execute commands on tasks they own (tag-based authorization):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ExecuteCommandOnOwnedTasks",
      "Effect": "Allow",
      "Action": ["ecs:ExecuteCommand"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ecs:ResourceTag/username": "auth0|abc123..."
        }
      }
    },
    {
      "Sid": "DescribeAndListECS",
      "Effect": "Allow",
      "Action": [
        "ecs:DescribeTasks",
        "ecs:ListTasks",
        "ecs:DescribeTaskDefinition"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SSMSessionForECSExec",
      "Effect": "Allow",
      "Action": ["ssm:StartSession"],
      "Resource": [
        "arn:aws:ecs:*:*:task/*",
        "arn:aws:ssm:*:*:document/AWS-StartInteractiveCommand"
      ],
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/username": "auth0|abc123..."
        }
      }
    }
  ]
}
```

## EFS Access Point Structure

Access points are created at:

```
/{cluster_id}/{investigation_id}/
```

**POSIX Configuration:**
- User: `1000:1000` (sre user)
- Permissions: `0755`

**Tags:**
- `Name`: `{cluster_id}-{investigation_id}`
- `ClusterID`: Cluster identifier
- `InvestigationID`: Investigation identifier
- `oidc_sub`: OIDC subject claim
- `username`: User's preferred username
- `ManagedBy`: `rosa-boundary-lambda`

## ECS Task Configuration

### Task Tags

All tasks are tagged with:

- `oidc_sub`: OIDC subject claim (audit)
- `username`: Human-readable username (ABAC key)
- `investigation_id`: Investigation identifier
- `cluster_id`: ROSA cluster identifier
- `oc_version`: OpenShift CLI version
- `access_point_id`: Associated EFS access point
- `created_at`: ISO 8601 timestamp

### Environment Variables

Tasks receive:

- `OC_VERSION`: Requested OpenShift CLI version
- `CLUSTER_ID`: ROSA cluster identifier
- `INVESTIGATION_ID`: Investigation identifier
- `S3_AUDIT_BUCKET`: S3 bucket for audit logs (if configured)

The container's entrypoint will auto-generate `S3_AUDIT_ESCROW` path:

```
s3://{S3_AUDIT_BUCKET}/{cluster_id}/{investigation_id}/{date}/{task_id}/
```

### Network Configuration

- **Launch Type**: FARGATE
- **Platform Version**: LATEST
- **Public IP**: Disabled (private subnets)
- **ECS Exec**: Enabled

## Token Validation

### JWKS Discovery

JWKS URL format:

```
{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs
```

### Token Verification

- **Signature**: Validated using RS256 with JWKS public keys
- **Expiration**: `exp` claim must be in the future
- **Audience**: `aud` claim must match `KEYCLOAK_CLIENT_ID`

### Expected Claims

```json
{
  "sub": "auth0|abc123...",
  "aud": "rosa-boundary-sre",
  "preferred_username": "jdoe@example.com",
  "email": "jdoe@example.com",
  "groups": ["sre-team", "admins"]
}
```

## Testing Locally

Start with [CONTRIBUTING.md](../../CONTRIBUTING.md) for development tools and the
[testing guide](../../docs/testing.md) for suite boundaries.

### Unit Tests (no AWS account or Keycloak server required)

From the repository root:

```bash
make test-lambda-create-investigation
make test-lambda  # All three Lambda suites, including both reapers
```

Or from this directory:

```bash
make test
make test-coverage
```

The Make targets use `uv run` with this directory's `pyproject.toml` and `uv.lock`,
including the dev group. No `requirements.txt`, system-wide pip installation, or
real OIDC token is needed. Fixtures mock client construction before handler import;
individual tests use moto and/or `unittest.mock` for AWS and identity behavior.

### LocalStack Workflow Tests

With LocalStack already healthy, from the repository root:

```bash
make -C lambda/create-investigation test-localstack
```

`test-localstack` is a compatibility alias for `test-e2e-localstack`: both select
`tests/localstack/integration/test_full_workflow.py` using the root uv group and
readiness guard. These emulate investigation resource workflows, not a deployed
Lambda invocation or real OIDC/IAM enforcement. See the [LocalStack guide](../../tests/localstack/README.md)
for licensing, executors, cleanup, and skipped coverage. These targets leave
LocalStack running; `make test-all` additionally reports overall completeness.

### Live Verification

Calling `lambda_handler` directly with real configuration can create AWS resources;
it is not an offline test. Real identity and deployed Lambda verification require
an approved personal dev environment, target/artifact checks, explicit permission,
audit evidence, and cleanup. Follow the [personal dev runbook](../../docs/runbooks/personal-dev-bootstrap.md)
and [live-verification procedure](../../.agents/skills/boundary-live-verification/SKILL.md).

## Deployment

### Lambda Configuration

The current regional Terraform configuration is authoritative
([lambda-create-investigation.tf](../../deploy/regional/lambda-create-investigation.tf)):

- **ZIP runtime**: Python 3.11
- **Memory**: 256 MB
- **Timeout**: 300 seconds
- **ZIP handler**: `handler.lambda_handler`
- **Image packaging**: supported through the regional packaging configuration;
  the image supplies its runtime/entrypoint.

### IAM Permissions

Lambda execution role needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:GetRole",
        "iam:PutRolePolicy",
        "iam:DeleteRole",
        "iam:TagRole"
      ],
      "Resource": "arn:aws:iam::*:role/rosa-boundary-user-*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecs:RunTask",
        "ecs:TagResource"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "efs:CreateAccessPoint",
        "efs:DeleteAccessPoint",
        "efs:TagResource"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::*:role/rosa-boundary-task-*"
    }
  ]
}
```

### Package Lambda

Use this directory's Makefile for packaging rather than installing host-platform
dependencies into a hand-built ZIP. From the repository root:

```bash
make -C lambda/create-investigation build  # Container-compatible ZIP dependencies
make build-lambda-image                   # Alternative: local Lambda image build
```

Builds may download dependencies/images; they do not publish or deploy. For an
actual deployment, inspect the current recipes and follow the approved
[personal dev](../../docs/runbooks/personal-dev-bootstrap.md) or
[staging](../../docs/staging-deployment.md) workflow. Do not bypass Terraform and
artifact review with an ad hoc `aws lambda update-function-code` command.

## Security Considerations

1. **Token Validation**: All tokens are cryptographically verified using JWKS
2. **Group Authorization**: Users must be in the required group (default: `sre-team`)
3. **Tag-Based Authorization**: Users can only access their own tasks via ECS Exec
4. **Role Isolation**: Each user gets a unique IAM role tied to their OIDC subject
5. **EFS Isolation**: Each investigation gets a unique access point with proper ownership
6. **Audit Logging**: All actions logged to CloudWatch, task history in S3

## Monitoring

### CloudWatch Logs

Log group: `/aws/lambda/create-investigation`

**Key log patterns:**
- `Token validated successfully for subject:` - Successful authentication
- `User not authorized:` - Authorization failures
- `Created new IAM role:` - New user roles
- `Launched ECS task:` - Successful task creation
- `Failed to create EFS access point:` - Resource creation errors

### CloudWatch Metrics

Monitor:
- **Invocations**: Total requests
- **Errors**: Failed invocations
- **Duration**: Response time
- **Throttles**: Rate limit hits

### Custom Metrics (Optional)

Add custom metrics for:
- Token validation failures
- Authorization failures (group membership)
- IAM role creation rate
- Task launch failures

## Error Handling

The Lambda implements comprehensive error handling:

1. **Input Validation**: Returns 400 for missing/invalid request data
2. **Authentication Failures**: Returns 401 for invalid/expired tokens
3. **Authorization Failures**: Returns 403 for insufficient permissions
4. **AWS Service Errors**: Returns 500 with error details
5. **Cleanup on Failure**: Deletes EFS access points if task launch fails

All errors are logged to CloudWatch with full stack traces.

## CORS Support

The Lambda returns CORS headers for browser-based clients:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: Content-Type,Authorization
Access-Control-Allow-Methods: POST,OPTIONS
```

Add an OPTIONS method handler if using API Gateway with CORS pre-flight.

# HCP Boundary Setup and Configuration

## Overview

Configure HCP Boundary with Keycloak OIDC authentication and create targets for ECS Fargate container access. This guide uses Terraform to manage Boundary configuration as code.

## Prerequisites

- HCP Boundary cluster provisioned
- Boundary CLI installed and configured
- Terraform installed
- Keycloak realm configured (see [Keycloak Realm Setup](keycloak-realm-setup.md))
- Keycloak client secret

## Terraform Configuration

Create `deploy/boundary/terraform/` directory for Boundary configuration.

### Directory Structure

```
deploy/boundary/terraform/
├── main.tf
├── variables.tf
├── outputs.tf
├── auth-method-oidc.tf
├── managed-groups.tf
├── scopes.tf
├── roles.tf
├── targets.tf
└── terraform.tfvars.example
```

### Provider Configuration

**`main.tf`:**

```hcl
terraform {
  required_version = ">= 1.0"

  required_providers {
    boundary = {
      source  = "hashicorp/boundary"
      version = "~> 1.1"
    }
  }
}

provider "boundary" {
  addr  = var.boundary_addr
  token = var.boundary_token
}
```

**`variables.tf`:**

```hcl
variable "boundary_addr" {
  description = "HCP Boundary cluster URL"
  type        = string
}

variable "boundary_token" {
  description = "Boundary admin token"
  type        = string
  sensitive   = true
}

variable "keycloak_issuer" {
  description = "Keycloak issuer URL"
  type        = string
  default     = "https://keycloak-keycloak.apps.rosa.dev.dyee.p3.openshiftapps.com/realms/rosa-boundary"
}

variable "keycloak_client_id" {
  description = "Keycloak OIDC client ID"
  type        = string
  default     = "hcp-boundary"
}

variable "keycloak_client_secret" {
  description = "Keycloak OIDC client secret"
  type        = string
  sensitive   = true
}

variable "aws_region" {
  description = "AWS region for ECS resources"
  type        = string
  default     = "us-east-2"
}
```

### OIDC Auth Method Configuration

**`auth-method-oidc.tf`:**

```hcl
resource "boundary_auth_method_oidc" "keycloak" {
  scope_id             = "global"
  name                 = "keycloak"
  description          = "Keycloak OIDC for rosa-boundary realm"

  # Keycloak configuration
  issuer               = var.keycloak_issuer
  client_id            = var.keycloak_client_id
  client_secret        = var.keycloak_client_secret

  # OIDC settings
  signing_algorithms   = ["RS256"]
  api_url_prefix       = var.boundary_addr

  # Claims configuration
  claims_scopes        = ["openid", "profile", "email", "groups"]
  account_claim_maps   = [
    "sub=sub",
    "email=email",
    "name=name"
  ]

  # IMPORTANT: Default 30s is too short, causes token expiry errors
  max_age              = 3600

  # Callback URLs (already configured in Keycloak client)
  callback_url         = "${var.boundary_addr}/v1/auth-methods/oidc:authenticate:callback"

  # Make this the primary auth method for global scope
  is_primary_for_scope = true
}
```

### Managed Groups Configuration

**`managed-groups.tf`:**

```hcl
# SRE Administrators - Full access
resource "boundary_managed_group" "sre_admins" {
  auth_method_id = boundary_auth_method_oidc.keycloak.id
  name           = "sre-admins"
  description    = "SRE administrators with full rosa-boundary access"

  # Filter matches Keycloak groups claim
  filter = "\"sre-admins\" in \"/token/groups\""
}

# SRE Operators - Standard incident access
resource "boundary_managed_group" "sre_operators" {
  auth_method_id = boundary_auth_method_oidc.keycloak.id
  name           = "sre-operators"
  description    = "SRE operators with assigned incident access"

  filter = "\"sre-operators\" in \"/token/groups\""
}

# SRE Viewers - Read-only access
resource "boundary_managed_group" "sre_viewers" {
  auth_method_id = boundary_auth_method_oidc.keycloak.id
  name           = "sre-viewers"
  description    = "SRE viewers with read-only access for audit"

  filter = "\"sre-viewers\" in \"/token/groups\""
}
```

### Scope Hierarchy

**`scopes.tf`:**

```hcl
# Organization scope for rosa-boundary
resource "boundary_scope" "org" {
  scope_id                 = "global"
  name                     = "rosa-boundary-org"
  description              = "Organization scope for ROSA boundary access"
  auto_create_admin_role   = true
  auto_create_default_role = true
}

# Project scope for incidents
resource "boundary_scope" "incidents" {
  scope_id                 = boundary_scope.org.id
  name                     = "incidents"
  description              = "Project scope for incident containers"
  auto_create_admin_role   = true
  auto_create_default_role = false
}
```

### Roles and Grants

**`roles.tf`:**

```hcl
# Admin role for sre-admins group
resource "boundary_role" "org_admin" {
  scope_id       = boundary_scope.org.id
  name           = "org-admin"
  description    = "Organization administrator"

  principal_ids = [
    boundary_managed_group.sre_admins.id
  ]

  grant_strings = [
    "ids=*;type=*;actions=*"
  ]
}

# Operator role for incident access
resource "boundary_role" "incident_operator" {
  scope_id       = boundary_scope.incidents.id
  name           = "incident-operator"
  description    = "Operators can connect to assigned incidents"

  principal_ids = [
    boundary_managed_group.sre_operators.id,
    boundary_managed_group.sre_admins.id
  ]

  grant_strings = [
    "ids=*;type=target;actions=authorize-session,read,list",
    "ids=*;type=session;actions=read,list,cancel:self"
  ]
}

# Viewer role for read-only access
resource "boundary_role" "incident_viewer" {
  scope_id       = boundary_scope.incidents.id
  name           = "incident-viewer"
  description    = "Viewers can see sessions but not connect"

  principal_ids = [
    boundary_managed_group.sre_viewers.id
  ]

  grant_strings = [
    "ids=*;type=target;actions=read,list",
    "ids=*;type=session;actions=read,list"
  ]
}
```

### Target Configuration

**`targets.tf`:**

```hcl
# Example target for an incident
resource "boundary_target" "incident_example" {
  type                     = "tcp"
  name                     = "rosa-prod-01-incident-123"
  description              = "ECS container for ROSA cluster rosa-prod-01, incident #123"
  scope_id                 = boundary_scope.incidents.id

  # Placeholder values (not used for -exec connections)
  default_port             = 9999
  address                  = "localhost"

  # Session limits
  session_max_seconds      = 28800  # 8 hours
  session_connection_limit = -1     # Unlimited connections per session

  # Worker filter (if using self-managed workers)
  # egress_worker_filter = "\"aws\" in \"/tags/region\" and \"/tags/region\" == \"us-east-2\""

  # Attributes for metadata (used by -exec script)
  attributes_json = jsonencode({
    cluster_id       = "rosa-prod-01"
    incident_number  = 123
    ecs_cluster      = "rosa-boundary-dev"
    ecs_task_arn     = "arn:aws:ecs:us-east-2:641875867446:task/rosa-boundary-dev/abc123"
    ecs_container    = "rosa-boundary"
    oc_version       = "4.20"
  })
}

# Output target details for scripts
output "incident_123_target_id" {
  value = boundary_target.incident_example.id
}
```

## Applying Configuration

### 1. Create terraform.tfvars

```hcl
boundary_addr            = "https://<your-cluster>.boundary.hashicorp.cloud"
boundary_token           = "<admin-token>"
keycloak_client_secret   = "<secret-from-realm-import>"
```

### 2. Initialize and apply

```bash
cd deploy/boundary/terraform

terraform init
terraform plan
terraform apply
```

### 3. Verify configuration

```bash
# List auth methods
boundary auth-methods list -scope-id global

# List managed groups
boundary managed-groups list -auth-method-id amoidc_<id>

# List targets
boundary targets list -scope-id <project-scope-id>
```

## User Authentication Test

### From CLI

```bash
# Authenticate via OIDC
boundary authenticate oidc -auth-method-id amoidc_<id>

# Opens browser, prompts for Keycloak login
# After successful login, returns to CLI with session token

# Verify authentication
boundary accounts list -auth-method-id amoidc_<id>

# List available targets (based on grants)
boundary targets list -scope-id <project-scope-id>
```

### From Admin Console

1. Navigate to HCP Boundary admin console
2. Go to Auth Methods → keycloak
3. Click "Authenticate"
4. Redirected to Keycloak login
5. Enter credentials
6. Redirected back to Boundary console (authenticated)

## Dynamic Target Creation

For incident lifecycle integration, targets should be created programmatically:

```bash
#!/bin/bash
# create-boundary-target.sh <cluster> <incident> <task-arn>

CLUSTER_ID="$1"
INCIDENT_NUM="$2"
TASK_ARN="$3"

boundary targets create tcp \
  -scope-id "$PROJECT_SCOPE_ID" \
  -name "${CLUSTER_ID}-incident-${INCIDENT_NUM}" \
  -description "Incident ${INCIDENT_NUM} for cluster ${CLUSTER_ID}" \
  -default-port 9999 \
  -address localhost \
  -session-max-seconds 28800 \
  -attr "ecs_task_arn=${TASK_ARN}" \
  -attr "ecs_cluster=rosa-boundary-dev" \
  -attr "cluster_id=${CLUSTER_ID}" \
  -attr "incident_number=${INCIDENT_NUM}" \
  -format json
```

This can be automated as part of the investigation creation workflow.

## Deleting Targets

When closing an incident:

```bash
# List targets for incident
boundary targets list -scope-id "$PROJECT_SCOPE_ID" -filter "\"incident-${INCIDENT_NUM}\" in \"/name\""

# Delete target
boundary targets delete -id ttcp_<target-id>
```

## HCP Boundary Limitations

**What HCP Boundary provides:**
- ✅ OIDC authentication
- ✅ Authorization enforcement (RBAC)
- ✅ Session metadata auditing
- ✅ Managed group synchronization

**What HCP Boundary does NOT provide for ECS:**
- ❌ Native ECS container discovery
- ❌ Direct SSM session proxy
- ❌ Session traffic recording (only metadata)
- ❌ Dynamic credential brokering to ECS

**Workarounds:**
- Manual target creation (can be automated)
- -exec flag for ECS Exec wrapper
- User IAM credentials for AWS API calls
- CloudWatch Logs for session recording

## Next Steps

- [AWS IAM Policies](aws-iam-policies.md) - Configure IAM for ECS Exec access
- [Integration Scripts](integration-scripts.md) - Deploy ecs-exec.sh wrapper
- [User Access Guide](../runbooks/user-access-guide.md) - End-user instructions

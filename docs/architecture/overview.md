# System Architecture Overview

## Introduction

The ROSA Boundary system implements an access control pattern for ephemeral SRE containers running on AWS ECS Fargate. The architecture consists of two distinct layers that work together to provide secure, audited access to infrastructure.

## High-Level Architecture

```mermaid
flowchart TB
    subgraph User["End User Layer"]
        Browser["Browser/CLI"]
        AWS_CLI["AWS CLI"]
    end

    subgraph Identity["Identity Layer (OpenShift)"]
        KC["Keycloak (RHBK)<br/>OIDC Provider"]
        KCDB["PostgreSQL<br/>(CloudNativePG)"]
    end

    subgraph AWS["AWS Infrastructure"]
        Lambda["Lambda<br/>Investigation Creator"]
        IAM["IAM<br/>Per-User Roles"]
        ECS["ECS Fargate<br/>Cluster"]
        SSM["SSM Session<br/>Manager"]
        Fargate["Ephemeral Container<br/>(rosa-boundary)"]
        EFS["EFS<br/>Per-Investigation Storage"]
        S3["S3<br/>Audit Logs"]
        CW["CloudWatch<br/>Session Logs"]
    end

    Browser -->|1. OIDC Login| KC
    KC -.->|stores| KCDB
    KC -->|2. ID Token| Browser
    Browser -->|3. Invoke with token| Lambda
    Lambda -->|4. Validate & authorize| KC
    Lambda -->|5. Create/get role| IAM
    Lambda -->|6. Launch task| ECS
    AWS_CLI -->|7. Assume role| IAM
    AWS_CLI -->|8. aws ecs execute-command| ECS
    ECS -->|9. SSM Session| SSM
    SSM -->|10. Shell| Fargate
    Fargate -.->|persist| EFS
    Fargate -.->|audit| S3
    SSM -.->|logs| CW

    style Identity fill:#e1f5fe
    style AWS fill:#f3e5f5
```

## Components

### Identity Layer (Keycloak on OpenShift)

**Keycloak (RHBK v26.4.7)**
- **Purpose**: Identity provider and OIDC authorization server
- **Deployment**: Red Hat build of Keycloak on OpenShift
- **Database**: CloudNativePG PostgreSQL 18.1
- **Namespace**: `keycloak`
- **Access**: https://keycloak-keycloak.apps.rosa.dev.dyee.p3.openshiftapps.com

**Responsibilities:**
- User authentication (username/password, MFA)
- Group membership management (sre-admins, sre-operators, sre-viewers)
- OIDC token issuance (ID token, access token)
- Claims mapping (sub, email, name, groups)

**Key Features:**
- Multi-realm support (rosa-boundary realm)
- Protocol mappers for custom claims
- Integration with external identity providers (LDAP, SAML)
- Persistent storage via CloudNativePG

### AWS Infrastructure Layer

**Lambda Function (Investigation Creator)**
- **Function**: rosa-boundary-{env}-create-investigation
- **Runtime**: Python 3.13
- **Trigger**: Function URL with IAM_OIDC auth
- **Purpose**: OIDC-authenticated investigation creation

**Responsibilities:**
- Validate OIDC token from Keycloak
- Check group membership (sre-team)
- Create or reuse per-user IAM role with tag-based permissions
- Launch ECS task with owner tags
- Return role ARN and task ARN

**ECS Fargate Cluster**
- **Cluster**: rosa-boundary-dev
- **Region**: us-east-2
- **Task Definition**: Per-investigation isolation (rosa-boundary-dev-{cluster}-{investigation}-{timestamp})
- **Container**: rosa-boundary (multi-arch: amd64/arm64)
- **Compute**: 512 CPU / 1024 MB (configurable)

**SSM Session Manager**
- **Protocol**: AWS Systems Manager Session Manager
- **Encryption**: KMS encrypted sessions
- **Authentication**: IAM-based (task role + user IAM)
- **Logging**: CloudWatch Logs `/ecs/rosa-boundary-dev/ssm-sessions`

**EFS Filesystem**
- **Mount**: `/home/sre` in container
- **Access Points**: Per-investigation isolation `/{cluster_id}/{investigation_id}/`
- **Encryption**: At-rest and in-transit
- **POSIX**: uid=1000, gid=1000 (sre user)

**S3 Audit Bucket**
- **Path**: `s3://{bucket}/{cluster}/{investigation}/{date}/{task_id}/`
- **Retention**: 90 days (WORM compliance mode)
- **Sync**: Automatic on container exit via entrypoint signal handling
- **Encryption**: AES256

## Data Flow Layers

### Layer 1: Authentication (Keycloak)

```mermaid
flowchart LR
    U[User] -->|1. Login request| KC[Keycloak]
    KC -->|2. Validate credentials| KCDB[(PostgreSQL)]
    KCDB -->|3. Return user + groups| KC
    KC -->|4. Issue ID token| U
```

**Outputs:**
- OIDC ID token with claims (sub, email, name, groups)
- Access token for userinfo endpoint
- Refresh token for long-lived sessions

### Layer 2: Authorization (Lambda + IAM)

```mermaid
flowchart LR
    U[User + Token] -->|1. Invoke Lambda| Lambda[Lambda Function]
    Lambda -->|2. Validate OIDC token| KC[Keycloak JWKS]
    KC -->|3. Public key| Lambda
    Lambda -->|4. Check group membership| Lambda
    Lambda -->|5. Create/get IAM role| IAM[IAM]
    IAM -->|6. Return role ARN| Lambda
    Lambda -->|7. Launch ECS task| ECS[ECS]
    Lambda -->|8. Return role + task ARN| U
```

**Outputs:**
- IAM role ARN (per-user, tag-based permissions)
- ECS task ARN (tagged with username)
- Temporary AWS credentials via assume-role-with-web-identity

### Layer 3: Execution (AWS ECS/SSM)

```mermaid
flowchart LR
    U[User + Role ARN] -->|1. assume-role-with-web-identity| STS[AWS STS]
    STS -->|2. Temporary credentials| U
    U -->|3. aws ecs execute-command| ECS[ECS API]
    ECS -->|4. Check IAM permissions| IAM[IAM]
    IAM -->|5. Verify task tags match role| ECS
    ECS -->|6. Start SSM session| SSM[SSM]
    SSM -->|7. WebSocket to container| Fargate[Container]
    Fargate -->|8. Interactive shell| U
```

**Outputs:**
- Interactive terminal session
- CloudWatch session logs
- S3 audit artifacts on exit

## Security Model

### Access Control Principles

1. **Verify Identity**: All users authenticate via Keycloak OIDC (no shared credentials)
2. **Least Privilege**: Lambda validates group membership; IAM enforces tag-based access (only owned tasks)
3. **Assume Breach**: Sessions are ephemeral, isolated per-investigation with audit logs
4. **Explicit Authorization**: Lambda validates group membership before creating investigation
5. **Continuous Monitoring**: All sessions logged to CloudWatch and artifacts synced to S3

### Authentication Chain

```
User Credentials → Keycloak MFA → OIDC Token → Lambda Validation → AWS IAM Role → ECS Exec → Container
```

Every step requires valid credentials/tokens:
- Keycloak validates username/password/MFA
- Lambda validates OIDC token signature and claims
- Lambda checks sre-team group membership
- AWS validates IAM credentials for ECS Exec API
- IAM policy validates task username tag matches role
- SSM validates session encryption keys
- Container enforces `sre` user permissions

### Audit Trail

Every access attempt generates logs in multiple locations:

1. **Keycloak**: Authentication events, login attempts, token issuance
2. **AWS CloudWatch Logs**: Lambda invocations, SSM session I/O, ECS Exec commands, container stdout/stderr
3. **AWS CloudTrail**: API calls (ECS, IAM, Lambda invocations)

Additional artifacts:
- **EFS**: User activity preserved in `/home/sre` per-investigation
- **S3**: Container home directory synced on exit for compliance

## Network Topology

```mermaid
flowchart TB
    subgraph Internet["Internet"]
        User["User Workstation"]
    end

    subgraph OpenShift["OpenShift Cluster"]
        KC["Keycloak Pod<br/>:8080"]
        KCDB["PostgreSQL Pod<br/>:5432"]
        Route["OpenShift Route<br/>TLS Edge"]
    end

    subgraph AWS["AWS VPC (us-east-2)"]
        Lambda["Lambda Function<br/>(Function URL)"]
        subgraph Subnet1["Private Subnet AZ1"]
            Fargate1["Fargate Task<br/>:8080 (not exposed)"]
            EFS1["EFS Mount Target"]
        end
        subgraph Subnet2["Private Subnet AZ2"]
            Fargate2["Fargate Task<br/>:8080 (not exposed)"]
            EFS2["EFS Mount Target"]
        end
        EFS["EFS Filesystem<br/>(encrypted)"]
        S3["S3 Audit Bucket<br/>(WORM)"]
        SSM["SSM API<br/>(regional endpoint)"]
    end

    User -->|HTTPS| Route
    User -->|HTTPS| Lambda
    User -->|AWS API| SSM
    Route -->|HTTP| KC
    KC -->|TCP 5432| KCDB
    Lambda -->|Validate token| Route
    Fargate1 -.->|NFS| EFS1
    Fargate2 -.->|NFS| EFS2
    EFS1 -->|replicate| EFS
    EFS2 -->|replicate| EFS
    Fargate1 -.->|on exit| S3
    Fargate2 -.->|on exit| S3
    SSM -->|WebSocket| Fargate1
    SSM -->|WebSocket| Fargate2

    style OpenShift fill:#e3f2fd
    style AWS fill:#fce4ec
```

**Network Isolation:**
- Keycloak: OpenShift Routes with edge TLS, internal ClusterIP services
- Lambda: Public Function URL with IAM_OIDC authentication
- Fargate: No ingress, SSM provides egress-only access via AWS PrivateLink

## Per-Investigation Isolation

Each investigation gets dedicated resources:

```
Investigation inv-123 for cluster rosa-prod-01
├── EFS Access Point: /rosa-prod-01/inv-123/
│   └── Mounted to: /home/sre in container
├── Task Definition: rosa-boundary-dev-rosa-prod-01-inv-123-20260103
│   ├── Environment: CLUSTER_ID=rosa-prod-01
│   ├── Environment: INVESTIGATION_ID=inv-123
│   └── Environment: OC_VERSION=4.20
├── IAM Role: rosa-boundary-dev-user-abc123def456 (per OIDC sub claim)
│   ├── Tag-based policy: only access tasks with username=sre-user
│   └── Created/reused by Lambda function
└── S3 Audit Path: s3://bucket/rosa-prod-01/inv-123/20260103/{task-id}/
```

**Isolation Guarantees:**
- Each investigation has dedicated filesystem namespace (EFS access point)
- Each investigation has immutable task definition (version locked)
- Each investigation has unique S3 prefix (audit segregation)
- IAM tag-based policies enforce per-user task access

## Integration Architecture

```mermaid
graph TB
    subgraph config["Configuration Layer"]
        TF[Terraform]
        KC_CR[KeycloakRealmImport CR]
    end

    subgraph runtime["Runtime Layer"]
        KC_RT[Keycloak Runtime]
        Lambda_RT[Lambda Runtime]
        ECS_RT[ECS Fargate Runtime]
    end

    subgraph scripts["User Tools"]
        AUTH[get-oidc-token.sh]
        ASSUME[assume-role.sh]
        CREATE[create-investigation-lambda.sh]
        MANUAL[Manual scripts in deploy/regional/examples/]
    end

    TF -->|provisions Lambda| Lambda_RT
    TF -->|provisions ECS| ECS_RT
    KC_CR -->|configures| KC_RT

    AUTH -->|gets token from| KC_RT
    CREATE -->|uses| AUTH
    CREATE -->|invokes| Lambda_RT
    Lambda_RT -->|validates token with| KC_RT
    Lambda_RT -->|creates task in| ECS_RT
    ASSUME -->|uses token from| AUTH
    MANUAL -->|direct AWS API| ECS_RT

    style config fill:#e8f5e9
    style runtime fill:#fff3e0
    style scripts fill:#f3e5f5
```

## Technology Stack

| Layer | Component | Version | Purpose |
|-------|-----------|---------|---------|
| **Identity** | Keycloak | 26.4.7 (RHBK) | OIDC authentication |
| | PostgreSQL | 18.1 (CNPG) | Keycloak database |
| | OpenShift | 4.x (ROSA) | Kubernetes platform |
| **Infrastructure** | AWS Lambda | Python 3.13 | Investigation creation & authorization |
| | IAM | Latest | Per-user roles with tag-based policies |
| | ECS Fargate | Latest | Container orchestration |
| | AWS SSM | Latest | Session management |
| | EFS | Latest | Persistent storage |
| | S3 | Latest | Audit log storage |
| | Terraform | Latest | Infrastructure as code |

## Next Steps

- [Configuration Guides](../configuration/) - Step-by-step setup instructions
- [User Access Guide](../runbooks/user-access-guide.md) - End-user workflow
- [Investigation Workflow](../runbooks/investigation-workflow.md) - Creating and managing investigations

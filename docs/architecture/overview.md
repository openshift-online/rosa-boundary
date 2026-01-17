# System Architecture Overview

## Introduction

The ROSA Boundary system implements a zero-trust access pattern for ephemeral SRE containers running on AWS ECS Fargate. The architecture consists of three distinct layers that work together to provide secure, audited access to infrastructure.

## High-Level Architecture

```mermaid
flowchart TB
    subgraph User["End User Layer"]
        Browser["Browser/CLI"]
        BC["Boundary CLI"]
    end

    subgraph Identity["Identity Layer (OpenShift)"]
        KC["Keycloak (RHBK)<br/>OIDC Provider"]
        KCDB["PostgreSQL<br/>(CloudNativePG)"]
    end

    subgraph Access["Access Control Layer (HCP)"]
        HCP["HCP Boundary<br/>Controllers"]
        BDB["Boundary DB<br/>(HCP Managed)"]
    end

    subgraph AWS["AWS Infrastructure"]
        ECS["ECS Fargate<br/>Cluster"]
        SSM["SSM Session<br/>Manager"]
        Fargate["Ephemeral Container<br/>(rosa-boundary)"]
        EFS["EFS<br/>Per-Incident Storage"]
        S3["S3<br/>Audit Logs"]
        CW["CloudWatch<br/>Session Logs"]
    end

    Browser -->|1. OIDC Login| KC
    KC -.->|stores| KCDB
    KC -->|2. ID Token| Browser
    Browser -->|3. Authenticate| HCP
    HCP -.->|stores| BDB
    HCP -->|4. Authorize| HCP
    BC -->|5. boundary connect -exec| HCP
    BC -->|6. aws ecs execute-command| ECS
    ECS -->|7. SSM Session| SSM
    SSM -->|8. Shell| Fargate
    Fargate -.->|persist| EFS
    Fargate -.->|audit| S3
    SSM -.->|logs| CW

    style Identity fill:#e1f5fe
    style Access fill:#fff3e0
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

### Access Control Layer (HCP Boundary)

**HCP Boundary**
- **Purpose**: Access control and session management
- **Deployment**: HashiCorp Cloud Platform (SaaS)
- **Authentication**: OIDC via Keycloak
- **Database**: Managed by HashiCorp

**Responsibilities:**
- OIDC authentication flow orchestration
- Role-based access control (RBAC)
- Session authorization and lifecycle management
- Audit logging of all access attempts
- Managed group filtering from OIDC claims

**Key Features:**
- Global scope for OIDC auth method
- Project scopes for target organization
- Managed groups synced from Keycloak groups
- Target-based access control
- Session recording metadata

### AWS Infrastructure Layer

**ECS Fargate Cluster**
- **Cluster**: rosa-boundary-dev
- **Region**: us-east-2
- **Task Definition**: Per-incident isolation (rosa-boundary-dev-{cluster}-{incident}-{timestamp})
- **Container**: rosa-boundary (multi-arch: amd64/arm64)
- **Compute**: 512 CPU / 1024 MB (configurable)

**SSM Session Manager**
- **Protocol**: AWS Systems Manager Session Manager
- **Encryption**: KMS encrypted sessions
- **Authentication**: IAM-based (task role + user IAM)
- **Logging**: CloudWatch Logs `/ecs/rosa-boundary-dev/ssm-sessions`

**EFS Filesystem**
- **Mount**: `/home/sre` in container
- **Access Points**: Per-incident isolation `/{cluster_id}/{incident_number}/`
- **Encryption**: At-rest and in-transit
- **POSIX**: uid=1000, gid=1000 (sre user)

**S3 Audit Bucket**
- **Path**: `s3://{bucket}/{cluster}/{incident}/{date}/{task_id}/`
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

### Layer 2: Authorization (Boundary)

```mermaid
flowchart LR
    U[User + Token] -->|1. Authenticate| HCP[HCP Boundary]
    HCP -->|2. Validate OIDC token| KC[Keycloak]
    KC -->|3. Token valid| HCP
    HCP -->|4. Map groups to roles| BDB[(Boundary DB)]
    BDB -->|5. Return permissions| HCP
    HCP -->|6. Issue session token| U
```

**Outputs:**
- Boundary session token (scoped to user + permissions)
- Managed group memberships
- Available targets based on grants

### Layer 3: Execution (AWS ECS/SSM)

```mermaid
flowchart LR
    U[User + Session] -->|1. boundary connect -exec| BC[Boundary CLI]
    BC -->|2. Authorize session| HCP[HCP Boundary]
    HCP -->|3. Session authorized| BC
    BC -->|4. Execute ecs-exec.sh| Script[ecs-exec.sh]
    Script -->|5. aws ecs execute-command| ECS[ECS API]
    ECS -->|6. Start SSM session| SSM[SSM]
    SSM -->|7. WebSocket to container| Fargate[Container]
    Fargate -->|8. Interactive shell| U
```

**Outputs:**
- Interactive terminal session
- CloudWatch session logs
- S3 audit artifacts on exit

## Security Model

### Zero-Trust Principles

1. **Verify Identity**: All users authenticate via Keycloak OIDC (no shared credentials)
2. **Least Privilege**: Boundary enforces role-based access (only authorized targets)
3. **Assume Breach**: Sessions are ephemeral, isolated per-incident with audit logs
4. **Explicit Authorization**: Every session requires Boundary approval
5. **Continuous Monitoring**: All sessions logged to CloudWatch and audited in Boundary

### Authentication Chain

```
User Credentials → Keycloak MFA → OIDC Token → Boundary Session → AWS IAM → ECS Exec → Container
```

Every step requires valid credentials/tokens:
- Keycloak validates username/password/MFA
- Boundary validates OIDC token signature and claims
- AWS validates IAM credentials for ECS Exec API
- SSM validates session encryption keys
- Container enforces `sre` user permissions

### Audit Trail

Every access attempt generates logs in three locations:

1. **Keycloak**: Authentication events, login attempts, token issuance
2. **Boundary**: Session authorization, connection attempts, session lifecycle
3. **AWS CloudWatch**: SSM session I/O, ECS Exec commands, container stdout/stderr

Additional artifacts:
- **EFS**: User activity preserved in `/home/sre` per-incident
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

    subgraph HCP["HashiCorp Cloud"]
        Boundary["HCP Boundary<br/>Controllers"]
    end

    subgraph AWS["AWS VPC (us-east-2)"]
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
    User -->|HTTPS| Boundary
    User -->|AWS API| SSM
    Route -->|HTTP| KC
    KC -->|TCP 5432| KCDB
    Fargate1 -.->|NFS| EFS1
    Fargate2 -.->|NFS| EFS2
    EFS1 -->|replicate| EFS
    EFS2 -->|replicate| EFS
    Fargate1 -.->|on exit| S3
    Fargate2 -.->|on exit| S3
    SSM -->|WebSocket| Fargate1
    SSM -->|WebSocket| Fargate2

    style OpenShift fill:#e3f2fd
    style HCP fill:#fff8e1
    style AWS fill:#fce4ec
```

**Network Isolation:**
- Keycloak: OpenShift Routes with edge TLS, internal ClusterIP services
- Boundary: HCP managed, no network dependencies on AWS
- Fargate: No ingress, SSM provides egress-only access via AWS PrivateLink

## Per-Incident Isolation

Each incident gets dedicated resources:

```
Incident #123 for cluster rosa-prod-01
├── EFS Access Point: /rosa-prod-01/123/
│   └── Mounted to: /home/sre in container
├── Task Definition: rosa-boundary-dev-rosa-prod-01-123-20260103
│   ├── Environment: CLUSTER_ID=rosa-prod-01
│   ├── Environment: INCIDENT_NUMBER=123
│   └── Environment: OC_VERSION=4.20
├── Boundary Target: rosa-prod-01-incident-123
│   ├── Authorization: sre-operators group
│   └── Session: max 8 hours
└── S3 Audit Path: s3://bucket/rosa-prod-01/123/20260103/{task-id}/
```

**Isolation Guarantees:**
- Each incident has dedicated filesystem namespace (EFS access point)
- Each incident has immutable task definition (version locked)
- Each incident has unique S3 prefix (audit segregation)
- Boundary targets scope access per-incident

## Integration Architecture

```mermaid
graph TB
    subgraph config["Configuration Layer"]
        TF[Terraform]
        KC_CR[KeycloakRealmImport CR]
        BD_TF[Boundary Terraform]
    end

    subgraph runtime["Runtime Layer"]
        KC_RT[Keycloak Runtime]
        BD_RT[Boundary Runtime]
        ECS_RT[ECS Fargate Runtime]
    end

    subgraph scripts["Integration Scripts"]
        CREATE[create_incident.sh]
        LAUNCH[launch_task.sh]
        JOIN[join_task.sh]
        EXEC[ecs-exec.sh]
        STOP[stop_task.sh]
        CLOSE[close_incident.sh]
    end

    TF -->|provisions| ECS_RT
    KC_CR -->|configures| KC_RT
    BD_TF -->|configures| BD_RT

    CREATE -->|creates| ECS_RT
    CREATE -->|creates target| BD_RT
    LAUNCH -->|starts task| ECS_RT
    JOIN -->|uses| EXEC
    EXEC -->|authorizes via| BD_RT
    EXEC -->|connects to| ECS_RT
    STOP -->|terminates| ECS_RT
    CLOSE -->|deletes target| BD_RT

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
| **Access** | HCP Boundary | SaaS | Authorization engine |
| | Terraform | Latest | Boundary configuration |
| **Infrastructure** | ECS Fargate | Latest | Container orchestration |
| | AWS SSM | Latest | Session management |
| | EFS | Latest | Persistent storage |
| | S3 | Latest | Audit log storage |

## Next Steps

- [Authentication Flow](authentication-flow.md) - Detailed OIDC flow between Keycloak and Boundary
- [Session Flow](session-flow.md) - How users connect to containers via Boundary
- [Configuration Guides](../configuration/) - Step-by-step setup instructions

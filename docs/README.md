# ROSA Boundary Zero-Trust Access Documentation

This documentation describes the zero-trust access architecture for ephemeral SRE containers on AWS ECS Fargate, using Keycloak for identity and HCP Boundary for access control.

## System Overview

The ROSA Boundary system provides secure, audited access to ephemeral SRE containers running on AWS ECS Fargate. Access is controlled through a three-tier security model:

1. **Identity Layer**: Keycloak (Red Hat build) provides OIDC authentication and group-based identity
2. **Access Control Layer**: HCP Boundary enforces authorization and provides session management
3. **Infrastructure Layer**: AWS ECS Fargate runs ephemeral containers with SSM-based access

## Architecture Documentation

- [**System Overview**](architecture/overview.md) - High-level architecture with diagrams
- [**Authentication Flow**](architecture/authentication-flow.md) - Keycloak OIDC integration with Boundary
- [**Session Flow**](architecture/session-flow.md) - How Boundary connects to ECS Fargate via SSM

## Configuration Guides

- [**Keycloak Realm Setup**](configuration/keycloak-realm-setup.md) - Configure Keycloak realm and OIDC client using KeycloakRealmImport CR
- [**HCP Boundary Setup**](configuration/hcp-boundary-setup.md) - Configure Boundary OIDC auth method, managed groups, and targets
- [**AWS IAM Policies**](configuration/aws-iam-policies.md) - IAM roles and policies for ECS Exec access
- [**Integration Scripts**](configuration/integration-scripts.md) - Helper scripts for Boundary -exec wrapper

## Runbooks

- [**User Access Guide**](runbooks/user-access-guide.md) - Step-by-step guide for end users
- [**Incident Workflow**](runbooks/incident-workflow.md) - Creating and managing incidents with Boundary integration
- [**Troubleshooting**](runbooks/troubleshooting.md) - Common issues and solutions

## Quick Start

### Prerequisites

- HCP Boundary cluster provisioned
- Keycloak deployed (see `deploy/keycloak/`)
- AWS account with ECS Fargate infrastructure (see `deploy/regional/`)
- Boundary CLI installed locally

### For Administrators

1. Configure [Keycloak realm and OIDC client](configuration/keycloak-realm-setup.md)
2. Set up [HCP Boundary OIDC auth method](configuration/hcp-boundary-setup.md)
3. Create [AWS IAM policies](configuration/aws-iam-policies.md) for users
4. Deploy [integration scripts](configuration/integration-scripts.md)

### For End Users

See the [User Access Guide](runbooks/user-access-guide.md) for authentication and connection instructions.

## Important Limitations

**HCP Boundary does not natively support AWS ECS containers or SSM Session Manager.** This implementation uses Boundary's `-exec` flag to wrap `aws ecs execute-command` calls, which provides:

- ✅ Authentication via Keycloak OIDC
- ✅ Authorization enforcement via Boundary RBAC
- ✅ Session audit logging in Boundary
- ⚠️  ECS Exec session establishment outside Boundary's proxy
- ⚠️  No dynamic ECS container discovery (manual target creation)

For more details, see [Session Flow](architecture/session-flow.md).

## Support

For issues related to specific components:
- **Keycloak**: Check `oc logs -n keycloak deployment/rhbk-operator`
- **Boundary**: Check HCP Boundary admin console
- **AWS ECS/SSM**: Check CloudWatch Logs `/ecs/rosa-boundary-*/ssm-sessions`

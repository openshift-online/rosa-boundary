# ROSA Boundary Access Documentation

This documentation describes the access architecture for ephemeral SRE containers on AWS ECS Fargate, using Keycloak for OIDC authentication and AWS IAM for authorization.

## System Overview

The ROSA Boundary system provides secure, audited access to ephemeral SRE containers running on AWS ECS Fargate. Access is controlled through a two-tier security model:

1. **Identity Layer**: Keycloak (Red Hat build) provides OIDC authentication and group-based identity
2. **Infrastructure Layer**: AWS ECS Fargate runs ephemeral containers with Lambda-based authorization and tag-based IAM policies

## Architecture Documentation

- [**System Overview**](architecture/overview.md) - High-level architecture with diagrams

## Configuration Guides

- [**Keycloak Realm Setup**](configuration/keycloak-realm-setup.md) - Configure Keycloak realm and OIDC client using KeycloakRealmImport CR
- [**AWS IAM Policies**](configuration/aws-iam-policies.md) - IAM roles and policies for ECS Exec access

## Runbooks

- [**User Access Guide**](runbooks/user-access-guide.md) - Step-by-step guide for end users
- [**Investigation Workflow**](runbooks/investigation-workflow.md) - Creating and managing investigations
- [**Troubleshooting**](runbooks/troubleshooting.md) - Common issues and solutions

## Quick Start

### Prerequisites

- Keycloak deployed (see `deploy/keycloak/`)
- AWS account with ECS Fargate infrastructure (see `deploy/regional/`)

### For Administrators

1. Configure [Keycloak realm and OIDC client](configuration/keycloak-realm-setup.md)
2. Create [AWS IAM policies](configuration/aws-iam-policies.md) for users
3. Deploy Lambda function for investigation creation (see `deploy/regional/lambda-create-investigation.tf`)

### For End Users

See the [User Access Guide](runbooks/user-access-guide.md) for authentication and connection instructions.

## Support

For issues related to specific components:
- **Keycloak**: Check `oc logs -n keycloak deployment/rhbk-operator`
- **AWS ECS/SSM**: Check CloudWatch Logs `/ecs/rosa-boundary-*/ssm-sessions`
- **Lambda**: Check CloudWatch Logs `/aws/lambda/rosa-boundary-*-create-investigation`

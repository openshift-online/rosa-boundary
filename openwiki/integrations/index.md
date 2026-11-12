# Files

- [Keycloak and OIDC provider integration](keycloak-deployment.md) - Describes how Boundary's account Terraform registers Keycloak as an AWS IAM OIDC provider per environment, how the shared SRE and Lambda-invoker roles gate assumption on audience/session-tag conditions, and how the Kustomize Keycloak deployment and CLI/Lambda OIDC consumers fit around that trust.
- [Trusted Actions API surface and clients](trusted-actions-api.md) - Describes the OpenAPI-defined Trusted Actions HTTP contract (catalog, run, runs, audit, health), its ocm_jwt bearer security scheme, its external OCM/AMS and Backplane dependencies, and the rta/action-cli/test-client command-line tools that call or bypass it.

# Files

- [Keycloak and OIDC provider integration](keycloak-deployment.md) - Describes the repository's Kustomize Keycloak deployment components and how the CLI, investigation Lambda, and AWS IAM consume configured OIDC issuer and client values.
- [Trusted Actions API surface and clients](trusted-actions-api.md) - Describes the OpenAPI-defined Trusted Actions HTTP contract (catalog, run, runs, audit, health), its ocm_jwt bearer security scheme, its external OCM/AMS and Backplane dependencies, and the rta/action-cli/test-client command-line tools that call or bypass it.

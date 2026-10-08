---
type: integration
title: Keycloak and OIDC provider integration
description: Describes the repository's Kustomize Keycloak deployment components and how the CLI, investigation Lambda, and AWS IAM consume configured OIDC issuer and client values.
tags: [keycloak, oidc, kubernetes, kustomize, aws-iam]
sources:
  - id: openwiki-source-0ab90febf03e268e72a1cada
    resource: repo://deploy/keycloak/base/kustomization.yaml
  - id: openwiki-source-d56d7281cedbdace309538cb
    resource: repo://deploy/keycloak/components/cnpg/cluster.yaml
  - id: openwiki-source-dda17d20d829b110b5cee49b
    resource: repo://deploy/keycloak/components/cnpg/external-secret-db.yaml
  - id: openwiki-source-3684bc42074ffe349698c05f
    resource: repo://deploy/keycloak/components/keycloak/keycloak.yaml
  - id: openwiki-source-9d5cae9d3aa92e38c6c83da6
    resource: repo://deploy/keycloak/components/keycloak/route.yaml
  - id: openwiki-source-e0b6878ee330d7f6ee18b18e
    resource: repo://deploy/keycloak/overlays/dev/kustomization.yaml
  - id: openwiki-source-9b7905e9e38369b09bae85a2
    resource: repo://deploy/regional/oidc.tf
  - id: openwiki-source-f3c901cd7f81495d7b85597f
    resource: repo://internal/auth/oidc.go
  - id: openwiki-source-a6037a5955153e01dc60d90b
    resource: repo://internal/lambda/client.go
  - id: openwiki-source-253b57ec87256e726a724093
    resource: repo://lambda/create-investigation/handler.py
generated: { by: "opencode", at: "2026-10-05T17:08:59.471Z" }
verified:
  - by: openwiki/0.7.0
    at: 2026-10-05T19:18:44.075Z
---

# Keycloak and OIDC provider integration

The repository contains a Kustomize deployment for a Keycloak service on OpenShift, plus AWS-side OIDC trust and consumers. These are related but separately configured surfaces: the Kustomize manifests create the Keycloak service and its database integration, while regional Terraform and CLI configuration receive issuer, realm, and client values used for authentication. The manifests in this deployment set do not define an OIDC realm or client resource.

## OpenShift deployment composition

`deploy/keycloak/base/` establishes the `keycloak` namespace. The `overlays/dev` Kustomization adds a ClusterSecretStore and includes the CloudNativePG and Keycloak components. The CNPG component creates a PostgreSQL `Cluster`; the Keycloak component creates a Keycloak custom resource and OpenShift Route. The deployment therefore depends on the cluster already providing the corresponding operators and external-secrets integration.

The database credentials are sourced from AWS Systems Manager Parameter Store keys `/keycloak/db/username` and `/keycloak/db/password` through the `aws-ssm-keycloak` ClusterSecretStore. An ExternalSecret materializes them as the `keycloak-db-app` Kubernetes secret, which both CNPG bootstrap and the Keycloak custom resource reference. Keycloak is configured for HTTP behind a proxy that supplies `X-Forwarded` headers; the OpenShift Route terminates TLS at the edge and redirects insecure requests.

The dev ClusterSecretStore reads Parameter Store in `us-east-2` using the external-secrets operator's service account. The overlay also contains a namespace SecretStore and a separately annotated service account; do not assume that this namespace-scoped store is the one used by the database ExternalSecret, which explicitly names the ClusterSecretStore.

## OIDC consumption by the application

The CLI configures a Keycloak base URL, realm, and OIDC client ID, then performs the browser-based PKCE authorization-code flow. Regional Terraform registers the primary issuer URL/client ID as an AWS IAM OIDC provider and uses audience conditions in the invoker and shared SRE role trust policies. Optional stage and production issuers each require their own client IDs and thumbprints when configured.

The create-investigation Lambda receives issuer/client settings as environment variables. It routes an incoming token by its issuer to the matching configured JWKS endpoint and verifies its signature, expiry, and audience before interpreting identity/group/session-tag claims. Stage and production issuers are accepted only when configured. The Lambda's `get_config` action is a separate bootstrap path authenticated by the AWS invoker role; it returns configuration identifiers before the CLI has completed OIDC setup.

## Evidence-backed claims

- The dev Kustomize overlay composes the namespace base with a ClusterSecretStore and the CNPG and Keycloak components. [base](repo://deploy/keycloak/base/kustomization.yaml#L1-L4) · [dev overlay](repo://deploy/keycloak/overlays/dev/kustomization.yaml#L1-L10)
- The database ExternalSecret reads two SSM Parameter Store entries and creates `keycloak-db-app`, which is referenced by CNPG initialization and the Keycloak database settings. [ExternalSecret](repo://deploy/keycloak/components/cnpg/external-secret-db.yaml#L1-L25) · [CNPG cluster](repo://deploy/keycloak/components/cnpg/cluster.yaml#L1-L17) · [Keycloak resource](repo://deploy/keycloak/components/keycloak/keycloak.yaml#L1-L28)
- The Keycloak resource enables HTTP and X-Forwarded proxy headers, while its OpenShift Route uses edge TLS termination and redirects insecure traffic. [Keycloak settings](repo://deploy/keycloak/components/keycloak/keycloak.yaml#L21-L28) · [Route](repo://deploy/keycloak/components/keycloak/route.yaml#L1-L14)
- Terraform registers primary OIDC provider audience trust and supports optional stage and production OIDC providers; the Lambda routes tokens to issuer-specific JWKS and validates signature, expiry, and audience. [OIDC providers](repo://deploy/regional/oidc.tf#L1-L64) · [Lambda issuer validation](repo://lambda/create-investigation/handler.py#L322-L405)
- The CLI derives its authorization and token endpoints from the configured Keycloak base URL, realm, and client ID and runs the PKCE callback flow. [PKCE flow](repo://internal/auth/oidc.go#L45-L135)
- Lambda's `get_config` action is dispatched before OIDC validation and returns only configuration identifiers through the IAM-authenticated invocation path. [early dispatch](repo://lambda/create-investigation/handler.py#L88-L117) · [config response](repo://lambda/create-investigation/handler.py#L1048-L1072) · [CLI invocation](repo://internal/lambda/client.go#L200-L222)

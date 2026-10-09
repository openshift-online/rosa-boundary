---
type: integration
title: Keycloak and OIDC provider integration
description: Describes the repository's Kustomize Keycloak deployment components and how the CLI, investigation Lambda, and AWS IAM consume configured OIDC issuer and client values, including the account-owned OIDC provider resources.
tags: [keycloak, oidc, kubernetes, kustomize, aws-iam]
sources:
  - id: openwiki-source-c2905a327012a93813a2dd05
    resource: repo://deploy/account/modules/shared-iam/oidc.tf
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
  - id: openwiki-source-6697a0d2171b442a1f541cf8
    resource: repo://deploy/regional/account-iam.tf
  - id: openwiki-source-d176128a85129af793772942
    resource: repo://deploy/regional/lambda-create-investigation.tf
  - id: openwiki-source-f3c901cd7f81495d7b85597f
    resource: repo://internal/auth/oidc.go
  - id: openwiki-source-a6037a5955153e01dc60d90b
    resource: repo://internal/lambda/client.go
  - id: openwiki-source-253b57ec87256e726a724093
    resource: repo://lambda/create-investigation/handler.py
verified:
  - by: openwiki/0.7.1
    at: 2026-10-09T17:04:25.482Z
generated: { by: "openwiki/0.7.1", at: "2026-10-09T17:04:25.482Z" }
---

# Keycloak and OIDC provider integration

The repository contains a Kustomize deployment for a Keycloak service on OpenShift, plus AWS-side OIDC trust and consumers. These are related but separately configured surfaces: the Kustomize manifests create the Keycloak service and its database integration, while account and regional Terraform and CLI configuration receive issuer, realm, and client values used for authentication. The manifests in this deployment set do not define an OIDC realm or client resource.

OIDC provider registration and consumption are split across two independent Terraform roots: the `deploy/account` root owns the AWS IAM OIDC provider resources, while `deploy/regional` only looks them up by issuer URL to wire into regional resources. See [Account-level IAM identity and budget ownership](../infrastructure/account-identity-ownership.md) for the full ownership split and migration rationale, and [Identity and Access](../architecture/identity-and-access.md) for the end-to-end runtime authentication flow.

## OpenShift deployment composition

`deploy/keycloak/base/` establishes the `keycloak` namespace. The `overlays/dev` Kustomization adds a ClusterSecretStore and includes the CloudNativePG and Keycloak components. The CNPG component creates a PostgreSQL `Cluster`; the Keycloak component creates a Keycloak custom resource and OpenShift Route. The deployment therefore depends on the cluster already providing the corresponding operators and external-secrets integration.

The database credentials are sourced from AWS Systems Manager Parameter Store keys `/keycloak/db/username` and `/keycloak/db/password` through the `aws-ssm-keycloak` ClusterSecretStore. An ExternalSecret materializes them as the `keycloak-db-app` Kubernetes secret, which both CNPG bootstrap and the Keycloak custom resource reference. Keycloak is configured for HTTP behind a proxy that supplies `X-Forwarded` headers; the OpenShift Route terminates TLS at the edge and redirects insecure requests.

The dev ClusterSecretStore reads Parameter Store in `us-east-2` using the external-secrets operator's service account. The overlay also contains a namespace SecretStore and a separately annotated service account; do not assume that this namespace-scoped store is the one used by the database ExternalSecret, which explicitly names the ClusterSecretStore.

## OIDC provider ownership: account vs. regional Terraform

The `aws_iam_openid_connect_provider` resources for the primary, optional stage, and optional production Keycloak issuers are defined in `deploy/account/modules/shared-iam/oidc.tf`, part of the separate `deploy/account` Terraform root. `deploy/regional/oidc.tf` has been removed; regional Terraform no longer registers any OIDC provider itself.

Instead, `deploy/regional/account-iam.tf` performs `data.aws_iam_openid_connect_provider` lookups by issuer URL (`var.keycloak_issuer_url`, and conditionally `var.stage_keycloak_issuer_url` / `var.prod_keycloak_issuer_url`) to resolve the ARNs of the account-created providers for regional consumers:

```hcl
data "aws_iam_openid_connect_provider" "keycloak" {
  url = var.keycloak_issuer_url
}
data "aws_iam_openid_connect_provider" "stage_keycloak" {
  count = var.stage_keycloak_issuer_url != "" ? 1 : 0
  url   = var.stage_keycloak_issuer_url
}
data "aws_iam_openid_connect_provider" "prod_keycloak" {
  count = var.prod_keycloak_issuer_url != "" ? 1 : 0
  url   = var.prod_keycloak_issuer_url
}
```

The shared SRE role and the Lambda invoker role's trust policies — which encode the `${oidc_provider_domain}:aud` audience-match conditions — are themselves built inside `deploy/account/modules/shared-iam` (`oidc.tf` for `sre_shared`, `lambda-invoker.tf` for the invoker role), using `var.keycloak_provider_arn` and the optional stage/prod provider ARNs that the account root supplies as inputs. Regional Terraform does not construct these trust policies; its only remaining OIDC-provider touchpoint is the `data.aws_iam_openid_connect_provider.keycloak.arn` lookup, which it passes into the create-investigation Lambda's `OIDC_PROVIDER_ARN` environment variable and exposes as a Terraform output. If any regional-owned inline policies reference the OIDC audience, they do so against this same looked-up ARN rather than a regionally-registered provider.

## OIDC consumption by the application

The CLI configures a Keycloak base URL, realm, and OIDC client ID, then performs the browser-based PKCE authorization-code flow against the Keycloak token and authorization endpoints derived from those values.

The create-investigation Lambda receives issuer/client settings as environment variables (`KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, and the optional `STAGE_*`/`PROD_*` equivalents), set by regional Terraform from the same `var.keycloak_issuer_url` and client-id variables used for the account-side provider lookup. The Lambda routes an incoming token by inspecting its unverified `iss` claim, matches it against the primary, stage, or production issuer, fetches that issuer's JWKS endpoint, and verifies signature, expiry, and audience before interpreting identity/group/session-tag claims. Stage and production issuers are accepted only when their corresponding environment variables are configured (non-empty). The Lambda's `get_config` action is a separate bootstrap path authenticated by the AWS invoker role; it returns configuration identifiers before the CLI has completed OIDC setup, and is dispatched before any OIDC token validation occurs.

## Evidence-backed claims

- The dev Kustomize overlay composes the namespace base with a ClusterSecretStore and the CNPG and Keycloak components. [base](repo://deploy/keycloak/base/kustomization.yaml#L1-L4) · [dev overlay](repo://deploy/keycloak/overlays/dev/kustomization.yaml#L1-L10)
- The database ExternalSecret reads two SSM Parameter Store entries and creates `keycloak-db-app`, which is referenced by CNPG initialization and the Keycloak database settings. [ExternalSecret](repo://deploy/keycloak/components/cnpg/external-secret-db.yaml#L1-L25) · [CNPG cluster](repo://deploy/keycloak/components/cnpg/cluster.yaml#L1-L17) · [Keycloak resource](repo://deploy/keycloak/components/keycloak/keycloak.yaml#L1-L28)
- The Keycloak resource enables HTTP and X-Forwarded proxy headers, while its OpenShift Route uses edge TLS termination and redirects insecure traffic. [Keycloak settings](repo://deploy/keycloak/components/keycloak/keycloak.yaml#L21-L28) · [Route](repo://deploy/keycloak/components/keycloak/route.yaml#L1-L14)
- The `deploy/account` shared-iam module registers the primary Keycloak OIDC provider trust condition on the shared SRE role and conditionally adds stage and production provider trust statements, while `deploy/regional` only performs `data.aws_iam_openid_connect_provider` lookups by issuer URL instead of defining providers itself. [account OIDC trust](repo://deploy/account/modules/shared-iam/oidc.tf#L1-L98) · [regional data lookups](repo://deploy/regional/account-iam.tf#L36-L46)
- The create-investigation Lambda routes an incoming token to the matching configured issuer by its unverified `iss` claim, then validates signature, expiry, and audience against that issuer's JWKS before accepting the token. [issuer routing](repo://lambda/create-investigation/handler.py#L362-L406) · [JWKS validation](repo://lambda/create-investigation/handler.py#L322-L359)
- The CLI derives its authorization and token endpoints from the configured Keycloak base URL, realm, and client ID and runs the PKCE callback flow. [PKCE flow](repo://internal/auth/oidc.go#L45-L135)
- Lambda's `get_config` action is dispatched before OIDC validation and returns only configuration identifiers through the IAM-authenticated invocation path. [early dispatch](repo://lambda/create-investigation/handler.py#L88-L117) · [config response](repo://lambda/create-investigation/handler.py#L1048-L1072) · [CLI invocation](repo://internal/lambda/client.go#L200-L222)

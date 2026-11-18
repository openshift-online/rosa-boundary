# Boundary CLI configuration discovery

Boundary uses IAM invocation permission as the access boundary for `get_config`. A caller authorized to invoke the create-investigation Lambda can read nine deployment settings without supplying an OIDC token to the handler. This lets the CLI locate resources, but it also lets an invoke-only principal identify those resources without authorization to create an investigation. Knowing a role ARN, cluster name or file system ID does not grant access to the resource. The response contains no credentials, investigation contents or employee identifiers.

## Who can read what?

- **Public repository reader:** can read committed deployment configuration without AWS or Keycloak access. That is a different disclosure from invoking Lambda.
- **CLI discovery:** [`config init`](../../internal/cmd/config_commands.go) already knows the bootstrap issuer, realm, client and AWS target. It gets an ID token, exchanges it at STS for invoker-role credentials, then signs a direct Lambda SDK invocation. It does not send the ID token to `get_config`. IAM authorizes the function invocation, not individual JSON actions.
- **Federated caller:** the [account-owned invoker trust](../../deploy/account/modules/shared-iam/lambda-invoker.tf) checks the trusted provider and its audience. Enabled role and UUID restrictions test `aws:RequestTag/roles` and `aws:RequestTag/uuid`. Staging config requires `ai-sd-sre` for the `rosa-boundary-sre` client and disables the UUID allowlist. Without the role check the audience expands to callers satisfying the remaining trust conditions; it does not become anonymous. The handler's `required_groups` check for investigations uses token group/realm-role claims, not the STS request tag. Matching configured names do not make these checks interchangeable.
- **Other IAM principals:** the [regional invoker grant](../../deploy/regional/iam.tf) permits `lambda:InvokeFunction` on this function. The separate [function URL](../../deploy/regional/lambda-create-investigation.tf) requires `AWS_IAM`; its resource-policy grant names the invoker role, not `*`. Neither grant is an exclusive ACL: same-account identities with effective invocation permissions need not be Lambda admins, and invoke permission does not imply permission to read the environment. No external-account invocation grant is specified here. Source and mocked policies do not establish the effective permissions or absence of drift in a live account.

## Disclosure inventory

The [handler](../../lambda/create-investigation/handler.py) returns `action: get_config` and a `config` object:

| Fields | What the caller learns |
|---|---|
| `lambda_function_name`, `ecs_cluster_name`, `aws_region` | Deployment names and location |
| `invoker_role_arn`, `sre_role_arn` | IAM account and role names, not role credentials |
| `keycloak_url`, `keycloak_realm`, `oidc_client_id` | Issuer location, realm and public client identifier, not a client secret |
| `efs_filesystem_id` | Deployment-specific workspace storage identifier, not a mount or file-access grant |

The public [Boundary workspace definitions](../../hcp-terraform/rosa-boundary/main.tf), CLI defaults and regional naming templates disclose more than this response. Inventory by category (values intentionally omitted):

- AWS account IDs, stages, regions and availability zones; workspace and repository names, regional ownership, replication and adoption settings; role prefixes, publisher principals and resource naming/tagging conventions.
- VPC/subnet identifiers and CIDRs, network layout and NAT strategy; image repositories/tags, Lambda packaging, log retention, Bedrock model selection/agreements, logging regions, budget and notification contact.
- Identity provider URL/realm, certificate thumbprint, client ID, session duration, role/group names, ABAC tag names and enforcement switches. These are configuration, not bearer credentials.
- Four distinct employee UUIDs remain in committed `allowed_uuids` values, **including the production account workspace**, although the allowlist is disabled and production regional workspaces omit the values. Disabling enforcement does not remove public or historical copies. These are personal identifiers, not authentication factors. Their disclosure comes from the public workspace definitions, not from `get_config`; changing Lambda authorization would not restrict access to them.

## Scope and verification

The disclosure assessment covers the fields and invocation paths listed above. Adding fields changes what callers can learn. Changing URL authentication, invocation grants, trusted issuers or accounts, or role conditions can change who can learn it. The current CLI sends no application token with `get_config`, so a handler that required one would reject its discovery request.

[Handler tests](../../lambda/create-investigation/test_handler.py) exercise the exact response and token boundary. [Regional](../../deploy/regional/tests/iam-ownership.tftest.hcl) and [account](../../deploy/account/tests/shared-iam.tftest.hcl) mocked Terraform tests check the declared URL/invoker grants and trust conditions. Neither is a live AWS authorization test.

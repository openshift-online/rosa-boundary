# Proposal: ready-to-use Trusted Actions CLI in Boundary

**Status: endpoint configuration implemented in source; rollout and CLI
hardening remain separate.** Building `rta` into the Boundary image does not
authorize API access. The selected endpoint still needs working private DNS,
TLS and network access from the deployed task.

## Runtime configuration

Use the **main Boundary container's ECS task-definition environment**, not an
entrypoint export or an EFS-backed configuration file. ECS Exec does not inherit
environment variables exported by the entrypoint.

| Setting | Source | Purpose |
| --- | --- | --- |
| `RTA_SERVER` | Optional regional Terraform input `rta_server_url`, default empty | Deployment-selected HTTPS origin; omit the env entry when unconfigured. |

No `OCM_CONFIG`, `OCM_KEYRING` or `RTA_TIMEOUT` overrides are added. Keep the
existing default OCM discovery and the CLI's five-minute timeout.

The CLI already supports `RTA_SERVER` and flag-over-environment precedence,
but does not load an RTA config file. Its client appends
`/api/v0/trusted-actions`: configure `https://<approved-host>`, **not** a URL
containing that API suffix. Terraform validates an HTTPS DNS origin with no
credentials, whitespace, query, fragment or path other than an optional
trailing slash. It removes the trailing slash and validates an optional port
in the range 1–65535.

Implementation points:

- [Regional variables](../../deploy/regional/variables.tf) and
  [main container environment](../../deploy/regional/ecs.tf).
- Deployment-specific origins in the Git-managed `variables` lists in
  [Boundary's HCP definition](../../hcp-terraform/rosa-boundary/main.tf).
  Every staging and production regional workspace uses the shared origin;
  do not edit workload variables directly in HCP.
- The create-investigation Lambda preserves `RTA_SERVER` from the base task
  definition. A regression test covers this; no Lambda runtime change is needed.
- For personal dev, explicitly supply the Terraform input through the supported
  local configuration path. A shell `RTA_SERVER` variable is not automatically
  a Terraform input.

## Identity and credential lifetime

Reuse Boundary's existing per-user, human-approved **access-token-only**
credential injection. Do not introduce `RTA_TOKEN`, shared secrets, refresh
tokens, client credentials, or credentials in Terraform/environment variables.
`RTA_TOKEN` is not currently supported by the CLI, and Boundary OIDC/AWS
credentials are not substitutes for a TA bearer token.

The credential helper already writes the minimal OCM config with restrictive
permissions to the ephemeral mount, outside workspace escrow. Keep those mount
checks, permissions and audit exclusions unchanged. Ensure the selected
Boundary profile's OCM environment matches the intended TA deployment.

“Ready to use” means a newly configured session with a valid injected access
token. Injection can be skipped or fail, and **RTA does not refresh tokens** or
reload the file during a running command. Missing/expired credentials should
direct users to this workstation operation, then a new RTA invocation:

```text
rosa-boundary --profile <deployment> session credentials configure ocm <session-id>
```

TA still independently authenticates and authorizes the user and target. Image
installation and Boundary group membership do not grant TA permissions.
Automatic renewal would require a separate identity-design review.

## Endpoint and network rollout

Use TA's approved regional origin as the configuration handoff. Its existing
[`internal_fqdn` output](../../components/trusted-actions/terraform/regional/outputs.tf)
already returns a URL, not merely a hostname; require its HTTPS form. Do not
grant Boundary broad access to TA Terraform state solely to discover this value.

All four staging and production Boundary regional workspaces select
`https://rosa-trusted-actions.dev0.rosav1.devshift.net` through one shared
local in the HCP definition. There is no need for a different
client URL per Region: private DNS and networking determine where that hostname
resolves and whether it is reachable from each VPC.

Primary staging Boundary and the currently declared TA stage deployment share
a VPC/subnets. TA has an internal ALB, private DNS, HTTPS support and VPC-CIDR
ingress; Boundary already permits outbound traffic. Configuring the shared URL
does not itself establish regional DNS or connectivity. Verify deployed DNS,
trusted TLS, network access and backend health separately in each Region.
Internet NAT does not make an internal ALB reachable.

Configuration changes affect new investigation tasks, not running sessions.
Keep Boundary and TA deployment states and release paths separate. Review
effective HCP auto-apply settings and downstream plans before merging.

## Validation and small CLI follow-up

1. Mock-provider Terraform tests cover unset URL, main-container-only
   propagation, trailing slash normalization and invalid origins/ports. No
   credential discovery or timeout overrides are introduced.
2. A Lambda regression verifies the endpoint survives investigation-specific
   environment overrides.
3. Proposed CLI tests/hardening: strict origin and positive-timeout validation;
   environment/flag precedence; access-token freshness rather than the OCM
   config's broader `Armed` predicate; actionable missing/expired-token errors.
   Do not silently refresh or retry action submission.
4. Separately approved new-task verification: actual ECS Exec environment,
   private DNS, verified HTTPS, authenticated read-only catalog access and
   expiry/reconfiguration behavior. No action execution is needed for the
   initial configuration smoke test.

Relevant implementation:
[CLI configuration](../../components/trusted-actions/internal/rta/command.go),
[client URL/TLS handling](../../components/trusted-actions/internal/rta/client.go),
[credential loading](../../components/trusted-actions/internal/rta/auth.go),
[credential helper](../../utils/rosa-boundary-credential-helper).

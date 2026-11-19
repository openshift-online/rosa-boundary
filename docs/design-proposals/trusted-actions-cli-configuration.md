# Proposal: ready-to-use Trusted Actions CLI in Boundary

**Status: proposed, not implemented.** Building `rta` into the Boundary image
does not configure or authorize API access. This follow-up would make an
approved deployment usable without manually passing server URLs or tokens.

## Runtime configuration

Use the **main Boundary container's ECS task-definition environment**, not an
entrypoint export or an EFS-backed configuration file. ECS Exec does not inherit
environment variables exported by the entrypoint.

| Setting | Proposed source | Purpose |
| --- | --- | --- |
| `RTA_SERVER` | Optional regional Terraform input `rta_server_url`, default empty | Deployment-selected HTTPS origin; omit the env entry when unconfigured. |
| `OCM_CONFIG` | Fixed task-definition value `/home/sre/.config/ocm/ocm.json` | Read the existing task-scoped, injected user credentials instead of a legacy EFS-backed `~/.ocm.json`. |
| `OCM_KEYRING` | Fixed empty task-definition value | Avoid selecting a desktop keyring instead of the injected configuration. |
| `RTA_TIMEOUT` | Initially omit | Retain the CLI's five-minute default. |

The CLI already supports `RTA_SERVER` and flag-over-environment precedence,
but does not load an RTA config file. Its client appends
`/api/v0/trusted-actions`: configure `https://<approved-host>`, **not** a URL
containing that API suffix. Validate the Terraform input as an HTTPS origin:
nonempty authority, no credentials, whitespace, query, fragment or path other
than an optional trailing slash. Normalize the trailing slash.

If operations need a timeout override, add a positive whole-number
`rta_timeout_seconds` input and render it as e.g. `300s`. Avoid accepting
arbitrary Go-duration strings in Terraform. The current CLI does not strictly
validate timeout settings; a client timeout does not cancel a server execution.

Implementation points:

- [Regional variables](../../deploy/regional/variables.tf) and
  [main container environment](../../deploy/regional/ecs.tf).
- Deployment-specific origins in the Git-managed `variables` lists in
  [Boundary's HCP definition](../../hcp-terraform/rosa-boundary/main.tf).
  Leave other deployments unset; do not edit workload variables directly in HCP.
- The create-investigation Lambda already preserves unrelated environment
  entries from the base task definition. Test this explicitly for the new
  settings; new Lambda configuration should not be necessary.
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

Current Git configuration places primary staging Boundary and staging TA in
the same VPC/subnets. TA has an internal ALB, private DNS, HTTPS support and
VPC-CIDR ingress; Boundary already permits outbound traffic. Start with that
pairing **after verifying the deployed configuration**, DNS, trusted TLS and
backend health.

Do not copy that origin into all regions or production. Other VPCs need an
explicit connectivity/DNS/ingress design or an independently approved local TA
deployment. Internet NAT does not make an internal ALB reachable.

Configuration changes affect new investigation tasks, not running sessions.
Keep Boundary and TA deployment states and release paths separate. Review
effective HCP auto-apply settings and downstream plans before merging.

## Validation and small CLI follow-up

1. Mock-provider Terraform tests: unset URL omits `RTA_SERVER`; a valid origin
   reaches only the main container; malformed origins fail; credential discovery
   points at the existing ephemeral mount.
2. Lambda regression: deployment defaults survive investigation-specific
   environment overrides.
3. CLI tests/hardening: strict origin and positive-timeout validation;
   environment/flag precedence; access-token freshness rather than the OCM
   config's broader `Armed` predicate; actionable missing/expired-token errors.
   Do not silently refresh or retry action submission.
4. Shell/local integration tests: a synthetic legacy `~/.ocm.json` cannot
   shadow the injected file under the proposed defaults; credential material
   remains absent from persistent workspace/audit output.
5. Separately approved new-task verification: actual ECS Exec environment,
   private DNS, verified HTTPS, authenticated read-only catalog access and
   expiry/reconfiguration behavior. No action execution is needed for the
   initial configuration smoke test.

Relevant implementation:
[CLI configuration](../../components/trusted-actions/internal/rta/command.go),
[client URL/TLS handling](../../components/trusted-actions/internal/rta/client.go),
[credential loading](../../components/trusted-actions/internal/rta/auth.go),
[credential helper](../../utils/rosa-boundary-credential-helper).

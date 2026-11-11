# Step 6 — Personal AWS and Keycloak access

Prerequisites:
`python3 .agents/skills/onboarding/scripts/check.py 6 --summary /private/path/summary.json`.
Use the actual completed step 5 report, not the literal placeholder. Confirm the
report belongs to this checkout/revision and the observed full run exited zero;
the script checks statuses, not provenance. Local tests need no real AWS/Keycloak
identity; this step prepares the separate required live workflow.

Follow [personal-dev prerequisites and Keycloak access](../../../../docs/runbooks/personal-dev-bootstrap.md).
Ask the user to obtain their personal development account and approved region,
authenticate with their organization's approved AWS account-access tooling,
request a non-admin SRE login/role/group in the approved development realm, and
confirm realm/client/issuer/principal-tag settings with its operator. They must
install AWS CLI v2, Session Manager plugin and GitHub tooling if still absent.
Do not create an account or assume another contributor's configuration.

No AWS account-creation document was supplied with this skill. If a new account is
needed, ask the user for their approved process/document and **halt**; do not
invent organization-specific instructions. For authentication, account requests,
Keycloak provisioning or any user action, give the linked instructions and
**halt until they respond**. They may need to exit/restart this coding session.

After response, verify STS identity read-only and have the user confirm the
account is personal dev, not staging/production. Never print tokens or read SSO
caches. Keycloak user/group claims need operator confirmation and ultimately
live verification, not just a successful STS request. Record non-secret account,
region and access status. Complete the checklist below before handing off to step 7.

## Deployment input checklist

Before asking questions, inspect existing **approved personal-dev** configuration
privately: account/network/regional tfvars, the root `.env`, and any prior private
handoff. Compare the target with STS and the owning Terraform provider account
guard. Existing files are hints, not proof of current authorization or realm
claims; never source an untrusted `.env` or dump tfvars/state/secrets.

Present one consolidated list of **missing, conflicting, or unconfirmed** inputs
and halt for the user's response. Do not ask again for an unchanged confirmed
value unless verification exposes a mismatch. Record the answer's provenance
(operator/user confirmation versus observed AWS state) and what remains unverified.
Use a private, gitignored record with restricted permissions; do not put personal
configuration into this skill or a PR.

| Input | What must be established |
| --- | --- |
| Deployment scope | Boundary personal dev, approved account and explicit Region(s), source revision/working-tree fingerprint; not Trusted Actions or HCP staging/production. |
| State and network | New versus existing account/network/regional roots, backend/workspace ownership, shared role prefix and legacy policy Region; existing VPC/private subnets and routing, or approved new-network configuration. |
| Keycloak identity | Approved issuer/base URL, realm, public client ID, independently verified TLS thumbprint, and non-admin SRE access. Reuse a confirmed issuer rather than deploying Keycloak again. |
| ABAC mapping | Exact principal-tag key emitted by this realm and consumed by `abac_tag_key`. `username` and `uuid` are examples, not interchangeable defaults. |
| Group and role claims | Actual `required_groups` and the separate `required_oidc_role`/role-tag mapping used by account trust enforcement. `ai-sd-sre` is an example, not proof of realm configuration; do not disable enforcement to make login work. |
| Task image | User-approved existing image or approved build/publication scope; resolve platform and registry digest, and record source provenance. Do not silently select `latest` or assume the infrastructure and image revisions match. |
| Lambda and sidecar | ZIP versus Image packaging, required build prerequisites/artifacts, and intended kube-proxy setting. Without an approved working cluster kubeconfig secret, propose disabling kube-proxy explicitly. |
| Budget and model access | Confirm this account's budget amount/recipient and any approved model-agreement manifest. Alerts are not a spending cap; do not accept model offers implicitly. |
| Audit effects and cost | Intended retention, audit Object Lock mode, account/Region-wide Bedrock logging scope/readers, and ongoing endpoint/storage/KMS/logging costs; actual plan approval remains separate. |
| Live test, if requested | Approved cluster/endpoint, identity, bounded duration/cost, evidence reader and cleanup contract. Infrastructure deployment is not authorization to launch a test. |

Map confirmed inputs into the owning root's private configuration, after approval
to write it. For regional Makefile use, explicitly set `KEYCLOAK_ISSUER_URL`,
`TF_VAR_abac_tag_key`, and `TF_VAR_enable_kube_proxy` in the gitignored root
`.env`; the Makefile's ABAC/kube-proxy exports can override tfvars. Verify optional
issuer overlays and effective variable precedence without printing secrets.
Never infer a realm's ABAC mapping from those fallbacks.

A user's confirmation supplies configuration, not runtime proof. Authentication,
group authorization and identity isolation remain live-verification boundaries.
Next: step 7.

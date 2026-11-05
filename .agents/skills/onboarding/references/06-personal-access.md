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
region and access status. Next: step 7.

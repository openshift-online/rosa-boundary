# Approve and verify Bedrock model access in personal dev

Complete this gate before treating a coding agent as ready. Provider configuration,
a successful Terraform apply and an ACTIVE model profile do not prove inference
access. This procedure is for an approved personal development account, not HCP
staging/production. Never copy another contributor's account or model approvals.

## 1. Confirm the target and obtain approval

Confirm the personal account, source region, operator identity, exact foundation
model and inference profile, approved processing geography, and intended agents.
Prefer one approved Claude profile shared by Claude Code, pi and OpenCode; Codex
needs its own Responses-compatible model. A US profile must not be silently
replaced with a global profile. Check availability and pricing for the exact
selection; do not activate additional models merely for discovery.

Obtain explicit approval before submitting organization information, accepting
model terms/offers, creating subscriptions, or making a paid inference request.
Agree on a harmless prompt, token/time/cost bounds and no customer data for a
smoke test. Approval to configure Terraform is not approval to accept terms.
Budget notifications are not spending limits.

## 2. Complete the Anthropic first-use form as an account operator

Authenticate with the contributor's approved AWS tooling and confirm the account
with STS. When using `rh-aws-saml-login`, open a console session in the target
account rather than relying on an unrelated browser login:

```bash
# Set ACCOUNT, REGION and AWS_LOGIN_SOURCE to the approved contributor values.
rh-aws-saml-login --no-display-banner \
  --assume-uid "${ACCOUNT:?}" --region "${REGION:?}" \
  --session-timeout 15 --console --console-service bedrock \
  "${AWS_LOGIN_SOURCE:?}"
```

Verify the account and role in the console. Open the chosen Anthropic model in
Bedrock's model catalog and complete the first-use/use-case form if requested.
The contributor must supply accurate organization and intended-use information;
an agent must not invent declarations or implicitly accept terms. Review any
model offer/terms separately before approving activation.

After the contributor responds, verify the form registration read-only using
`bedrock get-use-case-for-model-access`, without printing or retaining the returned
organization form data. A `ResourceNotFoundException` saying the request form has
not been filled out is a concrete onboarding blocker. A successful form response
is not proof of model activation or successful inference.

## 3. Verify activation, permissions and propagation

Check the selected model's regional availability and the approved account model
agreement manifest. `get-foundation-model-availability` authorization/entitlement
metadata and `list-inference-profiles` ACTIVE status are useful inventory, not a
substitute for an actual response. Neither a single `agreementAvailability` value
nor a Marketplace error alone establishes the full cause.

Errors mentioning `aws-marketplace:ViewSubscriptions` or
`aws-marketplace:Subscribe` can occur while Bedrock attempts model activation.
After form/permission/activation changes, allow the propagation interval in the
AWS error (for example five minutes) before a bounded retry. If it persists,
verify the console identity, exact model/account/region, operator IAM, session
restrictions, boundaries and organizational controls. Policy simulation alone is
not proof that the live subscription path will succeed.

**Do not add Marketplace subscription permissions to investigation task roles.**
Use an approved account operator for activation. Terraform-managed model offers
belong to `deploy/account/bedrock-model-agreements.tf`, with a reviewed offer ID;
the regional root consumes the matching manifest for default-model validation.
Do not import/adopt an existing console activation, cancel an agreement or enable
a duplicate subscription without an explicit ownership/plan review. An empty
manifest does not prove access is disabled or activation complete.

## 4. Prove the selected model works, then configure agents

With explicit live-test approval, send one harmless, token-bounded request through
the console playground or approved client. Record the exact profile, account,
region and result; user-reported success must be labelled as such. Console
success proves that operator's path, not the investigation task's IAM/endpoint
path. Verify a separate bounded request from the actual agent/task identity
before claiming runtime success. Do not create an investigation without separate
approval. Do not read customer prompts or credential material for troubleshooting.

Configure `claude_default_model` for the shared Claude/pi/OpenCode selection and
keep `codex_default_model` separate. Review/apply through the owning Makefile and
verify the deployed task environment. A new task definition does not update an
existing session. The initializer preserves saved pi/OpenCode settings; select
the model explicitly when reusing a home. See
[coding-agent configuration](../configuration/coding-agent-bedrock.md).

Record approval status, selected model, deployment revision, observed inference
result, remaining runtime/audit gaps and the next resumable action privately.
Keep tokens, form data, signed console URLs, plans and state out of Git. Never
mark onboarding fully verified solely because a playground or model catalog works.

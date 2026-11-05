# Step 4 — Start and verify LocalStack

Prerequisites: run `python3 .agents/skills/onboarding/scripts/check.py 4`.
It checks tools, root dependencies, token presence and engine reachability without
displaying secrets. Confirm the user completed LocalStack and HCP access requests.

Inspect the current root Makefile startup/readiness recipes. Ask approval for
the image download and local emulated resources and **halt until they respond**.
Then follow [LocalStack startup](../../../../docs/runbooks/contributor-local-setup.md#2-request-localstack-access)
using the uv-managed environment. On macOS include GNU coreutils on PATH for
startup; unlike shell tests, startup does not supply GNU timeout itself.
Use `uv run --group localstack make localstack-up` (with the documented macOS
PATH adjustment), then `uv run --group localstack make localstack-ready`.

Completion requires live HTTP and required-service readiness, not a tracker file
or mere container existence. Retain failures privately. For license activation
failure, tell the user to fix workspace entitlement/token privately and halt;
do not retry with a longer timeout. Use [troubleshooting](../../../../tests/localstack/README.md#troubleshooting)
for engine/service failures. Never replace this with real AWS or a regional
Terraform apply. Next: step 5.

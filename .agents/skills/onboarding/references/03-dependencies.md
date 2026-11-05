# Step 3 — Dependencies and engine

Prerequisites: run `python3 .agents/skills/onboarding/scripts/check.py 3`.
Missing executables block this step: direct the user to step 1 and halt.
Confirm step 2's access status; access can still be pending while installing
dependencies, but must be resolved before steps 4–5.

Inspect git status. Explain downloads, repository trust, dependency installation,
hook installation and local container effects. Ask permission and **halt until
the user responds**. Preserve unrelated work; do not stash/reset it.

After approval, use the applicable [mise or non-mise setup sequence](../../../../docs/runbooks/contributor-local-setup.md#1-set-up-your-development-tools):
trust reviewed mise configuration, install selected tools/dependencies, sync the
root LocalStack group and install pre-commit. The nested LocalStack Python project
is a CI adapter, not another environment to install. Verify the resulting tools
are visible to this coding session; ask for a restart and halt if necessary.

Follow [platform engine setup](../../../../docs/runbooks/contributor-local-setup.md#2-request-localstack-access)
for Podman machine initialization/start on macOS or rootless socket setup on
Linux. If the user must install/enable anything, give the exact applicable
instructions and halt. Do not hardcode socket paths or change XDG_RUNTIME_DIR.

Completion: `podman info` succeeds and the step 4 assertion passes. That assertion
also needs the private token file: if missing, return to step 2 and halt.
Next: step 4.

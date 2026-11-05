# Step 1 — Workstation tools

Prerequisites: an existing checkout, Git and Make. Run
`python3 .agents/skills/onboarding/scripts/check.py 1`; if Python is absent,
ask the user to install it first and halt (the assertion cannot run without it).
Read [development standards](../../../../docs/development-standards.md).

Follow [tool installation](../../../../docs/runbooks/contributor-local-setup.md#1-set-up-your-development-tools),
including the mise/non-mise alternatives, uv, standalone lint tools, macOS GNU
utilities and workstation-wide OpenWiki/AWS/GitHub tools. Do not guess versions:
inspect mise.toml, go.mod, pyproject.toml and current Make recipes. If a declared
version is unavailable, report it rather than silently changing repository pins.

Ask the user to install missing tools, activate mise and open a fresh shell if
needed; **halt until they confirm**. Do not install system/global tools for them.
The dependency commands in that guide belong to step 3; do not run them twice.
OpenWiki installation does not authorize regeneration or require model secrets.
Completion: tool commands resolve in the agent's shell; run the step 3 assertion
to identify any remaining tool gaps. Next: step 2.

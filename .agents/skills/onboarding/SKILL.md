---
name: onboarding
description: Set up or resume ROSA Boundary contributor onboarding, including tools, LocalStack Pro, make test-all, and personal AWS/Keycloak access. Use when a contributor asks to onboard or continue onboarding from a numbered step.
---

# Contributor onboarding

Run from the repository root. Read only the requested step's reference; default to
step 1. Keep these numbers stable so “continue onboarding from step 3” works.
Run that step's prerequisite assertion even when earlier steps were skipped;
a failed assertion blocks progress, not permission to skip it.

1. [Workstation tools](references/01-tools.md)
2. [License and registry access](references/02-access.md)
3. [Dependencies and container engine](references/03-dependencies.md)
4. [Start and verify LocalStack](references/04-localstack.md)
5. [Run all local gates](references/05-test-all.md)
6. [Personal AWS and Keycloak access](references/06-personal-access.md)
7. [Approved live verification and PR handoff](references/07-live.md)

## Pause and resume contract

Before asking the user to install, authenticate, obtain access, edit private
configuration, approve an action, or do any other work: explain exactly what they
must do using the reference, then **halt the turn until they respond**. Never
continue dependent work while waiting. If a new shell/session is needed, tell
them to return with “continue onboarding from step N”. Do not solicit secrets in
chat or print credential files. A user's response is not proof: rerun assertions
and verify outcomes. Ask before downloads, hooks that rewrite files, or local
resource/image creation; preserve unrelated work.

At every pause record: current step, passed assertions, blocked prerequisite,
next action, and private evidence paths (no secret values). On resume recheck
current state, not just the previous checklist. Never auto-apply Terraform,
publish images, or create investigations; step 7 needs separate live approval.
Local completion means step 5 ran to completion; report skips as unverified,
not passed. Personal-AWS verification is a separate completion boundary.

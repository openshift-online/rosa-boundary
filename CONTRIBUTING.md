# Contributing to ROSA Boundary

Start with [development standards](docs/development-standards.md). For guided,
resumable setup, use the [onboarding skill](.agents/skills/onboarding/SKILL.md);
you can ask a coding agent to “continue onboarding from step 3”. Each step checks
its prerequisites and pauses for installations, access requests or authentication.

## Contributor setup

1. Follow [local setup](docs/runbooks/contributor-local-setup.md) for workstation
   tools, LocalStack Pro licensing/startup and HCP private-module access.
2. Run `make test-all` to completion; see [testing](docs/testing.md#exhaustive-local-validation)
   for artifacts, failures and incomplete coverage. Skips are not verified behavior.
3. **Before opening a PR**, deploy and verify the affected behavior in your personal
   AWS development account using [personal-dev bootstrap](docs/runbooks/personal-dev-bootstrap.md)
   and separately approved [live verification](.agents/skills/boundary-live-verification/SKILL.md).
   LocalStack is not a substitute. Verify revision/artifact provenance, obtain
   approval before AWS changes/investigation creation, and record audit evidence
   and cleanup. Never target staging or production with local dev commands.

## Open a PR from an upstream branch

Create feature branches directly in `openshift-online/rosa-boundary` and open PRs
from those branches against its `main` branch, **not from a fork**. HCP Terraform
only runs speculative plans for PRs from branches in the connected upstream
repository; fork PRs do not trigger those plans.

For example, if your `upstream` remote points to
`git@github.com:openshift-online/rosa-boundary.git`:

```bash
git fetch upstream
git switch -c my-change upstream/main
# Make your changes, run checks, and commit them.
git push -u upstream my-change
gh pr create --repo openshift-online/rosa-boundary --base main --head my-change
```

Use your configured remote name if it differs, and verify its URL with
`git remote -v` before pushing. If you do not have upstream write access, ask a
maintainer to push the reviewed changes to an upstream branch and open the PR
there so speculative plans can run.

For infrastructure changes, review the applicable HCP Terraform plan checks
before merging. Local Terraform validation is not a substitute for these plans.
See the [staging delivery workflow](docs/staging-deployment.md#how-a-code-change-becomes-live)
for plan, review, and apply behavior.

## Further reading

- [Personal-dev bootstrap](docs/runbooks/personal-dev-bootstrap.md): fresh-account
  IAM/OIDC, VPC, image publication, regional deployment, CLI setup and live cleanup.
- [Testing guide](docs/testing.md): complete suite coverage, prerequisites, skip
  handling, synthetic identity and test-only CLI fixtures, and the boundary
  between local checks and live AWS verification.
- [LocalStack guide](tests/localstack/README.md): integration fixtures, emulator
  limitations, and troubleshooting.
- [User access guide](docs/runbooks/user-access-guide.md): authentication and
  group access for a real Boundary deployment; separate from local test setup.

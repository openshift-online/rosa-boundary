# Agent Context

This is a routing guide, not a snapshot of the implementation. Start with the relevant documentation, then verify behavior against current source and tests before changing it. Do not infer current behavior from this file or dated runbooks.

## Where to look

| Task | Start here | Verify against |
|------|------------|----------------|
| Architecture, identity, investigations, audit | [docs index](docs/README.md) | Relevant code in `internal/`, `lambda/`, `deploy/`, and the entrypoint |
| CLI and user workflows | [CLI authentication](docs/architecture/cli-authentication.md), [runbooks](docs/runbooks/investigation-workflow.md) | CLI implementation and tests in `internal/` |
| Container and shell | [development standards](docs/development-standards.md) | `Containerfile`, `entrypoint.sh`, `skel/`, `build/`, shell tests |
| Tests and CI | [testing guide](docs/testing.md), [LocalStack guide](tests/localstack/README.md) | Makefiles, test suites, CI configuration |
| Infrastructure and deployments | [regional README](deploy/regional/README.md), [staging guide](docs/staging-deployment.md) | Terraform roots under `deploy/`, workspace definition under `hcp-terraform/` |
| Keycloak | [realm setup](docs/configuration/keycloak-realm-setup.md) | `deploy/keycloak/` |
| Cross-cutting questions needing repository context | [OpenWiki](openwiki/quickstart.md) (on demand; see guidance below) | Current source and tests |

## CLI quickstart context

For CLI installation and deployment-specific configuration, use the [user access guide](docs/runbooks/user-access-guide.md) and current root Makefile. For a basic end-to-end check, follow the [investigation workflow](docs/runbooks/investigation-workflow.md): authenticate, start and join a task, write a harmless workspace artifact, disconnect, stop the task, verify CloudWatch session logs and S3 audit evidence, then close the investigation. Confirm the authorized target, account, region, and cleanup plan before creating resources. Check CLI help and source if a runbook disagrees; leaving an ECS Exec shell does **not** stop the task or prove that audit sync succeeded.

## Design constraints

- Do not introduce static, long-lived, or shared **credential material** into Boundary runtime or investigations. Prefer per-user, short-lived identity and task-scoped credentials; keep secrets off persistent workspaces and audit escrow. A shared IAM role issuing separate temporary, identity-scoped sessions is not itself a shared credential. Investigate any existing credential path against this constraint before extending it.
- Prefer AWS-native managed services over bespoke or additional runtime dependencies when they meet the same identity, isolation, audit, and lifecycle requirements. For exceptions, document why a native alternative cannot meet those requirements or would introduce worse failure modes. Do not replace a working control solely because an AWS service exists.

## Rules to apply before editing

- Follow [development standards](docs/development-standards.md) for security invariants, build constraints, and quality gates; check current implementation and affected tests rather than copying details from here.
- Use the repository's Makefiles for builds and local dev Terraform; inspect their current recipes before choosing targets. Use the [staging delivery path](docs/staging-deployment.md), not local dev commands, for HCP deployments.
- For local dev, consult Terraform variable definitions and the regional Makefile for required inputs and precedence. Ask for missing configuration; never hardcode environment-specific values, print secrets, or commit credentials.
- Change Git-managed staging workspace variables through a PR, not directly through HCP UI/API/MCP. Inspect the [workspace definition](hcp-terraform/rosa-boundary/main.tf) for the current variable owner and apply settings before changing or approving anything.
- Before deployment, verify target account and region, image and architecture, plan, and scope. Choose tests based on the change using the [testing guide](docs/testing.md) and actual Make recipes; report checks not run.

<!-- OPENWIKI:START -->

## OpenWiki

This repository has a generated `openwiki/` evidence index. It is optional just-in-time context, not required startup reading.

- Do not enumerate, preload, or search wikis at task start. Use retrieval when the user asks for it, when unfamiliar architecture or dependency behavior materially affects the task, or when source inspection leaves an important uncertainty. Stop once the question is grounded.
- When those conditions apply and OpenWiki retrieval tools are available, use `openwiki_search` for just-in-time context and `openwiki_read` for the relevant complete sections. If search returns `workspace_required`, ask which listed workspace to use and retry with its ID.
- Use `openwiki_list_workspaces` or `openwiki_list_wikis` when workspace membership itself needs to be discovered.
- If the retrieval tools are unavailable, read `openwiki/quickstart.md` and follow its links to the relevant pages.
- Treat source code and tests as authoritative. A brief's unknowns and review items are verification gaps, not automatic requirements.
- Prefer the narrowest quiet validation that proves the changed behavior. Preserve complete failure output.

Do not hand-edit generated OpenWiki pages unless explicitly asked; prefer updating source code/docs and regenerating the wiki through the approved CI process.

<!-- OPENWIKI:END -->

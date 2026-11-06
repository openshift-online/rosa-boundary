# Agent Context

This is a routing guide, not a snapshot of the implementation. Start with the relevant documentation, then verify behavior against current source and tests before changing it. Do not infer current behavior from this file or dated runbooks.

## Where to look

| Task | Start here | Verify against |
|------|------------|----------------|
| Boundary architecture, identity, investigations, audit | [Boundary docs index](docs/README.md) | Boundary code in root `internal/`, `lambda/`, `deploy/`, and the entrypoint |
| Boundary CLI and user workflows | [CLI authentication](docs/architecture/cli-authentication.md), [runbooks](docs/runbooks/investigation-workflow.md) | Root `internal/` and CLI tests |
| Boundary container and shell | [development standards](docs/development-standards.md) | Root `Containerfile`, `entrypoint.sh`, `skel/`, `build/`, shell tests |
| Boundary tests and CI | [testing guide](docs/testing.md), [LocalStack guide](tests/localstack/README.md); use [change verification skill](.agents/skills/boundary-change-verification/SKILL.md) for diff-scoped checks | Root Makefile, test suites, and CI configuration |
| Boundary infrastructure and deployments | [regional README](deploy/regional/README.md), [staging guide](docs/staging-deployment.md) | Terraform roots under `deploy/`, Boundary workspace definitions under `hcp-terraform/rosa-boundary/` |
| Trusted Actions API, CLI, image, and tests | [TA README](components/trusted-actions/README.md), [TA contributor guidance](components/trusted-actions/CLAUDE.md), [TA testing](components/trusted-actions/TESTING.md) | `components/trusted-actions/` source, its `go.mod`, Makefile, generated-code rules, and tests |
| Trusted Actions Terraform and delivery | [source co-location and cutover](docs/trusted-actions-source-colocation.md), [TA deployment guide](components/trusted-actions/docs/deployment.md) | `components/trusted-actions/terraform/{global,regional}/`, `hcp-terraform/rosa-trusted-actions/`, `.tekton/rosa-trusted-actions-*.yaml` |
| Keycloak | [realm setup](docs/configuration/keycloak-realm-setup.md) | `deploy/keycloak/` |
| Cross-cutting questions needing repository context | [OpenWiki](openwiki/quickstart.md) (on demand; see guidance below) | Current source and tests |

## Verification skills

Repository skills live in `.agents/skills/`; `.claude/skills` points to the same directory for Claude Code discovery. Use [docs-drift-review](.agents/skills/docs-drift-review/SKILL.md) to audit documentation and [adversary](.agents/skills/adversary/SKILL.md) for security reviews when relevant.

- The Boundary verification skills below cover Boundary changes, not the separate Trusted Actions test suite or deployment. For TA changes, check its own Makefile and tests; run commands in `components/trusted-actions/`, not from the repository root.
- Use [boundary-change-verification](.agents/skills/boundary-change-verification/SKILL.md) to select and run diff-scoped **local Boundary** checks; it does not deploy or create AWS resources. Hand off required live assertions and provenance gaps rather than claiming mocks or plans prove real behavior.
- Use [boundary-live-verification](.agents/skills/boundary-live-verification/SKILL.md) for an approved test against a contributor's **personal dev** environment. Verify the exact changeset and deployed artifacts before reuse; obtain explicit approval for AWS changes and investigation creation, then record audit evidence and cleanup. Never use it for staging or production.

## Component boundaries

- Boundary's CLI, container, and Lambda applications still live at the repository root; `components/trusted-actions/` is a separate Go module, image, API, CLI, and test tree. Root `go test ./...` and root Make targets do **not** test the TA module. Do not move Boundary's `lambda/` into `components/` as part of the source-import milestone; paths in Terraform, tests, Makefiles, and Konflux must be migrated together in a separate change.
- The TA source import did not change deployed infrastructure. Boundary's `deploy/account/`, `deploy/network/`, and `deploy/regional/` and TA's `components/trusted-actions/terraform/global/` and `terraform/regional/` are separate Terraform roots and states. Never copy TA resources into a Boundary root or enable a duplicate TA stack merely because the code now shares a repository.
- `.tekton/` contains separately scoped Boundary container, Boundary Lambda, and TA image pipelines; component ownership is defined in nested `OWNERS` files. A TA-only change must not silently alter Boundary build/deployment behavior. Verify Prow ownership and external CI bindings on real PRs rather than assuming the source layout proves independent merging.

## CLI quickstart context

For CLI installation and deployment-specific configuration, use the [user access guide](docs/runbooks/user-access-guide.md) and current root Makefile. For a basic end-to-end check, follow the [investigation workflow](docs/runbooks/investigation-workflow.md): authenticate, start and join a task, write a harmless workspace artifact, disconnect, stop the task, verify CloudWatch session logs and S3 audit evidence, then close the investigation. Confirm the authorized target, account, region, and cleanup plan before creating resources. Check CLI help and source if a runbook disagrees; leaving an ECS Exec shell does **not** stop the task or prove that audit sync succeeded.

## Design constraints

- Do not introduce static, long-lived, or shared **credential material** into Boundary runtime or investigations. Prefer per-user, short-lived identity and task-scoped credentials; keep secrets off persistent workspaces and audit escrow. A shared IAM role issuing separate temporary, identity-scoped sessions is not itself a shared credential. Investigate any existing credential path against this constraint before extending it.
- Prefer AWS-native managed services over bespoke or additional runtime dependencies when they meet the same identity, isolation, audit, and lifecycle requirements. For exceptions, document why a native alternative cannot meet those requirements or would introduce worse failure modes. Do not replace a working control solely because an AWS service exists.
- Trusted Actions has its own authentication, authorization, credentials, and audit design. Do not conflate it with Boundary's OIDC/ECS Exec model or assume shared audit coverage; inspect the TA implementation and its own deployment before asserting integration.

## Rules to apply before editing

- Follow [Boundary development standards](docs/development-standards.md) for Boundary changes and [TA contributor guidance](components/trusted-actions/CLAUDE.md) for TA changes; verify current implementation and affected tests rather than copying dated details from either guide.
- Use each component's Makefile for supported builds and tests, and Boundary's regional Makefile for local Boundary Terraform; inspect current recipes before choosing targets. TA Terraform roots have no Makefile. Use the [staging delivery path](docs/staging-deployment.md), not local dev commands, for Boundary HCP deployments.
- For Boundary local dev, consult Terraform variable definitions and the regional Makefile for required inputs and precedence. For TA, check its own Terraform variables and [deployment guide](components/trusted-actions/docs/deployment.md). Ask for missing configuration; never hardcode environment-specific values, print secrets, or commit credentials.
- Change Git-managed staging workspace variables through a PR, not directly through HCP UI/API/MCP. Inspect the owning [Boundary](hcp-terraform/rosa-boundary/main.tf) or [TA](hcp-terraform/rosa-trusted-actions/main.tf) workspace definition for current settings before changing or approving anything. The copied TA definition still targets the original TA repository and working directories; rebind the existing HCP workspaces only through a separately reviewed cutover, checking live auto-apply, runs, state permissions, and downstream plans first.
- Before deployment, verify target account and region, image and architecture, plan, and scope. Choose tests based on the affected component's [Boundary](docs/testing.md) or [TA](components/trusted-actions/TESTING.md) testing guide and actual Make recipes; report checks not run.

<!-- OPENWIKI:START -->

## OpenWiki

Boundary has a generated root `openwiki/` evidence index; TA also has its own imported `components/trusted-actions/openwiki/`. Neither is required startup reading, and TA's copy may still describe the original repository layout. Verify consequential details against current code and deployment.

- Do not enumerate, preload, or search wikis at task start. Use retrieval when the user asks for it, when unfamiliar architecture or dependency behavior materially affects the task, or when source inspection leaves an important uncertainty. Stop once the question is grounded.
- When those conditions apply and OpenWiki retrieval tools are available, use `openwiki_search` for just-in-time context and `openwiki_read` for the relevant complete sections. If search returns `workspace_required`, ask which listed workspace to use and retry with its ID.
- Use `openwiki_list_workspaces` or `openwiki_list_wikis` when workspace membership itself needs to be discovered.
- If the retrieval tools are unavailable, read [openwiki/quickstart.md](openwiki/quickstart.md) and follow its links to the relevant pages.
- Treat source code and tests as authoritative. A brief's unknowns and review items are verification gaps, not automatic requirements.
- Prefer the narrowest quiet validation that proves the changed behavior. Preserve complete failure output.

Do not hand-edit generated OpenWiki pages unless explicitly asked; prefer updating source code/docs and regenerating the wiki through the approved CI process.

<!-- OPENWIKI:END -->

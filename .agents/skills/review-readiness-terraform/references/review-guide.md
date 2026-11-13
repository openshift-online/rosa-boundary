# ROSA Boundary workspace and evidence guide

Use this after a positive gate; verify current source and live workspace settings. This is routing, not a deployment inventory or a statement that a copied definition is active.

| Paths | Terraform owner / typical blast radius |
| --- | --- |
| `hcp-terraform/rosa-boundary/` | Boundary HCP meta-workspace: VCS connections, stage/prod workspaces, variables, run triggers and apply settings. A meta speculative plan alone cannot show AWS changes. |
| `hcp-terraform/aws-creds/rosa-boundary-{stage,prod}/` | HCP dynamic AWS credential trusts/roles; account-level authorization. |
| `deploy/account/` | Boundary account-global IAM/OIDC/Bedrock/ECR resources, shared across regions. |
| `deploy/network/` | Boundary stage/prod network roots; VPC/NAT/subnets/endpoints shared by regional workloads. |
| `deploy/regional/` | Boundary regional ECS/EFS/Lambda/S3/CloudWatch/KMS/IAM; same source can fan out to multiple regions and accounts. |
| `hcp-terraform/rosa-trusted-actions/` | Trusted Actions HCP definition; existing workspaces were rebound to this repo. Verify their live VCS binding and settings before relying on triggered plans. |
| `components/trusted-actions/terraform/global/` | Separate TA global account state: shared IAM, secrets and DNS; not Boundary account state. |
| `components/trusted-actions/terraform/regional/` | Separate TA regional state: networking, ECS, audit pipeline and state dependency on global. |
| `tests/localstack/terraform/` | Test fixtures: check whether only tests change or production resource behavior changes too. |

For Boundary delivery, start with `docs/staging-deployment.md` and current `hcp-terraform/rosa-boundary/main.tf`. For Trusted Actions, start with `components/trusted-actions/AGENTS.md`, `components/trusted-actions/docs/deployment.md`, `docs/trusted-actions-monorepo-migration.md` and current HCP definition. Do not rely on historical auto-apply or VCS-binding statements without rechecking.

PR evidence: `gh pr view` for body/head/base; `gh api repos/openshift-online/rosa-boundary/issues/NUMBER/comments --paginate` for discussion; `gh api repos/openshift-online/rosa-boundary/pulls/NUMBER/comments --paginate` for inline reviews; `gh pr checks` and `gh api repos/openshift-online/rosa-boundary/commits/SHA/status` for checks/status links. Terraform's aggregated commit status can hide multiple workspaces: follow it to individual HCP plans, or mark their details unavailable. Check that plans/CI correspond to the PR head, not merely the same branch name. Plan details, state, and CI logs may be sensitive: report resource addresses/actions and redacted evidence references, not raw secret values.

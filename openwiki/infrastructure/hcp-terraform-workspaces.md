---
type: infrastructure integration
title: HCP Terraform workspace integration
description: Traces ROSA Boundary's tenant bootstrap, meta-workspace, AWS credentials and staging workload workspaces across repositories, including run scheduling and a checklist for adding workspaces.
tags: [terraform, hcp-terraform, workspaces, staging, deployment]
verified:
  - by: openwiki/0.7.0
    at: 2026-10-06T17:52:44.901Z
sources:
  - id: openwiki-source-45393b666c4d8ce854ed025b
    resource: repo://deploy/account/README.md
  - id: openwiki-source-d1dce668163058effacc5e53
    resource: repo://deploy/network/main.tf
  - id: openwiki-source-57978093f4049406c4540f6b
    resource: repo://deploy/network/outputs.tf
  - id: openwiki-source-a467cf2af07b3f58e60a50ab
    resource: repo://deploy/regional/main.tf
  - id: openwiki-source-b9cdc6ab772f1188b137a1a8
    resource: repo://hcp-terraform/aws-creds/rosa-boundary-stage/main.tf
  - id: openwiki-source-81722021d767635aca673ab8
    resource: repo://hcp-terraform/rosa-boundary/main.tf
generated: { by: "opencode", at: "2026-10-06T17:52:44.901Z" }
---

# HCP Terraform workspace integration

This page describes the **declared staging configuration**, not a live inventory of HCP Terraform runs. The tenant bootstrap and reusable modules live in [openshift-online/infra-platform](https://github.com/openshift-online/infra-platform); the project-specific meta-workspace and AWS workloads live in this repository. For resource-level details see [regional infrastructure](regional-runtime.md); for the deployment walkthrough see [`docs/staging-deployment.md`](../../docs/staging-deployment.md), but use the Terraform definitions below when its apply settings disagree.

## Ownership and why there are multiple workspaces

```
infra-platform: rosa-bootstrap                    (L1, Default project)
  hcp-terraform/tenants/rosa
      │ creates rosa-boundary and meta-rosa projects, teams, policies,
      │ meta-rosa-rosa-boundary; on apply, triggers its run
      ▼
rosa-boundary: meta-rosa-rosa-boundary             (L2, meta-rosa project)
  hcp-terraform/rosa-boundary
      │ creates/configures workspaces, variables, variable-set bindings;
      │ on apply, triggers their runs
      ├── rosa-boundary-stage-aws-creds            (L3, rosa-boundary project)
      │     hcp-terraform/aws-creds/rosa-boundary-stage
      ├── rosa-boundary-stage-network              (L3, rosa-boundary project)
      │     deploy/network
      └── rosa-boundary-stage-regional             (L3, rosa-boundary project)
            deploy/regional
```

Each box is a separate HCP Terraform workspace with its **own state, working directory, permissions/credentials, and run history**. L1 owns HCP organization/project control-plane setup; L2 owns the configuration of the project workspaces through the TFE API; the three L3 workspaces own different AWS concerns. The credentials workspace owns the account's HCP OIDC provider, plan/apply roles and HCP variable set; network owns VPC/subnets/routing; regional consumes a VPC and private subnet IDs as inputs and owns ECS, EFS, Lambda, IAM, KMS and audit infrastructure. This separation is not one workspace per Terraform file or a requirement for every new region: it avoids one state owning mutually distinct lifecycle/security domains. The credentials role group is scoped to named workspaces, not every workspace in the organization. **The account-level access stack in `deploy/account/` is not registered in the current L2 map**; do not mistake its presence in Git for an automatically deployed HCP workspace. If onboarded, it should have one state per AWS account rather than one per region (see [`deploy/account/README.md`](../../deploy/account/README.md)).

| Layer | Configuration authority | Workspace and runtime | Inputs required before runs |
|---|---|---|---|
| L1 | [infra-platform tenant config](https://github.com/openshift-online/infra-platform/blob/main/hcp-terraform/tenants/rosa/main.tf) and its [bootstrap module](https://github.com/openshift-online/infra-platform/blob/main/hcp-terraform/modules/terraform-tfe-bootstrap/main.tf) | `rosa-bootstrap`, `infra-platform` VCS, Terraform `1.13.4`; its `import` block adopts its own workspace | Platform admin and notification variable sets; initial run bootstrapped manually by platform admin |
| L2 | [`hcp-terraform/rosa-boundary/main.tf`](../../hcp-terraform/rosa-boundary/main.tf) and upstream [workspaces module](https://github.com/openshift-online/infra-platform/blob/main/hcp-terraform/modules/terraform-tfe-workspaces/main.tf) | `meta-rosa-rosa-boundary`, `rosa-boundary` VCS, Terraform `1.16.0` | `rosa-admin-creds` (`TFE_TOKEN`) and `rosa-notification-url`, attached by L1 |
| L3: AWS credentials | [`hcp-terraform/aws-creds/rosa-boundary-stage/main.tf`](../../hcp-terraform/aws-creds/rosa-boundary-stage/main.tf) | `rosa-boundary-stage-aws-creds`, Terraform `1.16.0` | `rosa-boundary-tfe-creds` for TFE API plus AWS credentials; after bootstrap, its **own** generated dynamic-credentials set |
| L3: network and regional | [`deploy/network/`](../../deploy/network/) and [`deploy/regional/`](../../deploy/regional/) | `rosa-boundary-stage-network`, `rosa-boundary-stage-regional`, Terraform `1.16.0` | Generated `rosa-boundary-rosa-boundary-stage-default-aws-dynamic-creds` variable set, plus workspace Terraform variables/defaults |

The bootstrap module creates the `rosa-boundary` and `meta-rosa` projects, `ai-sd-sre` team access, and the `rosa-deletion-protection` policy set over the bootstrap and both projects; its project map creates `meta-rosa-rosa-boundary` and connects it to `openshift-online/rosa-boundary`. The private registry modules are version-pinned by **each caller** (bootstrap `0.0.23`, Boundary workspaces and AWS dynamic credentials `0.0.15`); changing upstream module source alone does not upgrade the deployed callers. `cloud.tf` in each control-plane/credentials directory names its own HCP workspace. The network and regional directories are run by their VCS-connected L3 workspaces; local `.env`, `terraform.tfvars`, Makefile and local state are for development, not inputs to the HCP runs.

## Bootstrap order and credential handoff

1. **Tenant and L1:** The HCP GitHub App must be able to read both repositories. The platform team first merged a minimal `infra-platform/hcp-terraform/tenants/rosa` directory, created `rosa-bootstrap` in the Default project with platform variable sets, and manually queued its first run. Its full config then manages that workspace via import and creates the `meta-rosa` project, the `rosa-boundary` project, the team/policies, and the L2 workspace. See the [infra-platform onboarding guide](https://github.com/openshift-online/infra-platform/blob/main/hcp-terraform/tenants/README.md) for the general bot and initial-run sequence. L1 does **not** provision Boundary's AWS resources.
2. **L2:** Its working directory must already be on `main` before L1 creates the VCS-connected meta-workspace. L1 attaches tenant-level TFE/notification variable sets and uses `tfe_workspace_run` for the initial L2 run. L2's TFE provider then creates the L3 workspaces, attaches their project-scoped variable sets, sets their Terraform variables, and queues first runs via the workspaces module.
3. **AWS identity bootstrap:** The L3 AWS-credentials workspace itself needs AWS access before it can create its own OIDC provider, IAM roles and dynamic-credentials variable set. Upstream's [AWS dynamic credentials guide](https://github.com/openshift-online/infra-platform/blob/main/docs/aws-dynamic-creds.md) describes the staged handoff: create the project-scoped `TFE_TOKEN` set and a temporary approved AWS bootstrap credential set, register/run the empty credentials workspace, then apply the module using temporary AWS credentials, switch its workspace binding to the new dynamic set, verify a remote run, and retire temporary credentials. For this account, the final configuration attaches `rosa-boundary-tfe-creds` and the generated set; **the current files do not prove which initial bootstrap method was actually used**. Do not put tokens or static keys into Git.
4. **Workloads:** The AWS-credentials module's `default` role group explicitly lists the credentials, network and regional workspace names. Its generated variable set is attached separately to those workspaces by L2. Both an IAM trust-policy entry **and** a variable-set binding are required. Network outputs `vpc_id` and `private_subnet_ids`; regional currently receives the corresponding VPC/subnet IDs as explicit L2 workspace variables, **not** through remote state or a network→regional run trigger. Verify the IDs and routing before regional runs, and update the regional variables by PR if the network changes.

The HCP OIDC provider is for **Terraform's AWS provider**, distinct from the Boundary user's Keycloak OIDC federation. The upstream [AWS dynamic-credentials module](https://github.com/openshift-online/infra-platform/blob/main/hcp-terraform/modules/terraform-tfe-aws-dynamic-creds/main.tf) restricts `app.terraform.io:aud` and `sub` to organization/project/workspace/run phase; by default the plan role has AWS `ReadOnlyAccess`, and the apply role has `AdministratorAccess`. It writes `TFC_AWS_PROVIDER_AUTH`, `TFC_AWS_PLAN_ROLE_ARN` and `TFC_AWS_APPLY_ROLE_ARN` into the project-scoped set. The credentials workspace additionally uses a TFE token to manage HCP resources; workload workspaces need only the AWS set. The AWS provider in the credentials stack checks the expected account ID, as do the network and regional providers.

## What causes a plan, and what applies it

There are **two independent event paths**, not just a single linear cascade:

| Event | Plan/run behavior | Apply behavior |
|---|---|---|
| Upstream-branch PR changing a workspace's VCS working directory (or configured trigger prefix) | HCP's GitHub App creates a **speculative plan** for an already initialized matching workspace; inspect the PR checks. Fork PRs do not reliably receive those plans. | A speculative plan is review-only; it does not apply. |
| Merge to `infra-platform` `main` changing `hcp-terraform/tenants/rosa` or its `hcp-terraform/policies` trigger prefix | VCS queues `rosa-bootstrap`; changes elsewhere in infra-platform do not automatically plan this tenant merely because a private registry module's source changed. | Bootstrap `auto_apply` defaults to true. Successful bootstrap apply feeds a `tfe_run_trigger` targeting L2; L2's own VCS connection to Boundary can also independently cause a run. |
| Merge to `rosa-boundary` `main` changing `hcp-terraform/rosa-boundary` | VCS queues L2. | L2's bootstrap-managed `auto_apply` defaults to true; it reconciles workspace configuration and its successful apply can trigger **all three** L3 workspaces, even when no files changed in their directories. |
| Merge to `rosa-boundary` `main` changing `deploy/network`, `deploy/regional`, or `hcp-terraform/aws-creds/rosa-boundary-stage` | The corresponding L3 VCS connection queues a run; it does not require an L1/L2 change. | Workspaces module defaults `auto_apply = true` and `auto_apply_run_trigger = true`; regional explicitly sets both true. Successful eligible runs apply automatically, including run-triggered runs. |
| A newly registered L2 or L3 workspace | The owning module's `tfe_workspace_run` queues an **initial** run after workspace settings, variables, bindings and policies; this is distinct from the ordinary run triggers. | The module's initial apply block has `manual_confirm = false`; review readiness and dependencies **before** creating the workspace. |

Run triggers are installed **on the downstream workspace**: bootstrap→meta in the upstream bootstrap module; meta→each L3 in the upstream workspaces module. `source_workspaces` can add further upstream sources, but the present L2 map does not declare any. In particular, there is no network→regional trigger and no guaranteed execution order between L3 siblings. VCS working-directory filtering and run triggers can both produce runs for a commit; review run source and state rather than assuming exactly one run. `queue_all_runs = false` is set by both modules for managed downstream workspaces. A failed plan, invalid credentials, policy denial, or missing input does not become an apply; auto-apply is **not** a promise that every change deploys. The `rosa-deletion-protection` OPA policy requires a matching unexpired `_deletion_approvals` entry for deletes; policy overrides, where permitted, are a separate deliberate action. Slack notification setup includes runs needing attention and errors, not just successful runs.

> **Current setting differs from older staging instructions:** [`hcp-terraform/rosa-boundary/main.tf`](../../hcp-terraform/rosa-boundary/main.tf) explicitly sets regional `auto_apply = true` and `auto_apply_run_trigger = true`. Do not assume a manual regional approval gate; inspect the current configuration and HCP workspace/run before changing it. There is no explicit `auto_apply` field on the network or credentials map entries, so their auto-apply behavior comes from the pinned workspaces module default.

## Adding a workspace without breaking the chain

1. **Choose ownership:** new HCP project/team/policy or a new meta-workspace belongs in [infra-platform's ROSA tenant `projects` map](https://github.com/openshift-online/infra-platform/blob/main/hcp-terraform/tenants/rosa/main.tf). A new AWS workload inside the existing `rosa-boundary` project belongs in the `workspaces` map of [`hcp-terraform/rosa-boundary/main.tf`](../../hcp-terraform/rosa-boundary/main.tf). Do not create a workspace manually as a substitute for its owner. Distinguish account-global IAM (`deploy/account/`, one state per account), per-account OIDC credentials, network, and per-region runtime states.
2. **Scaffold first, register second:** merge the new working directory and minimal valid Terraform configuration into the connected repo's default branch **before** adding the workspace definition in a separate PR. A new VCS-connected workspace needs an initial completed run before PR webhook speculative plans work. L1's first run is manual; L2/L3 initial runs are queued by `tfe_workspace_run`, but cannot succeed if the working directory is absent. Specify the `cloud.tf` workspace name for control-plane/credentials directories as appropriate; choose a reviewed exact `terraform_version` compatible with `required_version` and pinned providers.
3. **Provision prerequisites before registration:** ensure GitHub App/repo access, project/team access, TFE token set if using the TFE provider, AWS account/provider guard, tags, appropriate region and network. For a new AWS account, bootstrap its **own** HCP OIDC/roles/variable set as above. For a new workspace in the staging account, extend the `role_groups.default.projects.rosa-boundary.workspace_names` allowlist in [`hcp-terraform/aws-creds/rosa-boundary-stage/main.tf`](../../hcp-terraform/aws-creds/rosa-boundary-stage/main.tf), apply/verify the credentials stack, then attach its generated set in the L2 entry. Merely adding the set binding does not widen the IAM trust policy.
4. **Add the L2 map entry by PR:** set unique name, VCS org/repo, working directory, Terraform version, `variable_set_names`, and an explicit `variables` list (possibly empty). Set `auto_apply`/`auto_apply_run_trigger` deliberately; their **default is true**. Set `source_workspaces` only for real cross-workspace run dependencies, and arrange a proper way to supply outputs as inputs: a run trigger does not transfer Terraform outputs. Put stage/region/account, image pins and other workload inputs in this Git-controlled list, not in ad hoc HCP workspace variable edits. For the current regional workspace, this map is the source of truth for variables.
5. **Review both PR and initial/merge runs:** confirm speculative plans actually appeared on upstream branches; check initial-run history, variable set bindings, policy results, planned AWS account/region, and network inputs. After merge, verify the L2 apply created the workspace, the initial L3 run completed, and subsequent VCS and run-triggered plans/applies behave as intended. For a new account/region, validate live access, routing, audit and recovery rather than assuming staging credentials or VPC IDs generalize. Do not manually trigger/create/apply runs just to paper over a missing source directory, failed policy, or unsatisfied credential prerequisite.

## Sources and verification boundaries

Boundary-owned definitions: [`hcp-terraform/rosa-boundary/main.tf`](../../hcp-terraform/rosa-boundary/main.tf), [`hcp-terraform/aws-creds/rosa-boundary-stage/main.tf`](../../hcp-terraform/aws-creds/rosa-boundary-stage/main.tf), [`deploy/network/outputs.tf`](../../deploy/network/outputs.tf), [`deploy/account/README.md`](../../deploy/account/README.md). Cross-repository implementation: [ROSA tenant bootstrap](https://github.com/openshift-online/infra-platform/blob/main/hcp-terraform/tenants/rosa/main.tf), [bootstrap module](https://github.com/openshift-online/infra-platform/blob/main/hcp-terraform/modules/terraform-tfe-bootstrap/main.tf), [workspaces module](https://github.com/openshift-online/infra-platform/blob/main/hcp-terraform/modules/terraform-tfe-workspaces/main.tf), [AWS credentials module](https://github.com/openshift-online/infra-platform/blob/main/hcp-terraform/modules/terraform-tfe-aws-dynamic-creds/main.tf), and [tenant onboarding](https://github.com/openshift-online/infra-platform/blob/main/hcp-terraform/tenants/README.md). These links describe the module source as inspected; Boundary calls published, pinned registry releases, so review the **deployed module version and HCP run history** before relying on module behavior for an operational change.

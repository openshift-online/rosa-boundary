---
name: smoke-test-boundary-environment
description: Runs the environment readiness runbook only when the user explicitly asks to smoke-test an already-deployed ROSA Boundary environment for general SRE use, such as “validate staging.” Uses the rosa-boundary CLI and in-session rta catalog reads without modifying the target cluster. Not for verifying a PR, commit, or working-tree change, or for requests to plan or explain tests.
---

# Smoke-test a Boundary environment

Read the current [environment readiness runbook](../../../docs/runbooks/environment-readiness.md) in full on every invocation. Follow it for prerequisites, commands, checks, cleanup, and reporting. If it is missing or a step cannot be followed safely, report the blocker rather than substituting another procedure.

Do not change running clusters, environments, or configuration without explicit user approval. Before creating anything, confirm approval covers creating and closing this run’s disposable Boundary resources in the named environment. A readiness request is not permission to edit a CLI profile, repair a deployment, or touch another investigation.

Keep the target cluster untouched: do not log in to it or submit a Trusted Action, including a dry run. If a check fails, report what was observed and follow the runbook’s cleanup guidance. Treat any proposed fix as a separate task requiring explicit approval.

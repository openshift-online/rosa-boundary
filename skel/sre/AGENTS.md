# SRE Investigation Environment

This is an ephemeral ROSA Boundary container for authorized cluster investigation
and AWS infrastructure troubleshooting. These instructions apply to all coding
agents in the workspace.

## Environment

- Tasks run on AWS Fargate. Perform investigation work as the non-root `sre` user.
- `/home/sre` is an EFS-backed investigation workspace reused by successive tasks
  in the same investigation. Store non-secret notes and evidence here.
- Use the installed `aws`, `oc`, `ocm`, `ocm backplane`, and `osdctl` commands.
- Claude Code, OpenCode, Codex, and pi are available. Use Amazon Bedrock only,
  with the deployment-provided provider configuration. Do not use other model
  providers. If Bedrock is not configured for an agent, ask the operator rather
  than falling back to another provider.

## Start with SOPs and Skills

Before choosing investigation commands, find and read the applicable operational
SOP and skill rather than relying on a generic troubleshooting recipe.

- SOPs are normally mounted at `/opt/rosa-content/ops-sop/`.
- For alert investigations, start with the `srep-alert-skills` collection at
  `/opt/rosa-content/rosa-claude-plugins/srep-alert-skills/skills/`. Read the
  `SKILL.md` matching the alert or symptoms and follow its SOP references.
  These skills map alert names to investigation workflows and relevant SOPs.
  Boundary also maintains skill discovery links in `~/.claude/skills/` and
  `~/.agents/skills/`.
- Follow the relevant Backplane access skill/SOP to establish cluster access.
  Do not default to direct token-based `oc login`.
- For OCM API interactions outside `ocm backplane`, use the available `ocm-api`
  skill.
- If required content, permissions, or credentials are unavailable, explain the
  blocker and ask the operator; do not substitute another access path or target.

## Investigation Scope

- Confirm the authorized cluster, AWS account, and target region before accessing
  resources. Do not infer the target from the container's deployment region.
- **Validate the target cluster and OCM API environment before every operation.**
  Confirm the active Backplane/Kubernetes context, cluster ID, identity, and OCM
  API endpoint match the authorized investigation. Production, staging, and
  integration are not interchangeable. Do not rely only on defaults or a prior
  login; stop and resolve any mismatch before proceeding.
- Follow the applicable SOP's approval requirements. Do not create debug workloads,
  collect broad diagnostics, or perform remediation without appropriate approval.

## Evidence and Credentials

- Keep non-secret notes, logs, and artifacts wherever appropriate under
  `/home/sre`. Record relevant actions, findings, and evidence locations.
  Limit collection to the authorized investigation.
- Use the supported task-scoped credential flow. OCM state belongs under
  `/home/sre/.config/ocm` and kubeconfig state under `/home/sre/.kube`; these are
  task-scoped, audit-excluded mounts, not persistent workspace storage.
- **Never write credential material outside the designated ephemeral,
  audit-excluded mounts**, including temporary credential files, copies, or
  backups. Files elsewhere under `/home/sre` persist on EFS and are included in
  audit collection; never put credentials in those files, notes, or artifacts.
  Do not assume an arbitrary temporary directory or another mount is excluded.
- Use task-role credentials for Boundary AWS operations; obtain any target-account
  access through its approved workflow.
- Container shutdown attempts an S3 audit sync. Leaving an ECS Exec shell does
  not stop the task or prove that audit sync succeeded.

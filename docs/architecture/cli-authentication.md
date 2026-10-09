# CLI Authentication Model

The Boundary CLI starts with an OIDC ID token from the configured identity provider, not pre-existing AWS credentials. For the current command-specific flow, check [`internal/cmd/root.go`](../../internal/cmd/root.go) and [`internal/aws/sts.go`](../../internal/aws/sts.go); IAM trust and ABAC are defined in [`deploy/account/`](../../deploy/account/) and [`deploy/regional/`](../../deploy/regional/). Consult the [user access guide](../runbooks/user-access-guide.md) for setup and the [investigation workflow](../runbooks/investigation-workflow.md) for an end-to-end check.

## Authentication steps

1. `rosa-boundary configure` can discover deployment configuration via Lambda after authenticating with OIDC and assuming an invoker role. It does **not** use existing config-file OIDC settings for auto-discovery. Supply the intended account, region, project and environment, and override OIDC flags for a non-default identity provider. Alternatively configure manually. See [`internal/cmd/configure.go`](../../internal/cmd/configure.go).
2. `rosa-boundary login` authenticates via browser PKCE when a fresh token is needed and caches an expiring ID token on the workstation. Use `login --force` to refresh it. The cache path respects `XDG_CACHE_HOME`; see [`internal/auth/token.go`](../../internal/auth/token.go). A cached ID token is not a standing AWS access key.
3. `start-task` and `create-investigation` assume the Lambda-invoker IAM role via `AssumeRoleWithWebIdentity`, using the OIDC token without an ambient AWS credential chain. The CLI calls Lambda with temporary SigV4 credentials; Lambda also validates the ID token and authorization claims before creating resources. `start-task` additionally assumes the SRE role to wait for and optionally connect to the new task. See [`internal/cmd/start_task.go`](../../internal/cmd/start_task.go) and [`lambda/create-investigation/handler.py`](../../lambda/create-investigation/handler.py).
4. Task management commands such as `join-task`, `list-tasks`, `stop-task`, `list-investigations`, and `close-investigation` also use an OIDC token to assume the shared SRE IAM role through STS on each CLI invocation. They do **not** use ambient workstation AWS credentials. The shared *role* issues distinct temporary sessions; it is not a shared secret. `join-task` hands ECS Exec to the AWS `session-manager-plugin` installed on the workstation.

AWS STS derives session tags from the token's `https://aws.amazon.com/tags` claim when the role trust permits tagging. IAM compares the caller's principal tag with the ECS task tag for the deployment's configured ABAC key; **do not assume that key is `username`**. A missing or mismatched claim may prevent STS assumption or ECS Exec. Lambda separately checks configured group membership and the ABAC claim. See the [architecture overview](overview.md), current IAM policies, and Lambda tests for deployment-specific behavior.

## Configuration and audit access

The CLI resolves settings from flags, environment, a config file and defaults; check [`internal/config/`](../../internal/config/) and CLI `--help` for current fields. The invoker role and Lambda name are needed to start a task, while management commands require an SRE role and `close-investigation` also needs the EFS filesystem ID. Auto-discovery populates these from the deployment when available.

The CLI's temporary SRE credentials are not exported to your shell. Independent `aws logs` or `aws s3` audit retrieval uses the AWS CLI and an **operator/audit-reader identity with read permissions** in the correct account and region. Neither pre-existing AWS CLI credentials nor AWS CLI installation is required for ordinary Boundary CLI operations. See [Verify Audit Evidence](../runbooks/investigation-workflow.md#verify-audit-evidence).

## Related documents

- [System architecture](overview.md)
- [AWS IAM policies](../configuration/aws-iam-policies.md)
- [User access guide](../runbooks/user-access-guide.md)

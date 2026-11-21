# AWS IAM Policies for Boundary Integration

## Identity and Terraform ownership

Boundary uses **EmployeeIDP OIDC federation and per-person temporary STS
sessions**, not IAM users, IAM groups, per-user roles, or shared access keys.
The shared SRE and Lambda-invoker roles are shared identities that issue
separate temporary credentials; they are not shared credential material.
Ordinary CLI operations do not require workstation AWS credentials and do not
export the assumed credentials into your shell.

The [account root](../../deploy/account/main.tf) owns OIDC providers and role
trusts through its shared IAM module. The [regional grants](../../deploy/regional/iam.tf)
attach permissions to those identities. Do not create parallel IAM groups,
attach ad hoc policies, or copy these resources into a second Terraform state.
For Git-managed deployments, review the owning
[HCP workspace definitions](../../hcp-terraform/rosa-boundary/main.tf) through a PR;
verify effective live settings separately.

## OIDC trust and UUID authorization

Both the [SRE trust](../../deploy/account/modules/shared-iam/oidc.tf) and
[Lambda-invoker trust](../../deploy/account/modules/shared-iam/lambda-invoker.tf)
allow `sts:AssumeRoleWithWebIdentity` and `sts:TagSession` for the configured
provider ARN and audience. Optional stage/production issuer statements use
their own provider and audience. The current implementation applies these
optional conditions to **every** emitted trust statement:

- `enable_oidc_group_enforcement`: requires `aws:RequestTag/roles` to equal
  `required_oidc_role`.
- `enable_uuid_allowlist`: requires `aws:RequestTag/uuid` to match an entry in
  `allowed_uuids`.

These conditions consume the ID token's `https://aws.amazon.com/tags`
`principal_tags`. The EmployeeIDP `uuid` value is the person's rhatUUID;
it is not a username and must not be assumed equal to the OIDC `sub`.
Disabling an optional trust gate removes that gate, not the other checks.
Inspect the account inputs and rendered trust rather than inferring enforcement
from a variable description or a regional input with a similar name.

Creation uses the invoker role's regional `lambda:InvokeFunction` grant.
The [create-investigation handler](../../lambda/create-investigation/handler.py)
separately validates the ID token and requires membership in at least one
configured `REQUIRED_GROUPS` entry. It reads a nonempty `groups` list, otherwise
`realm_access.roles`. It also extracts the configured ABAC claim.
The [regional default](../../deploy/regional/variables.tf) is
`abac_tag_key = "uuid"`; a missing UUID claim fails rather than falling back to
a display name. The handler's legacy `username` mode has a username fallback;
it is not the EmployeeIDP UUID model. Keep the Lambda ABAC key and IAM
principal/task tag comparison aligned.

## Investigation management versus task ownership

Required-group membership is the investigation-management trust boundary.
Within that trusted population, investigation resources are not generally
isolated by creator UUID in the SRE permission policy. Task exec and stop are
person-scoped. These are different boundaries:

| Operation | Current authorization in regional IAM / application |
| --- | --- |
| Create investigation or session | Invoker-role trust and Lambda invocation permission, then Lambda token, group and ABAC validation |
| Execute command | Cluster grant plus task grant requiring `ecs:ResourceTag/<abac_tag_key>` equal to `aws:PrincipalTag/<abac_tag_key>` |
| Stop task | Same ABAC equality, scoped to this deployment's cluster task ARN pattern |
| List/describe ECS resources and deregister task definitions | SRE policy grants these actions on `*`; no creator condition |
| Describe access points | SRE grant scoped to the deployment filesystem |
| Delete access point | SRE grant on regional/account access-point ARNs with `ManagedBy = rosa-boundary-lambda`; no creator condition |

The current exec task statement uses `Resource = "*"` with ABAC; do not describe
it as an explicit cluster-task ARN restriction like the stop statement.
The SRE role also grants `ssm:StartSession` on ECS task and
`AWS-StartInteractiveCommand` document patterns, `ssmmessages:OpenDataChannel`,
and `kms:Decrypt` / `kms:GenerateDataKey` on `*`. SSM cannot inspect ECS task
tags; the ECS ExecuteCommand policy enforces the ECS ABAC comparison. This
inventory describes existing grants, not a recommendation to broaden them.
There is no IAM-user `${aws:username}` session model to configure.

**Close ownership remains unresolved:**
[ROSAENG-75946](https://redhat.atlassian.net/browse/ROSAENG-75946) tracks the
conflict between shared-SRE management and the
[CLI close check](../../internal/cmd/close_investigation.go).
Today the CLI requires the access point's creator `oidc_sub` to match the
authenticated ID token's `sub`, including during dry-run. This is an
application check, **not** an IAM owner restriction on other AWS clients.
Do not remove it, promise group-wide CLI close, or prescribe bypassing it based
on this guide. `--force` does not bypass it and stopping tasks still requires
the task ABAC match.

Access-point creator tags remain creation provenance when another SRE reuses
the workspace; task tags identify the creator of each new task. They do not
track every subsequent actor. Correlate the AWS assumed-role session and audit
records for the current actor, rather than rewriting creator tags. See the
[investigation workflow](../runbooks/investigation-workflow.md) for tag and
handover details.

## External policy and audit-reader prerequisites

The CLI uses direct SDK `lambda:InvokeFunction`, not a Function URL.
Organization SCPs and other external controls can deny an otherwise allowed
operation; this repository does not establish their effective live policy.
Confirm the target account's SCP permits the SDK path and the required
STS/ECS/SSM operations. Do not assume a Terraform plan proves that an OIDC
session can use them.

The SRE exec grant is not an audit-reader grant: it does not grant CloudWatch
log reads or audit-bucket object reads. Independent `aws logs` / `aws s3`
commands require an AWS CLI and a separately authorized operator/audit-reader
identity in the correct account and Region. That identity needs scoped log,
S3 and applicable KMS access approved by the deployment operator. Do not add
long-lived credentials to the container or investigation workspace to obtain it.

The [audit bucket policy](../../deploy/regional/s3.tf) denies non-TLS access;
it is not a blanket deny of every non-task principal. Object Lock/versioning
protect retained versions but do not supply reader permissions. Cross-account
audit replication additionally requires the destination bucket, retention and
bucket policy to be configured separately. Task logging and encryption grants
are in [regional IAM](../../deploy/regional/iam.tf) and
[the exec key policy](../../deploy/regional/kms.tf), not hand-created user
policies from this guide.

## Verification and limits

For ordinary setup, follow [CLI authentication](../architecture/cli-authentication.md)
and the [user access guide](../runbooks/user-access-guide.md).
Review account trust, regional grants, Lambda claim checks and the close
owner check together. Source and policy tests describe the intended controls;
they do not prove deployed IAM, SCPs, or audit-reader access.

A real enforcement test requires separate personal-dev authorization and
known deployed artifacts. Include positive and negative group/UUID cases,
another user's exec/stop denial, and separate audit retrieval. Do not use
`aws ecs execute-command --dry-run` (there is no such option), or treat a
successful shell connection as proof of audit sync. Use the
[workflow's audit verification](../runbooks/investigation-workflow.md#verify-audit-evidence)
and retain evidence without tokens or credentials.

## Optional: cross-account CloudWatch metric read (ROSAENG-68823)

An external monitoring system can read this deployment's CloudWatch metrics
without any long-lived credential, by assuming a dedicated role. The role is
**off by default** and is created only when explicitly enabled.

The role is split across the two Terraform roots the way every other shared
identity is:

| Piece | Owner | Input |
|-------|-------|-------|
| Role identity and trust policy | `deploy/account` | `enable_metrics_read_role`, `metrics_read_trusted_principal_arns`, `metrics_read_session_duration` |
| Inline permission grant | `deploy/regional` | `enable_metrics_read_grant` |

Enable them in that order, in two separate applies: the regional root resolves
the role by name and fails with `NoSuchEntity` if the account root has not
created it yet. Enable the grant only in the workspace whose `aws_region`
matches `legacy_policy_region`; the grant is account-global, so any other region
fails the plan rather than managing a duplicate policy on the same role.

**Trust.** An explicit allowlist of complete caller ARNs, for example
`arn:aws:iam::<caller-account-id>:role/<caller-role>` or
`arn:aws:sts::<caller-account-id>:assumed-role/<caller-role>/<session-name>`.
Account roots, service principals, partial names and wildcards are rejected by
variable validation. That validation is load-bearing: IAM rejects a partial
wildcard such as `role/*`, but it accepts a bare `*` as an anonymous principal,
which would make the role assumable by anyone in the partition. Prefer the plain
role ARN — a session ARN pins trust to one session name.

**Permissions.** Exactly four read actions, and nothing else:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:ListMetrics",
        "cloudwatch:GetMetricData",
        "cloudwatch:GetMetricStatistics",
        "tag:GetResources"
      ],
      "Resource": "*"
    }
  ]
}
```

CloudWatch metric reads cannot be scoped by resource ARN, which is why
`Resource` is `*`. The AWS managed `CloudWatchReadOnlyAccess` policy is
deliberately **not** used: it also grants logs and autoscaling reads this role
has no reason to hold.

`tag:GetResources` is the Resource Groups Tagging API, which collectors use for
tag-based metric discovery. Unlike the three `cloudwatch:` actions it is
cross-service by nature: it returns the ARNs and tag keys/values of tagged
resources across services, though it exposes no service configuration or data.
Grant it only while a discovery job needs it.

No `Describe`/`List` permission for any other AWS service is granted, so a
collector that needs metrics from another service still requires a reviewed
change to this grant, not a configuration change on the caller's side.

## Content publishing and replication identities

Every deployment of [`deploy/account`](../../deploy/account/README.md) creates
one publisher role per configured source repository and creates or resolves the
account's GitHub Actions OIDC provider. Publishers have no enablement flag.
A separate replication role dedicated to content buckets is also always created,
independently of the optional audit replication identity.

**These identities carry no permissions.** As with every other shared role, the
grants are owned by the regional root and arrive in a separate, later change.
An enabled role is assumable but holds no content access from this
configuration until then. Nothing in the account root references a bucket, a
KMS key or another Terraform state. This describes what the account state
declares; it is not a claim that no resource-based policy elsewhere names the
role, which only an account review can establish.

| Identity | Role name | Trusted by |
| --- | --- | --- |
| ops-sop publisher | `<prefix>-publisher-ops-sop` | GitHub Actions, `openshift/ops-sop` on `master` |
| managed-notifications publisher | `<prefix>-publisher-managed-notifications` | GitHub Actions, `openshift/managed-notifications` on `master` |
| rosa-claude-plugins publisher | `<prefix>-publisher-rosa-claude-plugins` | GitHub Actions, `openshift-online/rosa-claude-plugins` on `main` |
| content replication | `<prefix>-content-replication-role` | `s3.amazonaws.com` |

Each publisher's trust policy is a single statement:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Principal": { "Federated": "arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com" },
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:openshift/ops-sop:ref:refs/heads/master"
      }
    }
  }]
}
```

`StringEquals` with a scalar subject restricts trust to the configured repository
and default-branch subject; it does **not** restrict the triggering event to a
merge. Scheduled runs, `workflow_dispatch` and `pull_request_target` workflows
can also present a matching default-branch subject. Privileged publishing
workflows must not check out or execute untrusted PR code, and their triggers
and permissions require separate review in the source repositories.

A list of subjects, a second audience, or a subject such as
`repo:openshift/ops-sop:pull_request` would expand the accepted subjects or
audiences. This configuration cannot express them: the subject is built from a
fixed template and the inputs are validated, so colons, full refs, wildcards
and empty values are rejected before a policy is rendered.

Be precise about the operator, because it is easy to state this wrongly. Under
`StringEquals` the subject is matched literally, so a `*` inside the value is
an ordinary character and would match no token any workflow presents — such a
subject is inert, not broad. Under `StringLike`, `*` and `?` are
metacharacters; a `StringLike` condition whose value contains neither still
matches exactly one string. The risk is the combination of `StringLike` with a
value containing a metacharacter, which is why this configuration both emits
`StringEquals` and refuses to store a `*`.

Note also what validation does *not* do. It constrains the shape of each value;
it does not restrict which owner, repository or branch an operator configures.
Trust is pinned to the three agreed sources by the configured
`content_publisher_sources` — the shipped defaults — and the account tests
assert the complete rendered subject set, so an unconfigured repository or
branch is excluded by the rendered policy rather than by input validation.
Repointing a publisher at a fork or another branch is a deliberate, reviewable
configuration change.

Terraform tests assert the rendered documents; they do not exercise
AWS, so real enforcement still needs an actual `AssumeRoleWithWebIdentity` from
a publishing workflow.

The content replication role's trust is S3 service only, with no condition,
matching the existing audit replication role exactly. It is a separate identity
so content replication and audit replication never share permissions.

Consume the identities through the account outputs — `content_publisher_roles`,
`content_publisher_role_arns`, `content_replication_role_arn` and
`github_actions_oidc_provider_arn` — rather than reconstructing names. See the
[account README](../../deploy/account/README.md) for the provider create /
reference / adopt modes and the enablement order.

## Published content grants (regional)

Every `deploy/regional` deployment creates its content bucket, bootstraps the
regional AWS-managed key and attaches the shared task role's content read grant.
Publisher grants are created only for supplied publisher role ARNs in the source
Region; replication grants are created only when destinations are configured.
The identities themselves are created by `deploy/account`; the regional state
only grants them permissions, and every policy name carries the regional suffix
so one Region cannot overwrite another's.

**Publisher** (`content-publish-<key>`, one per source key, source Region only):

| Action | Resource | Why it is needed |
|---|---|---|
| `s3:ListBucket` (conditioned on `s3:prefix`) | content bucket | `aws s3 sync` enumerates the prefix |
| `s3:PutObject` | `<bucket>/<prefix>*` | covers PutObject, CreateMultipartUpload, UploadPart, CompleteMultipartUpload |
| `s3:DeleteObject` | `<bucket>/<prefix>*` | `--delete` removes objects no longer in the source |
| `s3:AbortMultipartUpload` | `<bucket>/<prefix>*` | the CLI aborts a failed multipart upload |
| `kms:GenerateDataKey` | regional `aws/s3` key | required by PutObject and CreateMultipartUpload under SSE-KMS |
| `kms:Decrypt` | regional `aws/s3` key | required by UploadPart and CompleteMultipartUpload |

Deliberately absent, each because no actual call path uses it: `s3:GetObject`
(sync compares size and last-modified time from the listing), `s3:PutObjectTagging`
(the CLI sets no tags), `kms:Encrypt` (SSE-KMS writes use GenerateDataKey), and
`kms:DescribeKey` (never called, and the `kms:ViaService` condition would deny a
direct call anyway because it does not arrive through S3).

Supplied role ARNs must be **path-less** (`arn:<partition>:iam::<account>:role/<name>`),
which is the only shape `deploy/account` emits. `PutRolePolicy` takes a role
name and role names are unique per account, so a path-qualified ARN whose
basename matched a real role would attach the policy to a role other than the
one the ARN names. Such input is rejected rather than silently normalised.

**Runtime** (`s3-content-read`, on the shared task role): `s3:ListBucket` and
`s3:GetObject` on the local Region's published prefixes plus `kms:Decrypt`. This
direction genuinely downloads and decrypts, so both are required. It has no
write action and no cross-Region ARN. The task role is shared across Regions,
so its effective permissions are the union of these regional grants; this does
not isolate task identities by Region.

**Replication** (`content-replication`, owned by the source Region): exactly the
minimal AWS-documented SSE-KMS replication set —
`s3:GetReplicationConfiguration`, `s3:ListBucket`,
`s3:GetObjectVersionForReplication`, `s3:GetObjectVersionAcl`,
`s3:ReplicateObject`, `s3:ReplicateDelete`, `kms:Decrypt` on the source key and
`kms:Encrypt` on each destination key. `kms:GenerateDataKey` is omitted: it is
needed only to replicate plaintext objects. Bucket default SSE-KMS encrypts
uploads that omit the encryption header; the policy rejects explicitly different
algorithms and SSE-C. This identity is separate from the audit
replication role, which must never carry content permissions.

KMS statements are scoped by `kms:EncryptionContext:aws:s3:arn` to the relevant
object ARNs — correct because S3 Bucket Keys are not enabled — and by
`kms:ViaService` to the S3 endpoint of each key's own Region.

## Next Steps

- [User Access Guide](../runbooks/user-access-guide.md) - End-user authentication workflow
- [Architecture Overview](../architecture/overview.md) - OIDC issuer, claims, and the IAM OIDC provider the policies trust

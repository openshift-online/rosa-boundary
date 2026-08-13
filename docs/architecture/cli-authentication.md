# CLI Authentication Model

This document explains how the `rosa-boundary` CLI authenticates when you run different commands. It is written for users who may not be deeply familiar with AWS IAM or OIDC — the concepts are introduced as needed.

---

## Key Concepts

Before diving into the CLI, a few foundational ideas are needed.

### AWS Credentials

Every AWS API call must include credentials that prove the caller is authorized. These credentials are a set of three values: an access key ID, a secret access key, and (usually) a session token. You can think of them as a temporary username/password pair that AWS checks on every request.

Credentials can come from several places. The AWS SDK checks them in order:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. Shared credentials file (`~/.aws/credentials`)
3. AWS config file with profiles (`~/.aws/config`)
4. ECS task role (if running inside a container on AWS)
5. EC2 instance profile (if running on an EC2 instance)

The first source that provides valid credentials wins. This is called the **default credential chain**, and it is what most AWS CLI tools and SDKs use when no explicit credentials are provided.

### Assume Role

AWS has a service called **STS** (Security Token Service). Its job is to issue temporary credentials. One of its key operations is **assume role**: you provide some proof of identity, and STS gives back temporary credentials that carry the permissions of a specific IAM role.

Think of it like a building's security desk. You show your ID badge, security verifies it, and hands you a visitor pass that opens specific doors. The visitor pass expires after a set time — you cannot extend it yourself.

There are different types of role assumption:

- **AssumeRole**: "I already have AWS credentials. Give me a different set with different permissions." (Trading one visitor pass for a more specific one.)
- **AssumeRoleWithWebIdentity**: "I have no AWS credentials at all, but I have an identity token from a trusted external system (like Keycloak). Verify that token and give me AWS credentials." (Showing your employee badge from a trusted partner company.)

The second type — `AssumeRoleWithWebIdentity` — is what rosa-boundary uses. It means **you never need pre-existing AWS credentials to start a task.** Your Keycloak login is enough.

### OIDC Authentication

OIDC (OpenID Connect) is a protocol for proving who you are to a system. Here is the simplified flow:

1. The CLI opens your web browser to a login page (Keycloak, in this case)
2. You authenticate — SSO, password, MFA, whatever Keycloak requires
3. Keycloak redirects your browser back to the CLI (which is listening on a local port)
4. The redirect includes an authorization code
5. The CLI exchanges that code for an **ID token** — a digitally signed JWT (JSON Web Token) that contains claims about you: your username, email, group memberships, and an expiration time

The ID token is the proof of identity. It is cryptographically signed by Keycloak's private key. Anyone (including AWS) can verify the signature using Keycloak's public key, which is published at a well-known URL.

### How an OIDC Token Becomes AWS Credentials

This is the mechanism that connects the two worlds. Here is how it works:

**Pre-configuration (done once by an administrator):**

An IAM role is created in AWS with a **trust policy** that says: "I trust tokens issued by this specific Keycloak server, for this specific OIDC client ID. If someone presents a valid token from that issuer, give them temporary AWS credentials for this role." The administrator also registers Keycloak as an IAM OIDC Provider in the AWS account, so AWS knows where to find Keycloak's public keys.

**At runtime (every time you authenticate):**

1. The CLI calls `STS AssumeRoleWithWebIdentity` and sends the OIDC ID token along with the ARN of the role to assume
2. AWS STS contacts Keycloak's public key endpoint (JWKS URL), fetches the signing keys, and verifies the JWT's digital signature is authentic
3. STS checks that the token's issuer and audience match what the role's trust policy expects, and that the token has not expired
4. If everything checks out, STS returns temporary AWS credentials (access key + secret + session token), valid for a configured duration (typically 1 hour)

The critical point: **the CLI starts with zero AWS credentials.** The OIDC token from Keycloak is the only authentication material. The code in `internal/aws/sts.go` explicitly uses anonymous credentials — it tells the AWS SDK "do not look for existing AWS creds; I am providing a web identity token instead."

---

## Two Authentication Patterns

The CLI commands split into two distinct groups based on how they authenticate:

| Pattern | Commands | How it works |
|---------|----------|--------------|
| **OIDC-bootstrapped** | `login`, `start-task`, `create-investigation` | Starts from a Keycloak OIDC token, assumes IAM roles via STS. No pre-existing AWS credentials needed. |
| **Ambient AWS credentials** | `list-tasks`, `join-task`, `stop-task`, `close-investigation`, `list-investigations` | Uses whatever AWS credentials are already in your environment. No Keycloak interaction. |

The rest of this document explains each pattern in detail.

---

## Pattern 1: OIDC-Bootstrapped Authentication

Used by: `login`, `start-task`, `create-investigation`

These commands start from nothing — no AWS credentials in your environment — and build up credentials through a chain of trust that begins with your Keycloak login.

### The `login` Command

The simplest OIDC-bootstrapped command. It performs the Keycloak PKCE browser flow and caches the resulting ID token. No AWS operations are involved.

```
You (no AWS creds, no token)
  │
  ▼
┌──────────────────────────────────────┐
│  Keycloak OIDC Login (PKCE)          │
│                                      │
│  1. CLI opens browser to Keycloak    │
│  2. You log in (SSO, MFA, etc.)      │
│  3. Keycloak redirects to CLI        │
│  4. CLI exchanges code for ID token  │
│                                      │
│  Token cached at:                    │
│  ~/.cache/rosa-boundary/token-cache  │
│  (reused for 4 minutes)              │
└──────────────┬───────────────────────┘
               │
               ▼
         ID token printed
         to stdout
```

**What you need:**
- Config: `keycloak_url`, `keycloak_realm`, `oidc_client_id` (all have defaults)
- A Keycloak account with the correct group membership
- A web browser

**What you do not need:**
- Any AWS credentials, roles, or configuration

### The `start-task` Command (Full Two-Step Flow)

This is the most complex authentication flow. It chains four steps: OIDC login, first role assumption, Lambda invocation, and second role assumption.

```
You (no AWS creds)
  │
  ▼
┌──────────────────────────────────────┐
│ Step 1: Keycloak OIDC Login          │
│                                      │
│  Same PKCE browser flow as `login`.  │
│  If a cached token exists and is     │
│  less than 4 minutes old, it is      │
│  reused without opening the browser. │
│                                      │
│  The ID token (JWT) contains:        │
│    - your username                   │
│    - your group memberships          │
│    - an expiration time              │
│    - a digital signature             │
└──────────────┬───────────────────────┘
               │ OIDC ID token (JWT)
               ▼
┌──────────────────────────────────────┐
│ Step 2: First Role Assumption        │
│ (Lambda Invoker Role)                │
│                                      │
│  CLI calls STS with:                 │
│    - no existing AWS credentials     │
│      (anonymous)                     │
│    - the OIDC ID token               │
│    - the invoker_role_arn from       │
│      your config                     │
│                                      │
│  AWS STS verifies the token and      │
│  returns temporary credentials.      │
│                                      │
│  These credentials are deliberately  │
│  narrow — they can ONLY invoke the   │
│  create-investigation Lambda.        │
│  Nothing else.                       │
└──────────────┬───────────────────────┘
               │ temporary AWS creds (Lambda-invoke only)
               ▼
┌──────────────────────────────────────┐
│ Step 3: Lambda Invocation            │
│                                      │
│  CLI calls the Lambda function using │
│  the invoker role's temporary creds. │
│  The AWS SDK automatically signs the │
│  request (SigV4).                    │
│                                      │
│  The OIDC token is ALSO passed       │
│  inside the request payload so the   │
│  Lambda handler can independently:   │
│    - verify your identity            │
│    - check you are in the required   │
│      group (e.g., "sre-team")        │
│    - tag the task with your username │
│                                      │
│  Authentication here is two-layered: │
│   Transport: SigV4 (proves you can   │
│     call the function)               │
│   Application: OIDC token (proves    │
│     who you are for RBAC)            │
│                                      │
│  Lambda returns:                     │
│    - task ARN                        │
│    - SRE role ARN                    │
│    - access point ID, owner, etc.    │
└──────────────┬───────────────────────┘
               │ task details from Lambda response
               ▼
┌──────────────────────────────────────┐
│ Step 4: Second Role Assumption       │
│ (Shared SRE ABAC Role)               │
│                                      │
│  CLI calls STS again with:           │
│    - no existing AWS credentials     │
│      (anonymous, same as Step 2)     │
│    - the same OIDC ID token          │
│    - the sre_role_arn                │
│                                      │
│  This time, session tags from the    │
│  JWT are embedded into the temporary │
│  credentials. For example, your      │
│  username becomes a session tag.     │
│                                      │
│  AWS IAM policies then use these     │
│  tags for access control (ABAC):     │
│  you can only ecs:ExecuteCommand     │
│  into tasks whose "username" tag     │
│  matches YOUR session tag.           │
│                                      │
│  These credentials are used for:     │
│    - waiting for the task to start   │
│    - connecting via ECS Exec         │
└──────────────────────────────────────┘
```

**Why two role assumptions instead of one?**

Principle of least privilege. The invoker role can *only* call the Lambda function — if those credentials were somehow leaked, an attacker could invoke the Lambda but could not touch ECS, EFS, or anything else. The SRE role can do ECS operations but is scoped by ABAC — you can only exec into tasks tagged with your username, even though every SRE assumes the same IAM role. Splitting these into separate roles means neither set of credentials is more powerful than necessary.

**What you need:**
- Config: `keycloak_url`, `invoker_role_arn`, `lambda_function_name`, `aws_region`, `ecs_cluster_name`
- A Keycloak account with the correct group membership
- A web browser
- `session-manager-plugin` installed (if using `--connect`)

**What you do not need:**
- Any pre-existing AWS credentials — the OIDC token is the seed for everything

### The `create-investigation` Command

Identical to `start-task` Steps 1 through 3, but stops there. It tells the Lambda to create only the EFS access point (no ECS task is launched), so Steps 4 (SRE role assumption) and beyond are not needed.

**What you need:** Same as `start-task`, minus `sre_role_arn` and `ecs_cluster_name`.

---

## Pattern 2: Ambient AWS Credentials

Used by: `list-tasks`, `join-task`, `stop-task`, `close-investigation`, `list-investigations`

These commands skip OIDC entirely. They call AWS APIs directly using credentials that are already present in your environment.

```
You
  │
  ▼
┌──────────────────────────────────────┐
│ AWS SDK Default Credential Chain     │
│                                      │
│  The SDK checks these sources in     │
│  order and uses the first one that   │
│  provides valid credentials:         │
│                                      │
│    1. Environment variables          │
│       AWS_ACCESS_KEY_ID              │
│       AWS_SECRET_ACCESS_KEY          │
│       AWS_SESSION_TOKEN              │
│                                      │
│    2. ~/.aws/credentials file        │
│                                      │
│    3. ~/.aws/config (named profiles) │
│                                      │
│    4. ECS task role                  │
│       (if you are inside a container │
│       running on AWS ECS)            │
│                                      │
│    5. EC2 instance profile           │
│       (if you are on an EC2 machine) │
└──────────────┬───────────────────────┘
               │ AWS credentials (from wherever)
               ▼
┌──────────────────────────────────────┐
│ Direct AWS API Calls                 │
│                                      │
│  Each command calls different APIs:  │
│                                      │
│  list-tasks:                         │
│    ecs:ListTasks                     │
│    ecs:DescribeTasks                 │
│                                      │
│  join-task:                          │
│    ecs:DescribeTasks                 │
│    ecs:ExecuteCommand                │
│                                      │
│  stop-task:                          │
│    ecs:StopTask                      │
│                                      │
│  close-investigation:                │
│    ecs:ListTasks                     │
│    ecs:StopTask                      │
│    ecs:ListTaskDefinitions           │
│    ecs:DeregisterTaskDefinition      │
│    elasticfilesystem:                │
│      DescribeAccessPoints            │
│      DeleteAccessPoint               │
│                                      │
│  list-investigations:                │
│    elasticfilesystem:                │
│      DescribeAccessPoints            │
└──────────────────────────────────────┘
```

**What you need:**
- Valid AWS credentials already configured via one of the sources above
- Those credentials must have the IAM permissions listed for the command you are running
- Config: `aws_region`, `ecs_cluster_name`, and for some commands `efs_filesystem_id`

**What you do not need:**
- Keycloak, a browser, or any OIDC interaction

---

## Typical Usage: Where Do My AWS Credentials Come From?

In practice, if you have already run `start-task` (Pattern 1), the `start-task` flow assumed the SRE role and obtained temporary AWS credentials. However, those credentials are not automatically made available for subsequent Pattern 2 commands — `start-task` uses them internally and does not export them to your shell environment.

For Pattern 2 commands, you typically get AWS credentials from one of these sources:

- **AWS SSO / `aws sso login`**: If your organization uses AWS IAM Identity Center (SSO), you log in via `aws sso login` and your CLI profile provides temporary credentials.
- **Exported environment variables**: If you have obtained temporary credentials through another mechanism (e.g., a wrapper script, `aws sts assume-role`, or a credential helper), you export `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`.
- **Named profiles**: A profile in `~/.aws/config` that references a role or credential source.
- **Running on AWS infrastructure**: If you are running the CLI inside an EC2 instance or ECS task that has an IAM role attached, credentials are provided automatically.

---

## Quick Reference

### What Do I Need for Each Command?

| Command | Auth pattern | What I need |
|---------|-------------|-------------|
| `login` | OIDC | Keycloak account + browser |
| `start-task` | OIDC | Keycloak account + browser; config: `invoker_role_arn`, `lambda_function_name` |
| `create-investigation` | OIDC | Same as `start-task` |
| `list-tasks` | Ambient AWS | AWS credentials with ECS read permissions |
| `join-task` | Ambient AWS | AWS credentials with ECS exec permissions; `session-manager-plugin` in PATH |
| `stop-task` | Ambient AWS | AWS credentials with ECS stop permissions |
| `close-investigation` | Ambient AWS | AWS credentials with ECS + EFS permissions; config: `efs_filesystem_id` |
| `list-investigations` | Ambient AWS | AWS credentials with EFS read permissions; config: `efs_filesystem_id` |

### Configuration Summary

OIDC-bootstrapped commands read from `~/.config/rosa-boundary/config.yaml` (or equivalent env vars / flags):

| Config field | Env var | Required by |
|-------------|---------|-------------|
| `keycloak_url` | `ROSA_BOUNDARY_KEYCLOAK_URL` | `login`, `start-task`, `create-investigation` |
| `keycloak_realm` | `ROSA_BOUNDARY_KEYCLOAK_REALM` | `login`, `start-task`, `create-investigation` |
| `oidc_client_id` | `ROSA_BOUNDARY_OIDC_CLIENT_ID` | `login`, `start-task`, `create-investigation` |
| `invoker_role_arn` | `ROSA_BOUNDARY_INVOKER_ROLE_ARN` | `start-task`, `create-investigation` |
| `lambda_function_name` | `ROSA_BOUNDARY_LAMBDA_FUNCTION_NAME` | `start-task`, `create-investigation` |
| `sre_role_arn` | `ROSA_BOUNDARY_SRE_ROLE_ARN` | `start-task` (optional; Lambda provides default) |
| `ecs_cluster_name` | `ROSA_BOUNDARY_ECS_CLUSTER_NAME` | `start-task`, `list-tasks`, `join-task`, `stop-task`, `close-investigation` |
| `efs_filesystem_id` | `ROSA_BOUNDARY_EFS_FILESYSTEM_ID` | `close-investigation`, `list-investigations` |
| `aws_region` | `ROSA_BOUNDARY_AWS_REGION` | All commands that call AWS APIs |

---

## Related Documents

- [System Architecture Overview](overview.md) — full system design including ABAC, reaper Lambda, and audit trail
- [AWS IAM Policies](../configuration/aws-iam-policies.md) — IAM role trust policies and permission boundaries
- [Keycloak Realm Setup](../configuration/keycloak-realm-setup.md) — OIDC provider and client configuration
- [User Access Guide](../runbooks/user-access-guide.md) — end-to-end onboarding walkthrough

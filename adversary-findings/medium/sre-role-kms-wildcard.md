# M2: Shared SRE Role Grants KMS Decrypt on All Keys

- **Severity**: Medium
- **Category**: Infrastructure — Overly Permissive IAM Policy
- **File**: `deploy/regional/oidc.tf:189`

## Issue

The `KMSForECSExec` statement in the shared SRE role's policy grants `kms:Decrypt` and `kms:GenerateDataKey` on `Resource = "*"`. This allows any SRE who assumes this role to decrypt data encrypted with any KMS key in the account (subject to key policy).

## Impact

An SRE with this role could potentially decrypt data outside the scope of ECS Exec sessions if other KMS keys have permissive key policies. The task role (`aws_iam_role_policy.task_kms` at `iam.tf:224`) already correctly scopes to `aws_kms_key.exec_session.arn`.

## Recommendation

Scope the KMS resource to the specific exec session key:

```hcl
Resource = aws_kms_key.exec_session.arn
```

# M4: S3 Audit Bucket Uses SSE-S3 Instead of SSE-KMS

- **Severity**: Medium
- **Category**: Infrastructure — Encryption Configuration
- **File**: `deploy/regional/s3.tf:48`

## Issue

The S3 audit bucket uses `sse_algorithm = "AES256"` (SSE-S3) instead of `aws:kms` (SSE-KMS). SSE-S3 uses AWS-managed keys with no audit trail for key usage and no ability to control access via KMS key policies.

## Impact

For an audit log bucket with WORM compliance (Object Lock), the inability to independently audit encryption key usage or enforce key-level access controls weakens the security posture. Any principal with `s3:GetObject` permission can decrypt objects; there is no separate `kms:Decrypt` gate.

## Recommendation

Use KMS encryption with a dedicated CMK:

```hcl
apply_server_side_encryption_by_default {
  sse_algorithm     = "aws:kms"
  kms_master_key_id = aws_kms_key.audit_bucket.arn
}
```

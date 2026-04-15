# M3: CloudWatch Logs Encryption Disabled for SSM Sessions

- **Severity**: Medium
- **Category**: Infrastructure — Encryption Gap
- **File**: `deploy/regional/ecs.tf:17`

## Issue

The ECS cluster's execute command configuration sets `cloud_watch_encryption_enabled = false`. While the ECS Exec session itself is encrypted with KMS, the log data written to the CloudWatch log group for SSM sessions is not encrypted within the CloudWatch transport layer. The CloudWatch log group (`ssm_sessions`) lacks a `kms_key_id` attribute, meaning logs are stored with default AWS-managed encryption only.

## Impact

SSM session logs may contain sensitive commands and output from SRE investigations. Without CMK encryption on the log group, there is less control over who can decrypt and read these logs. This is a defense-in-depth gap — CloudWatch Logs are encrypted at rest with AWS-managed keys by default.

## Recommendation

Enable CloudWatch encryption and attach the KMS key to the log group:

```hcl
cloud_watch_encryption_enabled = true
```

Add `kms_key_id` to the `ssm_sessions` log group:

```hcl
resource "aws_cloudwatch_log_group" "ssm_sessions" {
  name              = "/ecs/${var.project}-${var.stage}/ssm-sessions"
  retention_in_days = var.retention_days
  kms_key_id        = aws_kms_key.exec_session.arn
  tags              = local.common_tags
}
```

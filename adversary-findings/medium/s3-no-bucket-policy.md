# M6: No S3 Bucket Policy (Missing Deny-Non-TLS, No Access Logging)

- **Severity**: Medium
- **Category**: Infrastructure — Missing Access Control and Auditability
- **File**: `deploy/regional/s3.tf`

## Issue

The S3 audit bucket has no `aws_s3_bucket_policy` to enforce encryption in transit (deny non-TLS requests) or restrict access. It also has no S3 server access logging or CloudTrail data events configured for the bucket.

## Impact

Without a deny-non-TLS policy, objects could theoretically be uploaded over unencrypted HTTP if VPC endpoints or proxy configurations allow it. Without access logging, unauthorized access attempts to audit data would go undetected.

## Recommendation

Add a bucket policy requiring TLS:

```hcl
resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonTLS"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [
        "${aws_s3_bucket.audit.arn}",
        "${aws_s3_bucket.audit.arn}/*"
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}
```

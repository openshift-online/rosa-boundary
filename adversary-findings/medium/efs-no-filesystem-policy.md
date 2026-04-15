# M5: No EFS Filesystem Policy Enforcing IAM Authorization

- **Severity**: Medium
- **Category**: Infrastructure — Missing Access Control
- **File**: `deploy/regional/efs.tf`

## Issue

The EFS filesystem has no `aws_efs_file_system_policy` resource. While the access points require IAM (`iam = "ENABLED"` in the task definition), the filesystem itself does not enforce IAM authorization or deny anonymous access. Any entity with network access to the mount targets (port 2049) could potentially mount the filesystem directly without an access point.

## Impact

If the Fargate security group or VPC network controls are misconfigured, an attacker with network access to the NFS port could mount the EFS filesystem as root and access all investigation data across all access points.

## Recommendation

Add a filesystem policy that enforces IAM authentication:

```hcl
resource "aws_efs_file_system_policy" "sre_home" {
  file_system_id = aws_efs_file_system.sre_home.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = [
        "elasticfilesystem:ClientMount",
        "elasticfilesystem:ClientWrite"
      ]
      Resource  = aws_efs_file_system.sre_home.arn
      Condition = {
        Bool = {
          "elasticfilesystem:AccessedViaMountTarget" = "true"
        }
        StringEquals = {
          "elasticfilesystem:AccessPointArn" = "arn:aws:elasticfilesystem:*:*:access-point/*"
        }
      }
    }]
  })
}
```

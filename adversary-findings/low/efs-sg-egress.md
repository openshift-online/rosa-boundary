# L2: EFS Security Group Allows All Egress

- **Severity**: Low
- **Category**: Infrastructure — Overly Permissive Network Configuration
- **Files**: `deploy/regional/efs.tf:31-36`

## Issue

The EFS security group allows all outbound traffic to `0.0.0.0/0` on all ports and protocols. EFS mount targets only need inbound NFS (port 2049) and do not initiate outbound connections.

## Impact

Minimal direct risk, but defense-in-depth suggests removing unnecessary egress from the EFS security group.

## Recommendation

Remove the egress rule from the EFS security group entirely, or scope it to only the VPC CIDR if required:

```hcl
resource "aws_security_group" "efs" {
  # Remove the egress block entirely for EFS mount targets
  ...
}
```

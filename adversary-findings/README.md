# Adversary Security Findings

Security scan performed **2026-04-15** against commit `bacef1e` (branch `main`).

## Summary

- **Medium**: 10 findings (IAM scoping, encryption gaps, missing policies, supply chain)
- **Low**: 7 findings (XSS, network config, input validation, image pinning)
- **No Critical or High findings**

Overall: strong security fundamentals with defense-in-depth hardening opportunities.

## Findings Index

### Medium

| # | File | Finding |
|---|------|---------|
| M1 | [lambda-ecs-wildcard-iam.md](medium/lambda-ecs-wildcard-iam.md) | Lambda ECS IAM policy uses wildcard resource |
| M2 | [sre-role-kms-wildcard.md](medium/sre-role-kms-wildcard.md) | Shared SRE role grants KMS on all keys |
| M3 | [cloudwatch-encryption-disabled.md](medium/cloudwatch-encryption-disabled.md) | CloudWatch Logs encryption disabled for SSM sessions |
| M4 | [s3-sse-s3-not-kms.md](medium/s3-sse-s3-not-kms.md) | S3 audit bucket uses SSE-S3 instead of SSE-KMS |
| M5 | [efs-no-filesystem-policy.md](medium/efs-no-filesystem-policy.md) | No EFS filesystem policy enforcing IAM auth |
| M6 | [s3-no-bucket-policy.md](medium/s3-no-bucket-policy.md) | No S3 bucket policy (deny-non-TLS, no access logging) |
| M7 | [lambda-cors-wildcard.md](medium/lambda-cors-wildcard.md) | Lambda CORS allows all origins |
| M8 | [container-sudo-all.md](medium/container-sudo-all.md) | Container grants passwordless sudo ALL |
| M9 | [lambda-deps-unpinned.md](medium/lambda-deps-unpinned.md) | Python Lambda deps use >= version pinning |
| M10 | [bedrock-iam-all-regions.md](medium/bedrock-iam-all-regions.md) | Bedrock IAM policy allows all regions and models |

### Low

| # | File | Finding |
|---|------|---------|
| L1 | [oauth-callback-xss.md](low/oauth-callback-xss.md) | Reflected XSS in OAuth callback error page |
| L2 | [efs-sg-egress.md](low/efs-sg-egress.md) | EFS security group allows all egress |
| L3 | [example-public-ip.md](low/example-public-ip.md) | Example script uses assignPublicIp=ENABLED |
| L4 | [oc-version-unvalidated.md](low/oc-version-unvalidated.md) | oc_version not validated in Lambda handler |
| L5 | [terraform-provider-broad-pin.md](low/terraform-provider-broad-pin.md) | Terraform AWS provider broadly pinned |
| L6 | [containerfile-unpinned-base.md](low/containerfile-unpinned-base.md) | Unpinned Fedora base image |
| L7 | [claude-code-piped-install.md](low/claude-code-piped-install.md) | Claude Code installed via piped shell |

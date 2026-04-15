# M10: Bedrock IAM Policy Allows All Regions and All Models

- **Severity**: Medium
- **Category**: Infrastructure — Overly Permissive IAM Policy
- **File**: `deploy/regional/iam.tf:155-165`

## Issue

The Bedrock policy grants `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream` on `arn:aws:bedrock:*:*:inference-profile/*` and `arn:aws:bedrock:*:*:foundation-model/*`. The wildcard regions and all-model access mean the task role can invoke any foundation model in any region.

## Impact

If an SRE's container is compromised, the attacker can invoke arbitrary Bedrock models (potentially expensive ones) in any region, leading to cost abuse. Additionally, data sent to Bedrock models outside the expected region may violate data residency requirements.

## Recommendation

Scope to the specific region and model(s) needed:

```hcl
Resource = [
  "arn:aws:bedrock:${data.aws_region.current.name}::foundation-model/anthropic.claude-*",
  "arn:aws:bedrock:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:inference-profile/*"
]
```

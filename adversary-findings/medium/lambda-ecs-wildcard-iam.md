# M1: Lambda ECS IAM Policy Uses Wildcard Resource

- **Severity**: Medium
- **Category**: Infrastructure — Overly Permissive IAM Policy
- **File**: `deploy/regional/lambda-create-investigation.tf:55`

## Issue

The Lambda IAM policy grants `ecs:RunTask`, `ecs:StopTask`, `ecs:RegisterTaskDefinition`, `ecs:DeregisterTaskDefinition`, `ecs:TagResource`, and other ECS actions on `Resource = "*"`. This allows the Lambda function to manage tasks and task definitions across any ECS cluster in the account.

## Impact

If the Lambda is compromised (e.g., via a token validation bypass or dependency supply chain attack), the attacker can launch, stop, or register task definitions in any cluster in the AWS account.

## Recommendation

Scope ECS resources to the specific cluster:

```hcl
Resource = [
  aws_ecs_cluster.main.arn,
  "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.main.name}/*",
  "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:task-definition/${var.project}-${var.stage}*"
]
```

Note: `RegisterTaskDefinition` and `DeregisterTaskDefinition` do not support resource-level scoping in IAM and must use `*`, but `RunTask`, `StopTask`, and `TagResource` can be scoped.

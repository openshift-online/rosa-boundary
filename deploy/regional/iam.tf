# Regional grants on shared account identities. Addresses and scopes are restored
# from 91c73fb. Only the designated legacy policy region retains unsuffixed names.
# Each (role, policy name) has one owner; no exclusive policy reconciliation.

# ROSAENG-68823: CloudWatch metric reads for an external collector.
#
# The role itself is account-owned; this is its only grant. CloudWatch metric
# reads cannot be scoped by resource ARN, and tag:GetResources is what the
# collector's discovery jobs use to find resources. tag:GetResources is
# cross-service by nature - it lists ARNs and tags of tagged resources across
# services - but it exposes no service configuration or data, and no other
# service's Describe/List is granted. Adding a service to the collector may
# therefore still require a reviewed change here.
#
# Deliberately NOT the AWS managed CloudWatchReadOnlyAccess, which also grants
# logs and autoscaling reads this collector has no reason to hold.
#
# Single owner: the grant is account-global in effect (Resource = "*"), so only
# the designated legacy policy region manages it. A second region enabling this
# would produce a duplicate policy on the same role for no benefit, so the
# precondition fails the plan instead of letting it happen quietly.
resource "aws_iam_role_policy" "metrics_read" {
  count = var.enable_metrics_read_grant ? 1 : 0
  # The suffix is always empty while the precondition below pins this grant to
  # the legacy policy region; it is kept for consistency with its siblings.
  name = "metrics-read${local.regional_policy_suffix}"
  role = data.aws_iam_role.metrics_read[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "cloudwatch:ListMetrics",
        "cloudwatch:GetMetricData",
        "cloudwatch:GetMetricStatistics",
        "tag:GetResources",
      ]
      Resource = "*"
    }]
  })

  lifecycle {
    precondition {
      condition     = var.aws_region == var.legacy_policy_region
      error_message = "enable_metrics_read_grant may only be set in the legacy_policy_region workspace: the grant is account-global, so a second region would manage a duplicate policy on the same role."
    }
  }
}

resource "aws_iam_role_policy" "s3_replication" {
  count = var.audit_replication_bucket_arn != "" ? 1 : 0
  name  = "s3-replication-policy${local.regional_policy_suffix}"
  role  = data.aws_iam_role.s3_replication[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
        Resource = aws_s3_bucket.audit.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging", "s3:GetObjectRetention", "s3:GetObjectLegalHold"
        ]
        Resource = "${aws_s3_bucket.audit.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags", "s3:ObjectOwnerOverrideToBucketOwner"]
        Resource = "${var.audit_replication_bucket_arn}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "execution_secrets" {
  name = "secrets-manager-access${local.regional_policy_suffix}"
  role = data.aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
      Resource = "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:secret:${var.project}/*"
    }]
  })
}

resource "aws_iam_role_policy" "task_s3" {
  name = "s3-audit-access${local.regional_policy_suffix}"
  role = data.aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${aws_s3_bucket.audit.arn}/*" },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = aws_s3_bucket.audit.arn }
    ]
  })
}

resource "aws_iam_role_policy" "task_bedrock" {
  name = "bedrock-access${local.regional_policy_suffix}"
  role = data.aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "bedrock:ListInferenceProfiles"]
        Resource = [
          "arn:${data.aws_partition.current.partition}:bedrock:*:*:inference-profile/*",
          "arn:${data.aws_partition.current.partition}:bedrock:*:*:foundation-model/*"
        ]
      },
      {
        # Resolve the profile to its backing model without a fallback retry.
        Effect = "Allow"
        Action = ["bedrock:GetInferenceProfile"]
        Resource = [
          "arn:${data.aws_partition.current.partition}:bedrock:${var.aws_region}:${data.aws_caller_identity.current.account_id}:inference-profile/*",
          "arn:${data.aws_partition.current.partition}:bedrock:${var.aws_region}:${data.aws_caller_identity.current.account_id}:application-inference-profile/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "task_ecs_exec" {
  name = "ecs-exec-access${local.regional_policy_suffix}"
  role = data.aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel", "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "task_ssm_logging" {
  name = "ssm-session-logging${local.regional_policy_suffix}"
  role = data.aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # DescribeLogGroups does not support resource-level authorization.
        Effect   = "Allow"
        Action   = ["logs:DescribeLogGroups"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
        Resource = [aws_cloudwatch_log_group.ssm_sessions.arn, "${aws_cloudwatch_log_group.ssm_sessions.arn}:*"]
      }
    ]
  })
}

resource "aws_iam_role_policy" "task_kms" {
  name = "kms-exec-session${local.regional_policy_suffix}"
  role = data.aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
      Resource = aws_kms_key.exec_session.arn
    }]
  })
}

resource "aws_iam_role_policy" "sre_shared_ecs_exec" {
  name = "ecs-exec-abac${local.regional_policy_suffix}"
  role = data.aws_iam_role.sre_shared.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Cluster authorization alone grants no task access.
        Sid      = "ExecuteCommandOnCluster"
        Effect   = "Allow"
        Action   = ["ecs:ExecuteCommand"]
        Resource = [aws_ecs_cluster.main.arn]
      },
      {
        Sid      = "ExecuteCommandOnOwnedTasks"
        Effect   = "Allow"
        Action   = ["ecs:ExecuteCommand"]
        Resource = "*"
        Condition = {
          StringEquals = {
            # The JWT principal tag must match the ECS resource tag (fail closed).
            "ecs:ResourceTag/${var.abac_tag_key}" = "$${aws:PrincipalTag/${var.abac_tag_key}}"
          }
        }
      },
      {
        Sid      = "StopOwnedTasks"
        Effect   = "Allow"
        Action   = ["ecs:StopTask"]
        Resource = "arn:${data.aws_partition.current.partition}:ecs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.main.name}/*"
        Condition = {
          StringEquals = { "ecs:ResourceTag/${var.abac_tag_key}" = "$${aws:PrincipalTag/${var.abac_tag_key}}" }
        }
      },
      {
        # List/deregister task definitions do not support resource-level scopes.
        Sid      = "DescribeListAndCleanupECS"
        Effect   = "Allow"
        Action   = ["ecs:DescribeTasks", "ecs:ListTasks", "ecs:DescribeTaskDefinition", "ecs:ListTaskDefinitions", "ecs:DeregisterTaskDefinition"]
        Resource = "*"
      },
      {
        Sid      = "EFSReadAccessPoints"
        Effect   = "Allow"
        Action   = ["elasticfilesystem:DescribeAccessPoints"]
        Resource = aws_efs_file_system.sre_home.arn
      },
      {
        # Dynamic access-point IDs require this original region/account scope;
        # deletion remains restricted to Lambda-managed access points by tag.
        Sid       = "EFSDeleteManagedAccessPoints"
        Effect    = "Allow"
        Action    = ["elasticfilesystem:DeleteAccessPoint"]
        Resource  = "arn:${data.aws_partition.current.partition}:elasticfilesystem:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:access-point/*"
        Condition = { StringEquals = { "aws:ResourceTag/ManagedBy" = "rosa-boundary-lambda" } }
      },
      {
        # The SSM API cannot inspect ECS tags; ECS ExecuteCommand enforces ABAC.
        Sid    = "SSMSessionForECSExec"
        Effect = "Allow"
        Action = ["ssm:StartSession"]
        Resource = [
          "arn:${data.aws_partition.current.partition}:ecs:*:*:task/*",
          "arn:${data.aws_partition.current.partition}:ssm:*:*:document/AWS-StartInteractiveCommand"
        ]
      },
      {
        # The caller opens the pre-signed relay; only the task needs Create*.
        Sid      = "SSMMessagesForECSExec"
        Effect   = "Allow"
        Action   = ["ssmmessages:OpenDataChannel"]
        Resource = "*"
      },
      {
        # Preserve the baseline scope; narrowing is a separate security change.
        Sid      = "KMSForECSExec"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_invoker" {
  name = "invoke-create-investigation${local.regional_policy_suffix}"
  role = data.aws_iam_role.lambda_invoker.id
  # Direct SDK invocation preserves the original SCP-compliant path.
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "lambda:InvokeFunction", Resource = local.create_investigation_function_arn }]
  })
}

resource "aws_iam_role_policy" "create_investigation_lambda_ecs" {
  name = "ecs-task-management${local.regional_policy_suffix}"
  role = data.aws_iam_role.create_investigation_lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecs:RunTask", "ecs:StopTask", "ecs:ListTasks", "ecs:DescribeTasks", "ecs:DescribeTaskDefinition", "ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition", "ecs:TagResource"]
        Resource = "*"
      },
      { Effect = "Allow", Action = ["iam:PassRole"], Resource = [data.aws_iam_role.task.arn, data.aws_iam_role.execution.arn] },
      {
        # DescribeSessions does not support resource-level scoping.
        Effect   = "Allow"
        Action   = ["ssm:DescribeSessions"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "create_investigation_lambda_efs" {
  name = "efs-access-point-management${local.regional_policy_suffix}"
  role = data.aws_iam_role.create_investigation_lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["elasticfilesystem:CreateAccessPoint", "elasticfilesystem:DeleteAccessPoint", "elasticfilesystem:DescribeAccessPoints", "elasticfilesystem:TagResource"]
      Resource = aws_efs_file_system.sre_home.arn
    }]
  })
}

resource "aws_iam_role_policy" "reap_tasks_lambda_ecs" {
  name = "ecs-task-reaping${local.regional_policy_suffix}"
  role = data.aws_iam_role.reap_tasks_lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = ["ecs:ListTasks"]
        Resource  = "*"
        Condition = { StringEquals = { "ecs:cluster" = aws_ecs_cluster.main.arn } }
      },
      {
        Effect   = "Allow"
        Action   = ["ecs:DescribeTasks"]
        Resource = "arn:${data.aws_partition.current.partition}:ecs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.main.name}/*"
      },
      {
        Effect    = "Allow"
        Action    = ["ecs:StopTask"]
        Resource  = "arn:${data.aws_partition.current.partition}:ecs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.main.name}/*"
        Condition = { "ForAnyValue:StringLike" = { "ecs:ResourceTag/deadline" = "*" } }
      },
      {
        # DescribeSessions cannot be scoped to an SSM resource ARN. Check active
        # ECS Exec sessions before reaping expired tasks (main #323).
        Effect   = "Allow"
        Action   = ["ssm:DescribeSessions"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "bedrock_invocation_logging" {
  name = "write-model-invocations${local.regional_policy_suffix}"
  role = data.aws_iam_role.bedrock_invocation_logging.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.bedrock_invocations.arn}:log-stream:aws/bedrock/modelinvocations"
    }]
  })
}

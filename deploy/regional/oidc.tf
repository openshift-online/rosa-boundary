# AWS IAM OIDC Provider for Keycloak
resource "aws_iam_openid_connect_provider" "keycloak" {
  url = var.keycloak_issuer_url

  client_id_list = [
    var.oidc_client_id
  ]

  thumbprint_list = [
    var.keycloak_thumbprint
  ]

  tags = merge(var.tags, {
    Name = "${var.project}-${var.stage}-keycloak-oidc"
  })
}

# Optional second OIDC provider (e.g. Red Hat EmployeeIDP stage)
resource "aws_iam_openid_connect_provider" "stage_keycloak" {
  count = var.stage_keycloak_issuer_url != "" ? 1 : 0

  url             = var.stage_keycloak_issuer_url
  client_id_list  = [var.stage_oidc_client_id]
  thumbprint_list = [var.stage_keycloak_thumbprint]

  lifecycle {
    precondition {
      condition     = var.stage_oidc_client_id != ""
      error_message = "stage_oidc_client_id must be set when stage_keycloak_issuer_url is configured."
    }
    precondition {
      condition     = var.stage_keycloak_thumbprint != ""
      error_message = "stage_keycloak_thumbprint must be set when stage_keycloak_issuer_url is configured."
    }
  }

  tags = merge(var.tags, {
    Name = "${var.project}-${var.stage}-stage-oidc"
  })
}

# Optional third OIDC provider (e.g. Red Hat EmployeeIDP production)
resource "aws_iam_openid_connect_provider" "prod_keycloak" {
  count = var.prod_keycloak_issuer_url != "" ? 1 : 0

  url             = var.prod_keycloak_issuer_url
  client_id_list  = [var.prod_oidc_client_id]
  thumbprint_list = [var.prod_keycloak_thumbprint]

  lifecycle {
    precondition {
      condition     = var.prod_oidc_client_id != ""
      error_message = "prod_oidc_client_id must be set when prod_keycloak_issuer_url is configured."
    }
    precondition {
      condition     = var.prod_keycloak_thumbprint != ""
      error_message = "prod_keycloak_thumbprint must be set when prod_keycloak_issuer_url is configured."
    }
  }

  tags = merge(var.tags, {
    Name = "${var.project}-${var.stage}-prod-oidc"
  })
}

locals {
  # Extract OIDC provider domain from ARN for use in trust policy conditions.
  # ARN format: arn:aws:iam::<account>:oidc-provider/<domain>
  oidc_provider_domain       = split("oidc-provider/", aws_iam_openid_connect_provider.keycloak.arn)[1]
  stage_oidc_provider_domain = var.stage_keycloak_issuer_url != "" ? split("oidc-provider/", aws_iam_openid_connect_provider.stage_keycloak[0].arn)[1] : ""
  prod_oidc_provider_domain  = var.prod_keycloak_issuer_url != "" ? split("oidc-provider/", aws_iam_openid_connect_provider.prod_keycloak[0].arn)[1] : ""
}

# Shared SRE IAM role using ABAC (Attribute-Based Access Control).
#
# Instead of creating one role per user, all SREs assume this single role.
# Isolation is enforced via session tags: the OIDC provider adds the user's
# unique identifier (uuid) to the JWT under the https://aws.amazon.com/tags claim,
# which AWS STS automatically processes as session tags during AssumeRoleWithWebIdentity.
#
# The permissions policy then uses ${aws:PrincipalTag/<abac_tag_key>} to match against
# ecs:ResourceTag/<abac_tag_key> on ECS tasks, so each user can only exec into tasks
# they own — enforced at the AWS API layer without per-user roles.
resource "aws_iam_role" "sre_shared" {
  name                 = "${var.project}-${var.stage}-sre-shared"
  max_session_duration = var.oidc_session_duration

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.keycloak.arn
        }
        # sts:TagSession is required for session tags from the JWT
        # https://aws.amazon.com/tags claim to propagate.
        Action = [
          "sts:AssumeRoleWithWebIdentity",
          "sts:TagSession"
        ]
        Condition = {
          StringEquals = merge(
            {
              "${local.oidc_provider_domain}:aud" = var.oidc_client_id
            },
            var.enable_uuid_allowlist ? {
              "aws:RequestTag/uuid" = var.allowed_uuids
            } : {},
            var.enable_oidc_group_enforcement ? {
              "aws:RequestTag/roles" = var.required_oidc_role
            } : {}
          )
        }
      }],
      var.stage_keycloak_issuer_url != "" ? [{
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.stage_keycloak[0].arn
        }
        Action = [
          "sts:AssumeRoleWithWebIdentity",
          "sts:TagSession"
        ]
        Condition = {
          StringEquals = merge(
            {
              "${local.stage_oidc_provider_domain}:aud" = var.stage_oidc_client_id
            },
            var.enable_uuid_allowlist ? {
              "aws:RequestTag/uuid" = var.allowed_uuids
            } : {},
            var.enable_oidc_group_enforcement ? {
              "aws:RequestTag/roles" = var.required_oidc_role
            } : {}
          )
        }
      }] : [],
      var.prod_keycloak_issuer_url != "" ? [{
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.prod_keycloak[0].arn
        }
        Action = [
          "sts:AssumeRoleWithWebIdentity",
          "sts:TagSession"
        ]
        Condition = {
          StringEquals = merge(
            {
              "${local.prod_oidc_provider_domain}:aud" = var.prod_oidc_client_id
            },
            var.enable_uuid_allowlist ? {
              "aws:RequestTag/uuid" = var.allowed_uuids
            } : {},
            var.enable_oidc_group_enforcement ? {
              "aws:RequestTag/roles" = var.required_oidc_role
            } : {}
          )
        }
      }] : []
    )
  })

  lifecycle {
    precondition {
      condition     = !var.enable_uuid_allowlist || length(var.allowed_uuids) > 0
      error_message = "allowed_uuids must contain at least one UUID when enable_uuid_allowlist is true."
    }
    precondition {
      condition     = !var.enable_oidc_group_enforcement || var.required_oidc_role != ""
      error_message = "required_oidc_role must be set when enable_oidc_group_enforcement is true."
    }
  }

  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-sre-shared"
  })
}

# ABAC permissions policy for the shared SRE role.
#
# IAM Policy Design: Two-Statement Structure for ECS Exec Isolation
#
# ecs:ExecuteCommand requires permissions on BOTH the cluster AND the task.
#
# Statement 1 (ExecuteCommandOnCluster):
#   - Grants permission on the cluster resource
#   - No condition — all SREs pass the cluster check
#   - This alone grants NO task access ("badge to enter the building")
#
# Statement 2 (ExecuteCommandOnOwnedTasks):
#   - Grants permission on task resources with dynamic ABAC condition
#   - ${aws:PrincipalTag/<abac_tag_key>} resolves per-session from the JWT session tag
#   - Only grants access to tasks tagged with matching ABAC tag value
#   - Fail-closed: missing session tag → no PrincipalTag → condition fails → deny
#
# Security properties:
#   - Users CANNOT access tasks tagged to other users (ABAC tag mismatch → deny)
#   - Users CANNOT access untagged tasks (missing tag fails condition)
#   - Tag values come from the OIDC JWT, not from user-controlled input
#   - Keycloak mapper misconfiguration → fail-closed (no tag → deny)
resource "aws_iam_role_policy" "sre_shared_ecs_exec" {
  name = "ecs-exec-abac"
  role = aws_iam_role.sre_shared.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ExecuteCommandOnCluster"
        Effect = "Allow"
        Action = ["ecs:ExecuteCommand"]
        Resource = [
          aws_ecs_cluster.main.arn
        ]
        # No condition — required prerequisite for all ECS exec operations.
        # This alone does NOT grant access to any tasks.
      },
      {
        Sid      = "ExecuteCommandOnOwnedTasks"
        Effect   = "Allow"
        Action   = ["ecs:ExecuteCommand"]
        Resource = "*"
        Condition = {
          StringEquals = {
            # $${...} escapes Terraform interpolation; produces ${aws:PrincipalTag/<key>}
            # in the policy JSON. This resolves dynamically per session from the JWT
            # session tag set by the Keycloak https://aws.amazon.com/tags mapper.
            # abac_tag_key must match the principal_tags key in the OIDC JWT
            # (e.g. "username" for dev Keycloak, "uuid" for Red Hat EmployeeIDP).
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
          StringEquals = {
            "ecs:ResourceTag/${var.abac_tag_key}" = "$${aws:PrincipalTag/${var.abac_tag_key}}"
          }
        }
      },
      {
        Sid    = "DescribeAndListECS"
        Effect = "Allow"
        Action = [
          "ecs:DescribeTasks",
          "ecs:ListTasks",
          "ecs:DescribeTaskDefinition"
        ]
        Resource = "*"
      },
      {
        Sid    = "DeregisterTaskDefinition"
        Effect = "Allow"
        Action = ["ecs:DeregisterTaskDefinition"]
        # Scoped to task definition families matching the project prefix.
        # Per-investigation task defs follow the pattern:
        #   {project}-{stage}-{cluster_id}-{investigation_id}-{timestamp}
        Resource = "arn:${data.aws_partition.current.partition}:ecs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:task-definition/${var.project}-${var.stage}-*"
      },
      {
        Sid      = "EFSDescribeAccessPoints"
        Effect   = "Allow"
        Action   = ["elasticfilesystem:DescribeAccessPoints"]
        Resource = aws_efs_file_system.sre_home.arn
      },
      {
        Sid    = "EFSDeleteOwnedAccessPoints"
        Effect = "Allow"
        Action = ["elasticfilesystem:DeleteAccessPoint"]
        # Access point ARNs are the correct resource type for DeleteAccessPoint.
        # Defense-in-depth: Three independent tag validations ensure access points are
        # (1) owned by the caller, (2) managed by rosa-boundary, and (3) on sre_home filesystem.
        # NOTE: AWS IAM does not provide a non-tag condition key to validate filesystem
        # association for DeleteAccessPoint action. Tags provide the only available validation.
        Resource = "arn:${data.aws_partition.current.partition}:elasticfilesystem:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:access-point/*"
        Condition = {
          StringEquals = {
            # ABAC: Only allow deleting access points tagged with the user's principal tag.
            # Access points created by rosa-boundary are tagged with the ABAC identifier from JWT.
            # EFS uses the global aws:ResourceTag prefix (not elasticfilesystem:ResourceTag).
            "aws:ResourceTag/${var.abac_tag_key}" = "$${aws:PrincipalTag/${var.abac_tag_key}}"
            # Constrain to rosa-boundary-managed access points only.
            # Lambda tags all access points with ManagedBy=rosa-boundary-lambda.
            "aws:ResourceTag/ManagedBy" = "rosa-boundary-lambda"
            # SECURITY: Validate access point is on sre_home filesystem only.
            # Prevents deletion of access points on other filesystems even if tagged correctly.
            # Lambda must tag access points with FileSystemId on creation.
            "aws:ResourceTag/FileSystemId" = aws_efs_file_system.sre_home.id
          }
        }
      },
      {
        Sid    = "SSMSessionForECSExec"
        Effect = "Allow"
        Action = ["ssm:StartSession"]
        Resource = [
          "arn:${data.aws_partition.current.partition}:ecs:*:*:task/*",
          "arn:${data.aws_partition.current.partition}:ssm:*:*:document/AWS-StartInteractiveCommand"
        ]
        # No tag condition — access control is enforced by ecs:ExecuteCommand above.
        # The SSM API does not have access to ECS resource tags.
      },
      {
        Sid      = "SSMMessagesForECSExec"
        Effect   = "Allow"
        Action   = ["ssmmessages:OpenDataChannel"]
        Resource = "*"
        # The operator (caller) needs OpenDataChannel to connect to the WebSocket relay
        # that ECS generates as a pre-signed URL signed with the caller's credentials.
        # The Create* actions are needed only by the container (task role), not the caller.
      },
      {
        Sid    = "KMSForECSExec"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}

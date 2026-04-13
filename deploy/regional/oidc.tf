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

  url            = var.stage_keycloak_issuer_url
  client_id_list = [var.stage_oidc_client_id]
  thumbprint_list = [var.stage_keycloak_thumbprint]

  tags = merge(var.tags, {
    Name = "${var.project}-${var.stage}-stage-oidc"
  })
}

locals {
  # Extract OIDC provider domain from ARN for use in trust policy conditions.
  # ARN format: arn:aws:iam::<account>:oidc-provider/<domain>
  oidc_provider_domain       = split("oidc-provider/", aws_iam_openid_connect_provider.keycloak.arn)[1]
  stage_oidc_provider_domain = var.stage_keycloak_issuer_url != "" ? split("oidc-provider/", aws_iam_openid_connect_provider.stage_keycloak[0].arn)[1] : ""
}

# Shared SRE IAM role using ABAC (Attribute-Based Access Control).
#
# Instead of creating one role per user, all SREs assume this single role.
# Isolation is enforced via session tags: Keycloak adds the user's preferred
# username to the JWT under the https://aws.amazon.com/tags claim, which AWS
# STS automatically processes as session tags during AssumeRoleWithWebIdentity.
#
# The permissions policy then uses ${aws:PrincipalTag/username} to match against
# ecs:ResourceTag/username on ECS tasks, so each user can only exec into tasks
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
          StringEquals = {
            "${local.oidc_provider_domain}:aud" = var.oidc_client_id
          }
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
          StringEquals = {
            "${local.stage_oidc_provider_domain}:aud" = var.stage_oidc_client_id
          }
        }
      }] : []
    )
  })

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
#   - ${aws:PrincipalTag/username} resolves per-session from the JWT session tag
#   - Only grants access to tasks tagged with matching username value
#   - Fail-closed: missing session tag → no PrincipalTag → condition fails → deny
#
# Security properties:
#   - Users CANNOT access tasks tagged to other users (username mismatch → deny)
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
        Sid    = "SSMSessionForECSExec"
        Effect = "Allow"
        Action = ["ssm:StartSession"]
        Resource = [
          "arn:aws:ecs:*:*:task/*",
          "arn:aws:ssm:*:*:document/AWS-StartInteractiveCommand"
        ]
        # No tag condition — access control is enforced by ecs:ExecuteCommand above.
        # The SSM API does not have access to ECS resource tags.
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

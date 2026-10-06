locals {
  # Extract OIDC provider domain from ARN for use in trust policy conditions.
  # ARN format: arn:aws:iam::<account>:oidc-provider/<domain>
  oidc_provider_domain       = split("oidc-provider/", var.keycloak_provider_arn)[1]
  stage_oidc_provider_domain = var.stage_keycloak_issuer_url != "" ? split("oidc-provider/", var.stage_keycloak_provider_arn)[1] : ""
  prod_oidc_provider_domain  = var.prod_keycloak_issuer_url != "" ? split("oidc-provider/", var.prod_keycloak_provider_arn)[1] : ""
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
  name                 = "${var.role_name_prefix}-sre-shared"
  max_session_duration = var.oidc_session_duration

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Effect = "Allow"
        Principal = {
          Federated = var.keycloak_provider_arn
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
          Federated = var.stage_keycloak_provider_arn
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
          Federated = var.prod_keycloak_provider_arn
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
    Name = "${var.role_name_prefix}-sre-shared"
  })
}

# Account-owned IAM role for Lambda function URL invocation via OIDC federation.
#
# SREs assume this role using AssumeRoleWithWebIdentity with their Keycloak OIDC
# token to obtain SigV4 credentials for calling the create-investigation Lambda URL.
#
# This provides a first authentication layer (AWS IAM/SigV4) before the Lambda
# performs its own OIDC token validation for application-level authorization.

resource "aws_iam_role" "lambda_invoker" {
  name                 = "${var.role_name_prefix}-lambda-invoker"
  max_session_duration = 3600 # AWS minimum; actual sessions are short-lived

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Effect = "Allow"
        Principal = {
          Federated = var.keycloak_provider_arn
        }
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

  tags = merge(local.common_tags, {
    Name = "${var.role_name_prefix}-lambda-invoker"
  })
}

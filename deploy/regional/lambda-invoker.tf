# IAM role for Lambda function URL invocation via OIDC federation.
#
# SREs assume this role using AssumeRoleWithWebIdentity with their Keycloak OIDC
# token to obtain SigV4 credentials for calling the create-investigation Lambda URL.
#
# This provides a first authentication layer (AWS IAM/SigV4) before the Lambda
# performs its own OIDC token validation for application-level authorization.

resource "aws_iam_role" "lambda_invoker" {
  name                 = "${var.project}-${var.stage}-lambda-invoker"
  max_session_duration = 3600 # AWS minimum; actual sessions are short-lived

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.keycloak.arn
      }
      Action = [
        "sts:AssumeRoleWithWebIdentity",
        "sts:TagSession"
      ]
      Condition = {
        StringEquals = {
          "${local.oidc_provider_domain}:aud" = var.oidc_client_id
        }
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-lambda-invoker"
  })
}

resource "aws_iam_role_policy" "lambda_invoker" {
  name = "invoke-create-investigation"
  role = aws_iam_role.lambda_invoker.id

  # Uses lambda:InvokeFunction (direct SDK invocation) rather than lambda:InvokeFunctionUrl
  # because org-level SCPs block InvokeFunctionUrl from OIDC-assumed role sessions.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.create_investigation.arn
    }]
  })
}

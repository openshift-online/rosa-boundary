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

# NOTE: Generic OIDC SRE role removed for security
# Per-user IAM roles are now created dynamically by the Lambda function
# with tag-based permissions that restrict access to only the tasks
# owned by that specific user (via owner_sub tag matching)

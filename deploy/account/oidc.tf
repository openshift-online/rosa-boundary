# Singleton providers retain their original names, tags, audiences and thumbprints.
resource "aws_iam_openid_connect_provider" "keycloak" {
  url             = var.keycloak_issuer_url
  client_id_list  = [var.oidc_client_id]
  thumbprint_list = [var.keycloak_thumbprint]
  tags = merge(var.tags, {
    Name = "${var.project}-${var.stage}-keycloak-oidc"
  })
}

resource "aws_iam_openid_connect_provider" "stage_keycloak" {
  count           = var.stage_keycloak_issuer_url != "" ? 1 : 0
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

resource "aws_iam_openid_connect_provider" "prod_keycloak" {
  count           = var.prod_keycloak_issuer_url != "" ? 1 : 0
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

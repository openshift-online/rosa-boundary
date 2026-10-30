# The staging publication source is an ordinary ECR repository, not the
# Quay pull-through-cache namespace. The account root manages it in its
# configured provider Region; regional Lambda image URIs are managed separately.
resource "aws_ecr_repository" "create_investigation_lambda_source" {
  count = var.enable_lambda_ecr_source ? 1 : 0

  name                 = "${var.project}/create-investigation-lambda"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.common_tags
}

# Retain tagged releases for rollback; never force-delete a populated repository.
resource "aws_ecr_lifecycle_policy" "create_investigation_lambda_source" {
  count      = var.enable_lambda_ecr_source ? 1 : 0
  repository = aws_ecr_repository.create_investigation_lambda_source[0].name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Retain the most recent 25 tagged Lambda images"
      selection = {
        tagStatus      = "tagged"
        tagPatternList = ["*"]
        countType      = "imageCountMoreThan"
        countNumber    = 25
      }
      action = { type = "expire" }
    }]
  })
}

# ECR replication is registry-wide, not repository-scoped. Keep its single owner
# in the account root; the filter limits this rule to the Lambda image path.
# Before enabling, review any other rules in this account: this resource
# manages the complete registry replication configuration, not just this rule.
resource "aws_ecr_replication_configuration" "create_investigation_lambda" {
  count = length(var.lambda_ecr_replication_regions) > 0 ? 1 : 0

  replication_configuration {
    rule {
      dynamic "destination" {
        for_each = var.lambda_ecr_replication_regions
        content {
          region      = destination.value
          registry_id = var.aws_account_id
        }
      }

      repository_filter {
        filter      = "${var.project}/create-investigation-lambda"
        filter_type = "PREFIX_MATCH"
      }
    }
  }

  lifecycle {
    precondition {
      condition     = var.enable_lambda_ecr_source
      error_message = "Enable the ordinary source repository before configuring Lambda image replication."
    }
  }

  depends_on = [aws_ecr_repository.create_investigation_lambda_source]
}

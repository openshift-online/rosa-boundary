# The staging publication source is an ordinary ECR repository, not the
# Quay pull-through-cache namespace. No Lambda function consumes it yet.
# This root runs in the source Region only; destination repositories and
# registry-wide replication are deliberately out of scope for the pilot.
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

# Retain enough tagged releases for rollback; never delete a populated
# repository as part of removing the pilot configuration.
resource "aws_ecr_lifecycle_policy" "create_investigation_lambda_source" {
  count      = var.enable_lambda_ecr_source ? 1 : 0
  repository = aws_ecr_repository.create_investigation_lambda_source[0].name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Retain the most recent 50 tagged Lambda images"
      selection = {
        tagStatus      = "tagged"
        tagPatternList = ["*"]
        countType      = "imageCountMoreThan"
        countNumber    = 50
      }
      action = { type = "expire" }
    }]
  })
}

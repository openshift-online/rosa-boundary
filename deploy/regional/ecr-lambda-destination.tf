# Source-region repository is owned by deploy/account, not by this regional
# state. This opt-in creates a matching ordinary repository only in destinations.
# Lambda continues using the Quay pull-through cache until a separate cutover.
resource "aws_ecr_repository" "create_investigation_lambda_destination" {
  count = var.lambda_ecr_destination_source_region != "" ? 1 : 0

  name                 = "${var.project}/create-investigation-lambda"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  lifecycle {
    precondition {
      condition     = var.aws_region != var.lambda_ecr_destination_source_region
      error_message = "The account root owns the Lambda ECR source repository; only create this repository in destination Regions."
    }
  }

  tags = local.common_tags
}

resource "aws_ecr_lifecycle_policy" "create_investigation_lambda_destination" {
  count      = var.lambda_ecr_destination_source_region != "" ? 1 : 0
  repository = aws_ecr_repository.create_investigation_lambda_destination[0].name

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

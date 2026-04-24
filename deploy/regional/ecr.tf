# ECR repositories for Lambda container images

resource "aws_ecr_repository" "create_investigation_lambda" {
  name                 = "${var.project}-${var.stage}-create-investigation"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.common_tags
}

resource "aws_ecr_lifecycle_policy" "create_investigation_lambda" {
  repository = aws_ecr_repository.create_investigation_lambda.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = { type = "expire" }
      }
    ]
  })
}

resource "aws_ecr_repository" "reap_tasks_lambda" {
  name                 = "${var.project}-${var.stage}-reap-tasks"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.common_tags
}

resource "aws_ecr_lifecycle_policy" "reap_tasks_lambda" {
  repository = aws_ecr_repository.reap_tasks_lambda.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = { type = "expire" }
      }
    ]
  })
}

output "ecr_create_investigation_url" {
  description = "ECR repository URL for the create-investigation Lambda image"
  value       = aws_ecr_repository.create_investigation_lambda.repository_url
}

output "ecr_reap_tasks_url" {
  description = "ECR repository URL for the reap-tasks Lambda image"
  value       = aws_ecr_repository.reap_tasks_lambda.repository_url
}

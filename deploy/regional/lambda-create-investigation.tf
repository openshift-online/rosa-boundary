# Lambda function for creating investigations (per-user IAM roles and ECS tasks)

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "create_investigation_lambda" {
  name              = "/aws/lambda/${var.project}-${var.stage}-create-investigation"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

# IAM role for Lambda execution
resource "aws_iam_role" "create_investigation_lambda" {
  name = "${var.project}-${var.stage}-create-investigation-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

# Lambda basic execution permissions (CloudWatch Logs)
resource "aws_iam_role_policy_attachment" "create_investigation_lambda_basic" {
  role       = aws_iam_role.create_investigation_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda permissions for ECS task operations
resource "aws_iam_role_policy" "create_investigation_lambda_ecs" {
  name = "ecs-task-management"
  role = aws_iam_role.create_investigation_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecs:RunTask",
          "ecs:DescribeTaskDefinition",
          "ecs:RegisterTaskDefinition",
          "ecs:DeregisterTaskDefinition",
          "ecs:TagResource"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = [
          aws_iam_role.task.arn,
          aws_iam_role.execution.arn,
        ]
      }
    ]
  })
}

# Lambda permissions for EFS access point management
resource "aws_iam_role_policy" "create_investigation_lambda_efs" {
  name = "efs-access-point-management"
  role = aws_iam_role.create_investigation_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "elasticfilesystem:CreateAccessPoint",
          "elasticfilesystem:DescribeAccessPoints",
          "elasticfilesystem:TagResource"
        ]
        Resource = aws_efs_file_system.sre_home.arn
      }
    ]
  })
}

# Archive the Lambda function code
data "archive_file" "create_investigation_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../lambda/create-investigation"
  output_path = "${path.module}/.terraform/lambda/create-investigation.zip"

  excludes = [
    "test_handler.py",
    "conftest.py",
    "pytest.ini",
    "test-security-fixes.sh",
    "pyproject.toml",
    "uv.lock",
    "README.md",
    "Makefile",
    "__pycache__",
    ".pytest_cache",
    "htmlcov",
    ".coverage",
    "bin",
    ".venv"
  ]
}

# Lambda function
resource "aws_lambda_function" "create_investigation" {
  filename         = data.archive_file.create_investigation_lambda.output_path
  function_name    = "${var.project}-${var.stage}-create-investigation"
  role             = aws_iam_role.create_investigation_lambda.arn
  handler          = "handler.lambda_handler"
  source_code_hash = data.archive_file.create_investigation_lambda.output_base64sha256
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      KEYCLOAK_URL         = regex("^(https://[^/]+)", var.keycloak_issuer_url)[0]
      KEYCLOAK_REALM       = regex("/realms/(.+)$", var.keycloak_issuer_url)[0]
      KEYCLOAK_CLIENT_ID   = var.oidc_client_id
      OIDC_PROVIDER_ARN    = aws_iam_openid_connect_provider.keycloak.arn
      ECS_CLUSTER          = aws_ecs_cluster.main.name
      TASK_DEFINITION      = aws_ecs_task_definition.rosa_boundary.family
      TASK_ROLE_ARN        = aws_iam_role.task.arn
      EXECUTION_ROLE_ARN   = aws_iam_role.execution.arn
      SUBNETS              = join(",", var.subnet_ids)
      SECURITY_GROUP       = aws_security_group.fargate.id
      EFS_FILESYSTEM_ID    = aws_efs_file_system.sre_home.id
      SHARED_ROLE_ARN      = aws_iam_role.sre_shared.arn
      S3_AUDIT_BUCKET      = aws_s3_bucket.audit.id
      AWS_ACCOUNT_ID       = data.aws_caller_identity.current.account_id
      PROJECT_NAME         = var.project
      REQUIRED_GROUP       = "sre-team"
      TASK_TIMEOUT_DEFAULT = tostring(var.task_timeout_default)
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.create_investigation_lambda,
    aws_iam_role_policy_attachment.create_investigation_lambda_basic
  ]

  tags = local.common_tags
}

# Lambda Function URL (simpler than API Gateway)
resource "aws_lambda_function_url" "create_investigation" {
  function_name      = aws_lambda_function.create_investigation.function_name
  authorization_type = "AWS_IAM" # SigV4 enforced; OIDC token validated inside the function

  cors {
    allow_credentials = false
    allow_origins     = ["*"] # Allow localhost for testing; restrict in production
    allow_methods     = ["POST"]
    allow_headers     = ["content-type", "x-oidc-token"] # SigV4 handles Authorization; OIDC token in custom header
    max_age           = 86400
  }

  # Ensure permission exists before creating Function URL
  depends_on = [aws_lambda_permission.create_investigation_url]
}

# Allow lambda-invoker role to call the Function URL via SigV4
resource "aws_lambda_permission" "create_investigation_url" {
  statement_id           = "AllowFunctionURLInvoke"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.create_investigation.function_name
  principal              = aws_iam_role.lambda_invoker.arn
  function_url_auth_type = "AWS_IAM"
}

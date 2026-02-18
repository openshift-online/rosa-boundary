# Lambda function for periodic reaping of expired ECS tasks

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "reap_tasks_lambda" {
  name              = "/aws/lambda/${var.project}-${var.stage}-reap-tasks"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

# IAM role for Lambda execution
resource "aws_iam_role" "reap_tasks_lambda" {
  name = "${var.project}-${var.stage}-reap-tasks-lambda"

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
resource "aws_iam_role_policy_attachment" "reap_tasks_lambda_basic" {
  role       = aws_iam_role.reap_tasks_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda permissions for ECS operations
resource "aws_iam_role_policy" "reap_tasks_lambda_ecs" {
  name = "ecs-task-reaping"
  role = aws_iam_role.reap_tasks_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecs:ListTasks"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ecs:cluster" = aws_ecs_cluster.main.arn
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "ecs:DescribeTasks"
        ]
        Resource = "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.main.name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecs:StopTask"
        ]
        Resource = "arn:aws:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:task/${aws_ecs_cluster.main.name}/*"
        Condition = {
          "ForAnyValue:StringLike" = {
            "ecs:ResourceTag/deadline" = "*"
          }
        }
      }
    ]
  })
}

# Archive the Lambda function code (single file, no dependencies)
data "archive_file" "reap_tasks_lambda" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/reap-tasks/handler.py"
  output_path = "${path.module}/.terraform/lambda/reap-tasks.zip"
}

# Lambda function
resource "aws_lambda_function" "reap_tasks" {
  filename         = data.archive_file.reap_tasks_lambda.output_path
  function_name    = "${var.project}-${var.stage}-reap-tasks"
  role             = aws_iam_role.reap_tasks_lambda.arn
  handler          = "handler.lambda_handler"
  source_code_hash = data.archive_file.reap_tasks_lambda.output_base64sha256
  runtime          = "python3.11"
  timeout          = 120 # 2 minutes (enough to process large task lists)
  memory_size      = 128 # Minimal memory needed

  environment {
    variables = {
      ECS_CLUSTER = aws_ecs_cluster.main.name
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.reap_tasks_lambda,
    aws_iam_role_policy_attachment.reap_tasks_lambda_basic
  ]

  tags = local.common_tags
}

# EventBridge Rule for periodic invocation
resource "aws_cloudwatch_event_rule" "reap_tasks_schedule" {
  name                = "${var.project}-${var.stage}-reap-tasks"
  description         = "Trigger task reaper Lambda every ${var.reaper_schedule_minutes} minutes"
  schedule_expression = "rate(${var.reaper_schedule_minutes} minutes)"

  tags = local.common_tags
}

# EventBridge Target
resource "aws_cloudwatch_event_target" "reap_tasks_lambda" {
  rule      = aws_cloudwatch_event_rule.reap_tasks_schedule.name
  target_id = "ReapTasksLambda"
  arn       = aws_lambda_function.reap_tasks.arn
}

# Lambda permission for EventBridge invocation
resource "aws_lambda_permission" "reap_tasks_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.reap_tasks.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.reap_tasks_schedule.arn
}

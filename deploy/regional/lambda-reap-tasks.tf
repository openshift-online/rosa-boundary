# Lambda function for periodic reaping of expired ECS tasks

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "reap_tasks_lambda" {
  name              = "/aws/lambda/${var.project}-${var.stage}-reap-tasks"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
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
  role             = data.aws_iam_role.reap_tasks_lambda.arn
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
    aws_iam_role_policy.reap_tasks_lambda_ecs,
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

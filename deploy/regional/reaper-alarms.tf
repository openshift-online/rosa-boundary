resource "aws_cloudwatch_metric_alarm" "reaper_errors" {
  for_each = {
    tasks          = aws_lambda_function.reap_tasks.function_name
    investigations = aws_lambda_function.reap_investigations.function_name
  }

  alarm_name          = "${each.value}-errors"
  alarm_description   = "One or more failed invocations of ${each.value}."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = each.value }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  actions_enabled     = var.reaper_alarm_sns_topic_arn != ""
  alarm_actions       = var.reaper_alarm_sns_topic_arn == "" ? [] : [var.reaper_alarm_sns_topic_arn]

  tags = local.common_tags
}

# Public Terraform Registry (hashicorp/aws): aws_budgets_budget (account singleton).
# Cost visibility only: these notifications do not limit or stop inference.
# The service filter covers all Bedrock charges in this AWS account, including
# callers outside ROSA Boundary.
resource "aws_budgets_budget" "bedrock" {
  name         = "${var.project}-${var.stage}-bedrock-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.bedrock_monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "Service"
    values = ["Amazon Bedrock"]
  }

  dynamic "notification" {
    for_each = [50, 80, 100]

    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.bedrock_budget_notification_email]
    }
  }

  tags = local.common_tags
}

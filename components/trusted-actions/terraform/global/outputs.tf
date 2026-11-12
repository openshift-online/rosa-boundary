output "secretsmanager_secret_arn" {
  description = "Secrets Manager secret ARN — pass to regional workspaces as var.secretsmanager_secret_arn."
  value       = aws_secretsmanager_secret.app.arn
}

output "iam_role_task_arn" {
  description = "ECS task role ARN — pass to regional workspaces as var.iam_role_task_arn."
  value       = aws_iam_role.task.arn
}

output "iam_role_task_execution_arn" {
  description = "ECS task execution role ARN — pass to regional workspaces as var.iam_role_task_execution_arn."
  value       = aws_iam_role.task_execution.arn
}

output "iam_instance_profile_name" {
  description = "EC2 instance profile name — pass to regional workspaces as var.iam_instance_profile_name."
  value       = aws_iam_instance_profile.ecs_instance.name
}

output "iam_role_cwl_to_firehose_arn" {
  description = "CloudWatch Logs → Firehose role ARN — pass to regional workspaces as var.iam_role_cwl_to_firehose_arn."
  value       = aws_iam_role.cwl_to_firehose.arn
}

output "iam_role_firehose_audit_logs_arn" {
  description = "Firehose → S3 role ARN — pass to regional workspaces as var.iam_role_firehose_audit_logs_arn."
  value       = aws_iam_role.firehose_audit_logs.arn
}

output "internal_fqdn" {
  description = "FQDN used by the global ACM validation anchor."
  value       = var.internal_fqdn
}

output "public_zone_name_servers" {
  description = "Name servers for the public hosted zone created from var.public_zone. Delegate the parent domain to these. Empty when an existing zone is passed via public_zone_id instead."
  value       = var.public_zone != "" ? aws_route53_zone.main[0].name_servers : []
}

output "public_zone_id" {
  description = "Route 53 public hosted zone ID backing the validation-anchor CNAME — created from var.public_zone or passed in as var.public_zone_id. Regional workspaces read this via terraform_remote_state instead of declaring their own public_zone_id variable."
  value       = local.public_zone_id
}

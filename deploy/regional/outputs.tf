output "bucket_name" {
  description = "Name of the S3 audit bucket"
  value       = aws_s3_bucket.audit.id
}

output "bucket_arn" {
  description = "ARN of the S3 audit bucket"
  value       = aws_s3_bucket.audit.arn
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.main.name
}

output "ecs_cluster_arn" {
  description = "ARN of the ECS cluster"
  value       = aws_ecs_cluster.main.arn
}

output "task_definition_arn" {
  description = "ARN of the ECS task definition"
  value       = aws_ecs_task_definition.rosa_boundary.arn
}

output "task_definition_family" {
  description = "Family name of the ECS task definition"
  value       = aws_ecs_task_definition.rosa_boundary.family
}

output "task_role_arn" {
  description = "ARN of the ECS task IAM role"
  value       = aws_iam_role.task.arn
}

output "execution_role_arn" {
  description = "ARN of the ECS task execution IAM role"
  value       = aws_iam_role.execution.arn
}

output "efs_filesystem_id" {
  description = "ID of the EFS filesystem"
  value       = aws_efs_file_system.sre_home.id
}

output "efs_access_point_id" {
  description = "ID of the EFS access point for /home/sre"
  value       = aws_efs_access_point.sre.id
}

output "security_group_id" {
  description = "Security group ID for Fargate tasks"
  value       = aws_security_group.fargate.id
}

output "efs_security_group_id" {
  description = "Security group ID for EFS mount targets"
  value       = aws_security_group.efs.id
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group name for container logs"
  value       = aws_cloudwatch_log_group.rosa_boundary.name
}

output "subnet_ids" {
  description = "Subnet IDs for Fargate tasks"
  value       = var.subnet_ids
}

output "kms_key_id" {
  description = "KMS key ID for ECS Exec encryption"
  value       = aws_kms_key.exec_session.id
}

output "kms_key_arn" {
  description = "KMS key ARN for ECS Exec encryption"
  value       = aws_kms_key.exec_session.arn
}

output "ssm_session_log_group" {
  description = "CloudWatch log group for SSM session logs"
  value       = aws_cloudwatch_log_group.ssm_sessions.name
}

output "oidc_provider_arn" {
  description = "ARN of the Keycloak OIDC provider"
  value       = aws_iam_openid_connect_provider.keycloak.arn
}

output "sre_shared_role_arn" {
  description = "ARN of the shared SRE IAM role (ABAC, assumed via OIDC session tags)"
  value       = aws_iam_role.sre_shared.arn
}

output "lambda_function_url" {
  description = "URL for the create-investigation Lambda function"
  value       = aws_lambda_function_url.create_investigation.function_url
}

output "lambda_function_name" {
  description = "Name of the create-investigation Lambda function"
  value       = aws_lambda_function.create_investigation.function_name
}

output "lambda_function_arn" {
  description = "ARN of the create-investigation Lambda function"
  value       = aws_lambda_function.create_investigation.arn
}

output "lambda_role_arn" {
  description = "ARN of the create-investigation Lambda execution role"
  value       = aws_iam_role.create_investigation_lambda.arn
}

output "reaper_lambda_function_name" {
  description = "Name of the reap-tasks Lambda function"
  value       = aws_lambda_function.reap_tasks.function_name
}

output "reaper_lambda_function_arn" {
  description = "ARN of the reap-tasks Lambda function"
  value       = aws_lambda_function.reap_tasks.arn
}

output "audit_replication_role_arn" {
  description = "ARN of the S3 replication IAM role. The audit account destination bucket policy must grant this role s3:ReplicateObject, s3:ReplicateDelete, s3:ReplicateTags, and s3:ObjectOwnerOverrideToBucketOwner on the destination bucket."
  value       = var.audit_replication_bucket_arn != "" ? aws_iam_role.s3_replication[0].arn : null
}

output "lambda_invoker_role_arn" {
  description = "ARN of the IAM role SREs assume to invoke the Lambda function URL via SigV4"
  value       = aws_iam_role.lambda_invoker.arn
}

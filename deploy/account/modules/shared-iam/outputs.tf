output "roles" {
  value = {
    execution                  = { name = aws_iam_role.execution.name, arn = aws_iam_role.execution.arn }
    task                       = { name = aws_iam_role.task.name, arn = aws_iam_role.task.arn }
    sre_shared                 = { name = aws_iam_role.sre_shared.name, arn = aws_iam_role.sre_shared.arn }
    lambda_invoker             = { name = aws_iam_role.lambda_invoker.name, arn = aws_iam_role.lambda_invoker.arn }
    create_investigation       = { name = aws_iam_role.create_investigation_lambda.name, arn = aws_iam_role.create_investigation_lambda.arn }
    reap_tasks                 = { name = aws_iam_role.reap_tasks_lambda.name, arn = aws_iam_role.reap_tasks_lambda.arn }
    reap_investigations        = { name = aws_iam_role.reap_investigations_lambda.name, arn = aws_iam_role.reap_investigations_lambda.arn }
    bedrock_invocation_logging = { name = aws_iam_role.bedrock_invocation_logging.name, arn = aws_iam_role.bedrock_invocation_logging.arn }
    s3_replication             = var.enable_s3_replication_role ? { name = aws_iam_role.s3_replication[0].name, arn = aws_iam_role.s3_replication[0].arn } : null
  }
}

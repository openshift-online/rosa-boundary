# Transfer only identities/common attachments/account singletons under a freeze.
# Never release regional policies: their original addresses remain managed here.
removed {
  from = aws_iam_role.s3_replication
  lifecycle { destroy = false }
}
removed {
  from = aws_iam_role.execution
  lifecycle { destroy = false }
}
removed {
  from = aws_iam_role_policy_attachment.execution_managed
  lifecycle { destroy = false }
}
removed {
  from = aws_iam_role.task
  lifecycle { destroy = false }
}
removed {
  from = aws_iam_openid_connect_provider.keycloak
  lifecycle { destroy = false }
}
removed {
  from = aws_iam_openid_connect_provider.stage_keycloak
  lifecycle { destroy = false }
}
removed {
  from = aws_iam_openid_connect_provider.prod_keycloak
  lifecycle { destroy = false }
}
removed {
  from = aws_iam_role.sre_shared
  lifecycle { destroy = false }
}
removed {
  from = aws_iam_role.lambda_invoker
  lifecycle { destroy = false }
}
removed {
  from = aws_iam_role.create_investigation_lambda
  lifecycle { destroy = false }
}
removed {
  from = aws_iam_role_policy_attachment.create_investigation_lambda_basic
  lifecycle { destroy = false }
}
removed {
  from = aws_iam_role.reap_tasks_lambda
  lifecycle { destroy = false }
}
removed {
  from = aws_iam_role_policy_attachment.reap_tasks_lambda_basic
  lifecycle { destroy = false }
}
removed {
  from = aws_iam_role.bedrock_invocation_logging
  lifecycle { destroy = false }
}
removed {
  from = aws_budgets_budget.bedrock
  lifecycle { destroy = false }
}
removed {
  from = aws_bedrock_foundation_model_agreement.approved
  lifecycle { destroy = false }
}

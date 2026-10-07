# Retain the legacy service trust by default. Additional regional service callers
# require explicitly approved source regions; never broaden to all regions/accounts.
locals {
  bedrock_logging_source_arns = [
    for region in var.bedrock_logging_source_regions :
    "arn:${data.aws_partition.current.partition}:bedrock:${region}:${data.aws_caller_identity.current.account_id}:*"
  ]
  # Encoding each branch avoids Terraform coercing the original scalar to a list.
  bedrock_logging_source_arn_json = length(local.bedrock_logging_source_arns) == 1 ? jsonencode(local.bedrock_logging_source_arns[0]) : jsonencode(local.bedrock_logging_source_arns)
}

resource "aws_iam_role" "bedrock_invocation_logging" {
  name = "${var.role_name_prefix}-bedrock-invocation-logging"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        # Keep the original scalar JSON for one region, IAM's OR-list for several.
        ArnLike = { "aws:SourceArn" = jsondecode(local.bedrock_logging_source_arn_json) }
      }
    }]
  })
  tags = local.common_tags
}

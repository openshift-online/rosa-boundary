# Shared execution identity and the common AWS-managed attachment, owned once.
resource "aws_iam_role" "create_investigation_lambda" {
  name = "${var.role_name_prefix}-create-investigation-lambda"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" } }]
  })
  tags = local.common_tags
}
resource "aws_iam_role_policy_attachment" "create_investigation_lambda_basic" {
  role       = aws_iam_role.create_investigation_lambda.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

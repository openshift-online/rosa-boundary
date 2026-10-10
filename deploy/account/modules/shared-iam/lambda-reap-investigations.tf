# Shared investigation reaper identity; regional ECS/EFS/S3 grants are deliberately managed separately.
resource "aws_iam_role" "reap_investigations_lambda" {
  name = "${var.role_name_prefix}-reap-investigations-lambda"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" } }]
  })
  tags = local.common_tags
}
resource "aws_iam_role_policy_attachment" "reap_investigations_lambda_basic" {
  role       = aws_iam_role.reap_investigations_lambda.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

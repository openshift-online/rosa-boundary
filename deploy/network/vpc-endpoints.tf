# S3 Gateway VPC Endpoint
# Provides S3 access without NAT Gateway data processing charges (Gateway endpoints are free)
# Other AWS services (EFS, ECS, CloudWatch Logs) use NAT Gateway for cost efficiency

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.private[*].id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-s3-endpoint"
  })
}

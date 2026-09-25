# VPC Endpoints for Lambda functions in VPC
# Required for reaper Lambda to access AWS services while in VPC for EFS mounting

# Security group for VPC endpoints
resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.project}-${var.stage}-vpc-endpoints-sg"
  description = "Security group for VPC endpoints"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.main.cidr_block]
  }

  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-vpc-endpoints-sg"
  })
}

# Get VPC CIDR block
data "aws_vpc" "main" {
  id = var.vpc_id
}

# EFS endpoint (for DescribeAccessPoints, DeleteAccessPoint)
resource "aws_vpc_endpoint" "efs" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.elasticfilesystem"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.subnet_ids
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-efs-endpoint"
  })
}

# ECS endpoint (for ListTasks, DescribeTaskDefinition, StopTask, DescribeTasks)
resource "aws_vpc_endpoint" "ecs" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ecs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.subnet_ids
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-ecs-endpoint"
  })
}

# S3 gateway endpoint (for reaper final backup uploads)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = data.aws_route_table.subnet[*].id

  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-s3-endpoint"
  })
}

# CloudWatch Logs endpoint (for Lambda logging)
resource "aws_vpc_endpoint" "logs" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.subnet_ids
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-logs-endpoint"
  })
}

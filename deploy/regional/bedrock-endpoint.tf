# Bedrock inference uses the regional runtime API. Private DNS directs its
# standard hostname to one interface ENI in each task subnet/AZ (defined by
# var.subnet_ids); other AWS APIs still use their existing NAT paths.
data "aws_subnet" "bedrock_runtime" {
  for_each = toset(var.subnet_ids)
  id       = each.value
}

resource "aws_security_group" "bedrock_runtime" {
  name        = "${var.project}-${var.stage}-bedrock-runtime-sg"
  description = "Bedrock Runtime interface endpoint for ROSA Boundary tasks"
  vpc_id      = var.vpc_id

  # No outbound rules: the provider removes AWS's default allow-all egress
  # on creation. Security groups are stateful, so TLS responses still work.
  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-bedrock-runtime-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "bedrock_runtime_from_tasks" {
  security_group_id            = aws_security_group.bedrock_runtime.id
  referenced_security_group_id = aws_security_group.fargate.id
  description                  = "HTTPS from ROSA Boundary Fargate tasks only"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_endpoint" "bedrock_runtime" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.subnet_ids
  security_group_ids  = [aws_security_group.bedrock_runtime.id]
  private_dns_enabled = true

  # Model-specific restrictions follow the approved model manifest; until then,
  # limit this endpoint to task-role inference on model/profile resources.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = data.aws_iam_role.task.arn }
      Action = [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ]
      Resource = [
        "arn:${data.aws_partition.current.partition}:bedrock:*:${data.aws_caller_identity.current.account_id}:inference-profile/*",
        "arn:${data.aws_partition.current.partition}:bedrock:*::foundation-model/*"
      ]
    }]
  })

  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-bedrock-runtime"
  })

  lifecycle {
    precondition {
      condition     = alltrue([for subnet in data.aws_subnet.bedrock_runtime : subnet.vpc_id == var.vpc_id])
      error_message = "All Bedrock Runtime endpoint subnets must belong to vpc_id."
    }
    precondition {
      condition     = length(distinct([for subnet in data.aws_subnet.bedrock_runtime : subnet.availability_zone_id])) == length(var.subnet_ids)
      error_message = "Bedrock Runtime endpoint requires exactly one task subnet per Availability Zone."
    }
  }

  depends_on = [aws_vpc_security_group_ingress_rule.bedrock_runtime_from_tasks]
}

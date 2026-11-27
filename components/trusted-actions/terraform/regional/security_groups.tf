resource "aws_security_group" "alb" {
  name        = "${var.app_name}-alb"
  description = "ALB: allow inbound HTTP/HTTPS from within the VPC only"
  vpc_id      = local.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.current.cidr_block]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.current.cidr_block]
  }
  tags = { Name = "${var.app_name}-alb-sg" }
}

# ALB egress to the tasks' 8080. A separate rule, not an egress block on
# aws_security_group.alb: that would create an alb↔ecs_task reference cycle,
# because ecs_task's ingress already references alb. Without any egress the
# ALB cannot reach its targets — health checks time out and ECS churns tasks
# (observed live: declaring the SG in Terraform removes the default
# allow-all egress).
resource "aws_security_group_rule" "alb_egress_tasks" {
  type                     = "egress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  security_group_id        = aws_security_group.alb.id
  source_security_group_id = aws_security_group.ecs_task.id
}

# Fargate task SG: inbound from ALB, outbound to Aurora and internet.
resource "aws_security_group" "ecs_task" {
  name        = "${var.app_name}-ecs-task"
  description = "Fargate task: inbound from ALB, outbound to Aurora and internet"
  vpc_id      = local.vpc_id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.app_name}-ecs-task-sg" }
}

resource "aws_security_group" "aurora" {
  name        = "${var.app_name}-aurora"
  description = "Aurora: inbound Postgres from Fargate tasks only"
  vpc_id      = local.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_task.id]
  }

  tags = { Name = "${var.app_name}-aurora-sg" }
}

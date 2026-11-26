# ── Regional IAM ───────────────────────────────────────────────────────────────
#
# The application task role is region-owned: its statement set includes an
# inline rds-db:connect policy scoped to THIS cluster's resource ID and the
# trusted_actions_app user, which no global role can express without a
# per-region policy. The global root keeps only the account-wide task
# execution role and its application-secret read.

# Task role assumed by ECS tasks in this region.
data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "task" {
  name               = "${var.app_name}-task-${var.aws_region}"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

# Runtime application grants, mirroring the global task_app policy. The
# per-region S3 bucket ARN is known exactly here, so no wildcard is needed.
resource "aws_iam_role_policy" "task_app" {
  name = "${var.app_name}-task-app"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [aws_s3_bucket.app.arn, "${aws_s3_bucket.app.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${aws_s3_bucket.app.arn}/trusted-actions/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
      },
      {
        # ECS Exec data channel — opened by the task role, not the execution role.
        Effect = "Allow"
        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
        ]
        Resource = "*"
      },
    ]
  })
}

# IAM database authentication: rds-db:connect scoped to this cluster's
# resource ID and the application user only. Structural cross-region
# isolation — another region's task role cannot mint tokens for this cluster,
# and this role cannot mint tokens for any other database user or cluster
# (including future ones in this account until granted here).
resource "aws_iam_role_policy" "task_db_connect" {
  name = "${var.app_name}-rds-db-connect"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["rds-db:connect"]
      Resource = ["arn:aws:rds-db:${var.aws_region}:${data.aws_caller_identity.current.account_id}:dbuser:${local.db_cluster_resource_id}/trusted_actions_app"]
    }]
  })
}

# ── Bootstrap execution role ──────────────────────────────────────────────────
#
# The sole reader of this cluster's exact master-secret ARN. It pulls the
# image and the master secret when the bootstrap task runs; it grants nothing
# else. The master password exists only in that task's runtime environment.

resource "aws_iam_role" "bootstrap_execution" {
  name               = "${var.app_name}-bootstrap-execution-${var.aws_region}"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "bootstrap_execution_core" {
  role       = aws_iam_role.bootstrap_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "bootstrap_execution_read_master_secret" {
  name = "${var.app_name}-bootstrap-read-master-secret"
  role = aws_iam_role.bootstrap_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [local.db_master_secret_arn]
    }]
  })
}

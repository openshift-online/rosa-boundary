# ── Database bootstrap ────────────────────────────────────────────────────────
#
# Runs the image's `bootstrap` subcommand as an ECS task: it fetches the
# RDS-managed master secret (via the bootstrap execution role), builds the
# master DSN in a shell, and applies the idempotent bootstrap SQL that creates
# the trusted_actions_app role, grants it rds_iam and CREATEDB, and transfers
# database/schema ownership to it.
#
# The master password exists only inside this task's runtime environment: the
# secret value is injected by ECS as an env var (never Terraform state), the
# DSN is built in-container, and the subcommand never logs it. No other task
# definition or role can read the master secret.
#
# Gated off by default (db_bootstrap_enabled, default false). Re-triggers on
# the cluster resource ID, the username, the database name, and the image —
# re-enabling on a database that was already bootstrapped is a no-op by design
# (the SQL is idempotent), which is what makes re-applies safe.
#
# Prerequisite: the deployed image must contain the `bootstrap` subcommand
# (merged with ticket 01's image build).

resource "aws_ecs_task_definition" "db_bootstrap" {
  family                   = "${var.app_name}-db-bootstrap"
  task_role_arn            = aws_iam_role.task.arn
  execution_role_arn       = aws_iam_role.bootstrap_execution.arn
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory

  container_definitions = jsonencode([
    {
      name      = "bootstrap"
      image     = var.container_image
      essential = true

      # The bootstrap subcommand reads ROSA_TA_DB_MASTER_DSN. The DSN is
      # assembled here from the cluster endpoint and the injected master
      # credentials; every part is connection metadata except the password
      # env var, which ECS resolves from the master secret at task start and
      # which never appears in Terraform state, plans, or logs. Keyword/value
      # form, not a URL: the RDS-generated password may contain characters
      # that are special in a URL, and the single-quoted value keeps the
      # shell from touching anything.
      command = ["/bin/sh", "-c", join(" && ", [
        "export ROSA_TA_DB_MASTER_DSN='host=${aws_rds_cluster.main.endpoint} port=${aws_rds_cluster.main.port} dbname=${var.db_name} user=${var.db_username} password=$$ROSA_TA_DB_MASTER_PASSWORD sslmode=verify-full sslrootcert=/etc/ssl/certs/rds-global-bundle.pem'",
        "exec /usr/local/bin/rosa-trusted-actions-server bootstrap",
      ])]

      environment = [
        { name = "AWS_REGION", value = var.aws_region },
        { name = "ROSA_TA_DB_SSLMODE", value = "verify-full" },
      ]

      secrets = [
        {
          name      = "ROSA_TA_DB_MASTER_PASSWORD"
          valueFrom = local.db_master_secret_arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs-db-bootstrap"
        }
      }
    },
  ])
}

# Runs the bootstrap task once whenever the trigger inputs change. The local
# triggers deliberately do NOT include the master-secret ARN or password:
# rotation (RDS-managed, every 7 days) must not re-run the bootstrap — the
# subcommand is idempotent but a re-run would still needlessly consume a
# master connection and surface rotation events in the task logs.
resource "null_resource" "db_bootstrap" {
  count = var.db_bootstrap_enabled ? 1 : 0

  triggers = {
    cluster_resource_id = local.db_cluster_resource_id
    master_username     = var.db_username
    db_name             = var.db_name
    bootstrap_image     = var.container_image
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -euo pipefail
      CLUSTER='${aws_ecs_cluster.main.name}'
      TASK_DEF='${aws_ecs_task_definition.db_bootstrap.arn}'
      SUBNET_A='${local.private_subnet_a}'
      SUBNET_B='${local.private_subnet_b}'
      SG='${aws_security_group.ecs_task.id}'
      REGION='${var.aws_region}'

      TASK_ARN="$(aws ecs run-task \
        --cluster "$CLUSTER" \
        --task-definition "$TASK_DEF" \
        --launch-type FARGATE \
        --region "$REGION" \
        --network-configuration "awsvpcConfiguration={subnets=[$SUBNET_A,$SUBNET_B],securityGroups=[$SG],assignPublicIp=DISABLED}" \
        --query 'tasks[0].taskArn' --output text)"

      # The subcommand applies idempotent SQL; tail it to completion so an
      # apply fails loudly when the bootstrap fails rather than leaving a
      # half-prepared database behind.
      aws ecs wait tasks-stopped \
        --cluster "$CLUSTER" \
        --tasks "$TASK_ARN" \
        --region "$REGION"

      EXIT_CODE="$(aws ecs describe-tasks \
        --cluster "$CLUSTER" \
        --tasks "$TASK_ARN" \
        --region "$REGION" \
        --query 'tasks[0].containers[0].exitCode' --output text)"
      if [ "$EXIT_CODE" != "0" ]; then
        echo "database bootstrap task $TASK_ARN failed with exit code $EXIT_CODE" >&2
        exit 1
      fi
    EOT
  }

  depends_on = [
    aws_rds_cluster_instance.main,
    aws_ecs_cluster.main,
    aws_iam_role_policy.task_db_connect,
    aws_iam_role_policy.bootstrap_execution_read_master_secret,
  ]
}

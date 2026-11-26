# ── Aurora PostgreSQL cluster ─────────────────────────────────────────────────
#
# IAM database authentication is the only runtime database auth: the service
# authenticates as trusted_actions_app with 15-minute RDS IAM tokens minted per
# connection (see internal/store/postgres_iam.go). The master user never serves
# the application — it exists for bootstrap and break-glass only.
#
# The master password is fully RDS-managed: manage_master_user_password makes
# RDS create and rotate the secret (default 7-day rotation) in Secrets Manager,
# cluster-scoped and deleted with the cluster. No master_password variable and
# no aws_secretsmanager_secret_rotation resource ever exists — the documented
# disable path (rotation_enabled = false) is a parking resource this project
# deliberately never creates. See docs/deployment.md for the
# rds:ModifyDBCluster caveat that comes with the RDS-managed rotation.

resource "aws_db_subnet_group" "main" {
  name       = var.app_name
  subnet_ids = [local.private_subnet_a, local.private_subnet_b]
  tags       = { Name = "${var.app_name}-db-subnet-group", Environment = var.environment }
}

resource "aws_rds_cluster" "main" {
  cluster_identifier = var.app_name
  engine             = "aurora-postgresql"
  engine_version     = var.db_engine_version # pinned; a floating minor means an unplanned upgrade
  database_name      = var.db_name
  master_username    = var.db_username

  # RDS owns the master password and its secret rotation. The ARN is read from
  # master_user_secret[0].secret_arn below — never a Terraform-authored value.
  manage_master_user_password = true

  iam_database_authentication_enabled = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.aurora.id]

  storage_encrypted         = true
  kms_key_id                = var.db_kms_key_id != "" ? var.db_kms_key_id : null
  backup_retention_period   = var.db_backup_retention_period
  preferred_backup_window   = var.db_preferred_backup_window
  deletion_protection       = var.db_deletion_protection
  skip_final_snapshot       = var.db_skip_final_snapshot
  final_snapshot_identifier = var.db_skip_final_snapshot ? null : "${var.app_name}-final"

  tags = { Name = "${var.app_name}-aurora", Environment = var.environment }
}

resource "aws_rds_cluster_instance" "main" {
  count              = var.db_instance_count
  identifier         = "${var.app_name}-${count.index}"
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = var.db_instance_class
  engine             = aws_rds_cluster.main.engine
  engine_version     = aws_rds_cluster.main.engine_version

  performance_insights_enabled = var.db_performance_insights_enabled

  tags = { Name = "${var.app_name}-aurora-${count.index}", Environment = var.environment }
}

locals {
  # The cluster resource ID (not the identifier and not the ARN) is the
  # rds-db:connect resource segment: arn:aws:rds-db:REGION:ACCOUNT:dbuser:<resource-id>/USER.
  # It is stable across cluster rename/replace-in-place and unique per cluster,
  # which is what structurally isolates each region's task role from every
  # other region's database.
  db_cluster_resource_id = aws_rds_cluster.main.cluster_resource_id

  # The RDS-managed master secret. Read only by the regional bootstrap
  # execution role (iam.tf); the application task role has no secret access.
  db_master_secret_arn = aws_rds_cluster.main.master_user_secret[0].secret_arn

  # The IAM-authenticated application user the service connects as. It is
  # created by the bootstrap SQL (cmd bootstrap / internal/store/bootstrap.go)
  # and is NOT the master user: var.db_username names the master, and the
  # task role's rds-db:connect grant covers this user only. Both must stay in
  # sync with appRoleName in internal/store/bootstrap.go.
  db_app_username = "trusted_actions_app"
}

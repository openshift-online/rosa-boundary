# EFS filesystem for persistent /home/sre storage
resource "aws_efs_file_system" "sre_home" {
  encrypted        = true
  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-sre-home"
  })
}

# Security group for EFS mount targets
resource "aws_security_group" "efs" {
  name        = "${var.project}-${var.stage}-efs-sg"
  description = "Security group for EFS mount targets"
  vpc_id      = var.vpc_id

  ingress {
    description     = "NFS from Fargate tasks"
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.fargate.id]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-efs-sg"
  })
}

# Mount targets in each subnet
resource "aws_efs_mount_target" "sre_home" {
  count = length(var.subnet_ids)

  file_system_id  = aws_efs_file_system.sre_home.id
  subnet_id       = var.subnet_ids[count.index]
  security_groups = [aws_security_group.efs.id]
}

# EFS access point for /home/sre with sre user ownership
resource "aws_efs_access_point" "sre" {
  file_system_id = aws_efs_file_system.sre_home.id

  posix_user {
    uid = 1000
    gid = 1000
  }

  root_directory {
    path = "/home/sre"

    creation_info {
      owner_uid   = 1000
      owner_gid   = 1000
      permissions = "0755"
    }
  }

  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-sre-access-point"
  })
}

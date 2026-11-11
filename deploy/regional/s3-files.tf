# One file system per published prefix: the file-system root exposes only that
# prefix, not sibling publishers or the bucket's bootstrap object.
resource "aws_s3files_file_system" "content" {
  for_each = var.content_prefixes

  bucket   = aws_s3_bucket.content.arn
  prefix   = each.value
  role_arn = aws_iam_role.content_files.arn

  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-content-${each.key}"
  })

  depends_on = [
    aws_iam_role_policy.content_files,
    aws_s3_bucket_versioning.content,
    aws_s3_bucket_notification.content,
  ]
}

locals {
  # The existing lookup uses toset(subnet_ids), deduplicating repeated IDs.
  # Group by AZ as well: S3 Files permits only one mount target per FS per AZ.
  content_subnets_by_az = {
    for id, subnet in data.aws_subnet.bedrock_runtime :
    subnet.availability_zone_id => id...
  }
  content_mount_targets = {
    for pair in setproduct(keys(var.content_prefixes), keys(local.content_subnets_by_az)) :
    "${pair[0]}/${pair[1]}" => {
      prefix_key = pair[0]
      subnet_id  = sort(local.content_subnets_by_az[pair[1]])[0]
    }
  }
}

resource "aws_security_group" "content_files" {
  name        = "${var.project}-${var.stage}-content-files-sg"
  description = "S3 Files NFS from ROSA Boundary tasks only"
  vpc_id      = var.vpc_id

  # No outbound rules needed for stateful responses.
  tags = merge(local.common_tags, {
    Name = "${var.project}-${var.stage}-content-files-sg"
  })
}

resource "aws_vpc_security_group_ingress_rule" "content_files_from_tasks" {
  security_group_id            = aws_security_group.content_files.id
  referenced_security_group_id = aws_security_group.fargate.id
  description                  = "NFS from ROSA Boundary Fargate tasks only"
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
}

resource "aws_s3files_mount_target" "content" {
  for_each = local.content_mount_targets

  file_system_id  = aws_s3files_file_system.content[each.value.prefix_key].id
  subnet_id       = each.value.subnet_id
  security_groups = [aws_security_group.content_files.id]

  depends_on = [
    aws_vpc_security_group_ingress_rule.content_files_from_tasks,
    aws_s3files_file_system_policy.content,
  ]
}

# Explicit denies prevent identity-policy grants from bypassing read-only,
# task-role-only access. These are IAM global condition keys, not EFS keys:
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
# ECS additionally enforces TLS and task-role authentication automatically:
# https://docs.aws.amazon.com/AmazonECS/latest/developerguide/s3files-volumes.html
resource "aws_s3files_file_system_policy" "content" {
  for_each = aws_s3files_file_system.content

  file_system_id = each.value.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyWriteAndRoot"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3files:ClientWrite", "s3files:ClientRootAccess"]
        Resource  = each.value.arn
      },
      {
        Sid       = "AllowTaskMount"
        Effect    = "Allow"
        Principal = { AWS = data.aws_iam_role.task.arn }
        Action    = "s3files:ClientMount"
        Resource  = each.value.arn
      },
      {
        Sid       = "DenyOtherPrincipals"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3files:ClientMount"
        Resource  = each.value.arn
        Condition = {
          ArnNotEquals = { "aws:PrincipalArn" = data.aws_iam_role.task.arn }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3files:ClientMount", "s3files:ClientWrite", "s3files:ClientRootAccess"]
        Resource  = each.value.arn
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

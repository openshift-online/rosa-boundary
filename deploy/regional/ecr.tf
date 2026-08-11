# ECR pull-through cache rule for Lambda container images from quay.io.
#
# Only created when lambda_package_type is "Image". This rule establishes
# the mapping between the project-scoped ECR prefix and quay.io, but it
# does NOT automatically pull images on demand. Lambda's internal image
# pull does not trigger the cache — the ECR repository must be created
# and the image copied in explicitly (via skopeo) before terraform apply
# creates the Lambda function. See docs/runbooks/lambda-zip-to-image-migration.md
# Step 5 for the seeding procedure.
#
# The cache prefix is project-scoped ("rosa-boundary-quay") to avoid
# conflicts with other projects sharing the same AWS account. Cached
# images are accessible at:
#   <account>.dkr.ecr.<region>.amazonaws.com/rosa-boundary-quay/<quay-path>:<tag>

resource "aws_ecr_pull_through_cache_rule" "quay" {
  count = local.lambda_use_image ? 1 : 0

  ecr_repository_prefix = "${var.project}-quay"
  upstream_registry_url = "quay.io"

  # No credential_arn needed — the quay.io repository is public.
}

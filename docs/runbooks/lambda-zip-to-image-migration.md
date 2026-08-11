# Lambda ZIP to Container Image Migration

## Overview

This runbook describes how to migrate the `create-investigation` Lambda from ZIP packaging
(`package_type = "Zip"`) to container image packaging (`package_type = "Image"`). Container
image packaging is required for HCP Terraform remote execution, where no build tools (Podman,
pip, Make) are available on the runner.

## Background

AWS Lambda does not support changing `package_type` on an existing function. The
`UpdateFunctionConfiguration` API does not accept `PackageType` — it is a create-time-only
attribute. The Terraform AWS provider reflects this with `ForceNew: true` on the `package_type`
attribute, meaning Terraform will **destroy and recreate** the Lambda function when toggling
between Zip and Image.

The Terraform configuration uses two mutually exclusive `aws_lambda_function` resources
(`create_investigation_zip` and `create_investigation_image`) controlled by the
`lambda_package_type` variable. This design enables a state-move migration strategy that avoids
the destroy+create cycle.

## Prerequisites

Before migrating, ensure:

1. **Container image exists on quay.io** — the Lambda container image must be published to
   a public quay.io repository. Verify:
   ```bash
   skopeo inspect docker://quay.io/<repository>:<tag>
   ```

2. **AWS CLI and skopeo available locally** — the ECR pull-through cache must be seeded from
   an engineer's workstation (see Step 5). HCP Terraform runners do not have container tools
   (`skopeo`, `podman`, `docker`), so this step cannot run inside a Terraform plan/apply.

3. **No active investigations** — while the migration is designed for zero downtime, it is
   safest to perform during a quiet period. Active ECS tasks are unaffected, but any Lambda
   invocations during the brief state-move window could fail if Terraform is mid-apply.

## Migration Steps

### Step 1: Verify Current State

Confirm the current Lambda is deployed via ZIP and identify its Terraform state address:

```bash
cd deploy/regional

# Show current Lambda resource in state
terraform state list | grep 'aws_lambda_function.create_investigation'
```

You should see:
```
aws_lambda_function.create_investigation
```

Or, if the dual-resource configuration is already deployed but still in ZIP mode:
```
aws_lambda_function.create_investigation_zip[0]
```

### Step 2: Move Terraform State

Move the existing Lambda resource to the new ZIP-mode address. This is a no-op rename in state
— no infrastructure changes occur.

**If migrating from the original single-resource layout** (pre-dual-mode):
```bash
terraform state mv \
  'aws_lambda_function.create_investigation' \
  'aws_lambda_function.create_investigation_zip[0]'
```

Also move the archive_file data source if it exists without an index:
```bash
terraform state mv \
  'data.archive_file.create_investigation_lambda' \
  'data.archive_file.create_investigation_lambda[0]'
```

**If already on the dual-resource layout in ZIP mode**, skip this step — state is already
correct.

### Step 3: Verify State Move

Run a plan to confirm no changes are pending after the state move:

```bash
terraform plan
```

Expected output should show **no changes** (or only unrelated changes). If Terraform wants to
destroy/create the Lambda, the state move was not applied correctly — re-check Step 2.

### Step 4: Update Variables

Set the following variables in your tfvars file or HCP Terraform workspace:

```hcl
lambda_package_type     = "Image"
lambda_image_repository = "redhat-user-workloads/rosa-tenant/rosa-boundary/lambda-create-investigation"
lambda_image_tag        = "v1.0.0"  # Use an immutable tag (git SHA, release version); avoid "latest"
```

### Step 5: Seed the ECR Pull-Through Cache

> **Why this step is needed**: Terraform creates an ECR pull-through cache rule that tells ECR
> where to find the upstream quay.io image. However, AWS Lambda's internal image pull does
> **not** trigger the pull-through cache to fetch from upstream. The image must be copied into
> the ECR repository under the cache prefix before `terraform apply` creates the Lambda
> function. This step must be run from an engineer's workstation — HCP Terraform runners do
> not have `skopeo` or other container tools.

First, create the pull-through cache rule by applying only the ECR resource:

```bash
terraform apply -target='aws_ecr_pull_through_cache_rule.quay[0]'
```

Then determine the ECR image URI that Terraform will use. It follows the pattern:
`<account>.dkr.ecr.<region>.amazonaws.com/<project>-quay/<lambda_image_repository>:<lambda_image_tag>`

For example, with account `123456789012`, region `us-east-1`, project `rosa-boundary`,
repository `redhat-user-workloads/rosa-tenant/rosa-boundary/lambda-create-investigation`, and
tag `latest`:

```
123456789012.dkr.ecr.us-east-1.amazonaws.com/rosa-boundary-quay/redhat-user-workloads/rosa-tenant/rosa-boundary/lambda-create-investigation:latest
```

Create the ECR repository and copy the image from quay.io:

```bash
# Set variables for your environment
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
REPOSITORY="rosa-boundary-quay/<lambda_image_repository value>"
TAG="<lambda_image_tag value>"
ECR_URI="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

# Create the ECR repository (the pull-through cache does not auto-create it reliably)
aws ecr create-repository \
  --repository-name "${REPOSITORY}" \
  --region "${REGION}"

# Copy the image from quay.io to ECR
skopeo copy \
  "docker://quay.io/<lambda_image_repository>:${TAG}" \
  "docker://${ECR_URI}/${REPOSITORY}:${TAG}" \
  --dest-creds "AWS:$(aws ecr get-login-password --region "${REGION}")"
```

Verify the image is in ECR:

```bash
aws ecr describe-images \
  --repository-name "${REPOSITORY}" \
  --image-ids imageTag="${TAG}" \
  --region "${REGION}"
```

> **For subsequent image tag updates** (e.g., deploying a new version): repeat only the
> `skopeo copy` and `aws ecr describe-images` commands with the new tag before running
> `terraform apply`. The repository and pull-through cache rule already exist.

### Step 6: Plan the Migration

```bash
terraform plan
```

Expected plan output:
- **Destroy**: `aws_lambda_function.create_investigation_zip[0]` (the ZIP Lambda)
- **Destroy**: `data.archive_file.create_investigation_lambda[0]` (the ZIP archive)
- **Create**: `aws_lambda_function.create_investigation_image[0]` (the Image Lambda)
- **Create**: `aws_ecr_pull_through_cache_rule.quay[0]` (ECR pull-through cache — if not
  already created in Step 5)
- **Update**: `aws_lambda_function_url.create_investigation` (function name reference)
- **Update**: `aws_lambda_permission.create_investigation_url` (function name reference)

Since both resources use the same `function_name`, AWS will delete the old function and create
the new one. There is a **brief window** (typically seconds) where the function does not exist.

### Step 7: Apply

```bash
terraform apply
```

### Step 8: Validate

Verify the new Lambda is functional:

```bash
# Check function exists and uses Image packaging
aws lambda get-function \
  --function-name "$(terraform output -raw lambda_function_name)" \
  --query 'Configuration.{PackageType:PackageType,CodeSize:CodeSize,LastModified:LastModified}' \
  --region <region>

# Test get_config action
rosa-boundary start-task --cluster-id test --dry-run

# Or invoke directly
aws lambda invoke \
  --function-name "$(terraform output -raw lambda_function_name)" \
  --payload '{"requestContext":{"http":{"method":"POST","path":"/"}},"headers":{"content-type":"application/json"},"body":"{\"action\":\"get_config\"}"}' \
  --cli-binary-format raw-in-base64-out \
  /dev/stdout
```

## Zero-Downtime Alternative (Blue-Green)

For production environments where even seconds of downtime are unacceptable, use a blue-green
approach:

### Step 1: Deploy Image Lambda Under a Temporary Name

Temporarily modify the `function_name` in the Image resource to include a `-v2` suffix, deploy
it alongside the existing ZIP Lambda, and validate independently.

This requires a temporary code change and is not covered by the standard Terraform variables.
Only use this approach if the brief downtime in the standard migration is unacceptable.

### Step 2: Swap Function URLs

After validating the `-v2` function:

1. Update the Function URL to point to the new function
2. Remove the old ZIP Lambda
3. Rename the new function back (requires another destroy+create cycle)

### Step 3: Cleanup

Remove the temporary name suffix and apply to finalize.

> **Note**: This approach doubles the Lambda cost during the overlap period and requires manual
> Terraform state manipulation. The standard migration (Steps 1-8) is recommended for most
> deployments since the downtime window is typically under 10 seconds.

## Rollback

To revert to ZIP packaging:

1. Update variables:
   ```hcl
   lambda_package_type = "Zip"
   # lambda_image_repository and lambda_image_tag can remain set — they are ignored in Zip mode
   ```

2. Run `terraform apply` — this will destroy the Image Lambda and create a ZIP Lambda.

3. The same brief downtime window applies during rollback.

## Troubleshooting

### `lambda_image_repository is required when lambda_package_type is 'Image'`

You set `lambda_package_type = "Image"` without providing `lambda_image_repository`. Set the
quay.io repository path in your tfvars or workspace variables.

### Terraform wants to destroy and recreate the Lambda unexpectedly

The Terraform state still references the old single-resource address
(`aws_lambda_function.create_investigation`). Run the state move from Step 2 first.

### Lambda returns "Runtime.InvalidEntrypoint"

The container image is missing the Lambda runtime interface client or the entrypoint is
misconfigured. Verify the Containerfile uses the official Lambda base image
(`public.ecr.aws/lambda/python:3.11`) and the handler is installed at
`${LAMBDA_TASK_ROOT}/handler.py`.

### Cold start is slow after migration

Container image Lambdas have slightly longer cold starts than ZIP Lambdas due to image pull
time. For the `create-investigation` function this is typically under 3 seconds. If cold starts
exceed 10 seconds, check the image size (`aws lambda get-function --query Configuration.CodeSize`)
and consider enabling provisioned concurrency.

### `Source image ... does not exist` during `terraform apply`

Lambda cannot pull images through the ECR pull-through cache on demand. The image must be
seeded into ECR before the Lambda function is created. If you see this error, the ECR cache
was not warmed before apply.

Fix — run Step 5 (Seed the ECR Pull-Through Cache) from your workstation:

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
REPOSITORY="rosa-boundary-quay/<lambda_image_repository value>"
TAG="<lambda_image_tag value>"

# Create the repo if it doesn't exist
aws ecr create-repository \
  --repository-name "${REPOSITORY}" \
  --region "${REGION}" 2>/dev/null || true

# Copy the image from quay.io into ECR
skopeo copy \
  "docker://quay.io/<lambda_image_repository>:${TAG}" \
  "docker://${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${REPOSITORY}:${TAG}" \
  --dest-creds "AWS:$(aws ecr get-login-password --region "${REGION}")"
```

Then re-run `terraform apply`.

### ECR pull-through cache rule exists but the ECR repository is empty

The pull-through cache rule tells ECR where the upstream registry is, but it does not
proactively pull images. Images are only cached when a client (not Lambda) pulls through the
cache URI. In practice, the most reliable approach is to copy the image explicitly with
`skopeo copy` as described in Step 5.

Verify the quay.io source image exists:

```bash
skopeo inspect docker://quay.io/<repository>:<tag>
```

Check the ECR pull-through cache rule:

```bash
aws ecr describe-pull-through-cache-rules --region <region>
```

If the quay.io repository is private, add a `credential_arn` pointing to a Secrets Manager
secret with quay.io credentials to the `aws_ecr_pull_through_cache_rule.quay` resource in
`deploy/regional/ecr.tf`.

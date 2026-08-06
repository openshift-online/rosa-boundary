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

1. **Container image exists in ECR** — the Lambda container image must be built and pushed to
   an ECR repository accessible from the target AWS account. Verify:
   ```bash
   aws ecr describe-images \
     --repository-name <repo-name> \
     --image-ids imageTag=<tag> \
     --region <region>
   ```

2. **ECR repository URI** — you need the full repository URI (without tag), e.g.:
   `123456789012.dkr.ecr.us-east-1.amazonaws.com/rosa-boundary-create-investigation`

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
lambda_package_type = "Image"
lambda_image_uri    = "123456789012.dkr.ecr.us-east-1.amazonaws.com/rosa-boundary-create-investigation"
lambda_image_tag    = "latest"  # or a specific tag
```

### Step 5: Plan the Migration

```bash
terraform plan
```

Expected plan output:
- **Destroy**: `aws_lambda_function.create_investigation_zip[0]` (the ZIP Lambda)
- **Destroy**: `data.archive_file.create_investigation_lambda[0]` (the ZIP archive)
- **Create**: `aws_lambda_function.create_investigation_image[0]` (the Image Lambda)
- **Update**: `aws_lambda_function_url.create_investigation` (function name reference)
- **Update**: `aws_lambda_permission.create_investigation_url` (function name reference)

Since both resources use the same `function_name`, AWS will delete the old function and create
the new one. There is a **brief window** (typically seconds) where the function does not exist.

### Step 6: Apply

```bash
terraform apply
```

### Step 7: Validate

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
> Terraform state manipulation. The standard migration (Steps 1-7) is recommended for most
> deployments since the downtime window is typically under 10 seconds.

## Rollback

To revert to ZIP packaging:

1. Update variables:
   ```hcl
   lambda_package_type = "Zip"
   # lambda_image_uri and lambda_image_tag can remain set — they are ignored in Zip mode
   ```

2. Run `terraform apply` — this will destroy the Image Lambda and create a ZIP Lambda.

3. The same brief downtime window applies during rollback.

## Troubleshooting

### `lambda_image_uri is required when lambda_package_type is 'Image'`

You set `lambda_package_type = "Image"` without providing `lambda_image_uri`. Set the ECR
repository URI in your tfvars or workspace variables.

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

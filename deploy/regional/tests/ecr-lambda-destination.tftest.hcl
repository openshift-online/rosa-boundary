# Mock plans: no ECR resources are created in AWS.
mock_provider "aws" {
  mock_data "aws_kms_alias" {
    defaults = { target_key_arn = "arn:aws:kms:us-west-2:123456789012:key/22222222-2222-2222-2222-222222222222" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::boundary-test-audit" }
  }

  mock_data "aws_partition" {
    defaults = { partition = "aws", dns_suffix = "amazonaws.com" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-west-2", name = "us-west-2" }
  }
  mock_data "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/boundary-shared", id = "boundary-shared" }
  }
  mock_data "aws_iam_openid_connect_provider" {
    defaults = { arn = "arn:aws:iam::123456789012:oidc-provider/auth.example.com/realms/sre" }
  }
}
mock_provider "archive" {}

# Keep content and audit identities distinct under mocking.
override_resource {
  target = aws_s3_bucket.content
  values = {
    arn = "arn:aws:s3:::123456789012-rosa-boundary-dev-us-west-2-content"
    id  = "123456789012-rosa-boundary-dev-us-west-2-content"
  }
}

variables {
  aws_account_id           = "123456789012"
  aws_region               = "us-west-2"
  legacy_policy_region     = "us-east-1"
  container_image          = "example.com/rosa-boundary:test"
  vpc_id                   = "vpc-00000000000000000"
  subnet_ids               = ["subnet-00000000000000000", "subnet-11111111111111111"]
  keycloak_issuer_url      = "https://auth.example.com/realms/sre"
  keycloak_thumbprint      = "0000000000000000000000000000000000000000"
  required_groups          = ["ai-sd-sre"]
  abac_tag_key             = "uuid"
  enable_kube_proxy        = false
  bedrock_model_agreements = { "anthropic.claude-sonnet-5" = "offer-test" }
  claude_default_model     = "us.anthropic.claude-sonnet-5"
}

override_data {
  target = data.aws_subnet.bedrock_runtime["subnet-00000000000000000"]
  values = { vpc_id = "vpc-00000000000000000", availability_zone_id = "usw2-az1" }
}
override_data {
  target = data.aws_subnet.bedrock_runtime["subnet-11111111111111111"]
  values = { vpc_id = "vpc-00000000000000000", availability_zone_id = "usw2-az2" }
}
override_data {
  target = data.aws_route_table.subnet[0]
  values = { routes = [{ cidr_block = "0.0.0.0/0", gateway_id = "igw-0", nat_gateway_id = "" }] }
}
override_data {
  target = data.aws_route_table.subnet[1]
  values = { routes = [{ cidr_block = "0.0.0.0/0", gateway_id = "igw-0", nat_gateway_id = "" }] }
}

run "destination_is_opt_in" {
  command = plan
  assert {
    condition     = length(aws_ecr_repository.create_investigation_lambda_destination) == 0 && length(aws_ecr_lifecycle_policy.create_investigation_lambda_destination) == 0
    error_message = "The regional root does not create an ordinary repository by default."
  }
}

run "destination_matches_source_and_lambda_uses_regional_ecr" {
  command = plan
  variables {
    lambda_ecr_destination_source_region = "us-east-1"
    lambda_package_type                  = "Image"
    lambda_image_tag                     = "0123456789abcdef0123456789abcdef01234567"
  }
  assert {
    condition = (
      aws_ecr_repository.create_investigation_lambda_destination[0].name == "rosa-boundary/create-investigation-lambda" &&
      aws_ecr_repository.create_investigation_lambda_destination[0].image_tag_mutability == "IMMUTABLE" &&
      aws_ecr_repository.create_investigation_lambda_destination[0].force_delete == false &&
      aws_ecr_repository.create_investigation_lambda_destination[0].encryption_configuration[0].encryption_type == "AES256" &&
      aws_ecr_repository.create_investigation_lambda_destination[0].image_scanning_configuration[0].scan_on_push == true &&
      jsondecode(aws_ecr_lifecycle_policy.create_investigation_lambda_destination[0].policy).rules[0].selection.countNumber == 25 &&
      local.lambda_ecr_image_uri == "123456789012.dkr.ecr.us-west-2.amazonaws.com/rosa-boundary/create-investigation-lambda:0123456789abcdef0123456789abcdef01234567"
    )
    error_message = "Destination matches source retention/settings and Lambda uses the ordinary regional repository."
  }
}

run "ordinary_regional_ecr_is_the_only_image_source" {
  command = plan
  variables {
    lambda_package_type = "Image"
    lambda_image_tag    = "0123456789abcdef0123456789abcdef01234567"
  }
  assert {
    condition = (
      local.lambda_ecr_image_uri == "123456789012.dkr.ecr.us-west-2.amazonaws.com/rosa-boundary/create-investigation-lambda:0123456789abcdef0123456789abcdef01234567" &&
      aws_lambda_function.create_investigation_image[0].image_uri == local.lambda_ecr_image_uri &&
      length(aws_ecr_repository.create_investigation_lambda_destination) == 0
    )
    error_message = "The image Lambda must use the account-local regional repository without creating a duplicate source repository."
  }
}

run "ordinary_ecr_rejects_non_sha_tag" {
  command = plan
  variables {
    lambda_package_type = "Image"
    lambda_image_tag    = "on-pr-194-abcdef0"
  }
  expect_failures = [aws_lambda_function.create_investigation_image[0]]
}

run "ordinary_ecr_rejects_mutable_tag" {
  command = plan
  variables {
    lambda_package_type = "Image"
    lambda_image_tag    = "latest"
  }
  expect_failures = [aws_lambda_function.create_investigation_image[0]]
}

run "zip_does_not_use_ecr_image" {
  command = plan
  variables {
    lambda_package_type = "Zip"
  }
  assert {
    condition     = local.lambda_ecr_image_uri == "" && length(aws_lambda_function.create_investigation_image) == 0
    error_message = "ZIP packaging must not build an image URI or create an image Lambda."
  }
}

run "source_region_cannot_duplicate_account_repository" {
  command = plan
  variables {
    aws_region                           = "us-east-1"
    lambda_ecr_destination_source_region = "us-east-1"
  }
  expect_failures = [aws_ecr_repository.create_investigation_lambda_destination[0]]
}

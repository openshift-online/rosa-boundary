# These plans use only the mock provider; no AWS calls or resources are created.
mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws", dns_suffix = "amazonaws.com" }
  }
}

variables {
  aws_account_id                    = "123456789012"
  aws_region                        = "us-east-1"
  legacy_policy_region              = "us-east-1"
  legacy_role_tag_region            = "us-east-1"
  bedrock_budget_tag_region         = "us-east-1"
  bedrock_monthly_budget_usd        = 1000
  bedrock_budget_notification_email = "alerts@example.com"
  keycloak_issuer_url               = "https://auth.example.com/realms/sre"
  keycloak_thumbprint               = "0000000000000000000000000000000000000000"
  bedrock_model_agreements          = {}
}

run "lambda_ecr_source_is_opt_in" {
  command = plan
  assert {
    condition     = length(aws_ecr_repository.create_investigation_lambda_source) == 0
    error_message = "The source repository must not be created in other accounts by default."
  }
  assert {
    condition     = length(aws_ecr_replication_configuration.create_investigation_lambda) == 0
    error_message = "Default configuration must not manage the registry-wide replication rules."
  }
}

run "staging_lambda_ecr_source_is_ordinary_and_immutable" {
  command = plan
  variables {
    stage                    = "stage"
    enable_lambda_ecr_source = true
  }
  assert {
    condition = (
      aws_ecr_repository.create_investigation_lambda_source[0].name == "rosa-boundary/create-investigation-lambda" &&
      aws_ecr_repository.create_investigation_lambda_source[0].image_tag_mutability == "IMMUTABLE" &&
      aws_ecr_repository.create_investigation_lambda_source[0].force_delete == false &&
      aws_ecr_repository.create_investigation_lambda_source[0].encryption_configuration[0].encryption_type == "AES256" &&
      aws_ecr_repository.create_investigation_lambda_source[0].image_scanning_configuration[0].scan_on_push == true &&
      length(aws_ecr_lifecycle_policy.create_investigation_lambda_source) == 1 &&
      jsondecode(aws_ecr_lifecycle_policy.create_investigation_lambda_source[0].policy).rules[0].selection.countType == "imageCountMoreThan" &&
      jsondecode(aws_ecr_lifecycle_policy.create_investigation_lambda_source[0].policy).rules[0].selection.countNumber == 25
    )
    error_message = "Pilot must create only a non-cache, encrypted, immutable repository with rollback retention."
  }
}

run "replication_is_source_owned_and_filtered" {
  command = plan
  variables {
    stage                    = "stage"
    enable_lambda_ecr_source = true
    replication              = { primary_region = "us-east-1", destinations = { "us-west-2" = {} } }
  }
  assert {
    condition = (
      length(aws_ecr_replication_configuration.create_investigation_lambda) == 1 &&
      aws_ecr_replication_configuration.create_investigation_lambda[0].replication_configuration[0].rule[0].destination[0].region == "us-west-2" &&
      aws_ecr_replication_configuration.create_investigation_lambda[0].replication_configuration[0].rule[0].destination[0].registry_id == "123456789012" &&
      aws_ecr_replication_configuration.create_investigation_lambda[0].replication_configuration[0].rule[0].repository_filter[0].filter == "rosa-boundary/create-investigation-lambda" &&
      aws_ecr_replication_configuration.create_investigation_lambda[0].replication_configuration[0].rule[0].repository_filter[0].filter_type == "PREFIX_MATCH"
    )
    error_message = "The account root replicates only the Lambda repository prefix to the same account's destination Region."
  }
}

run "replication_requires_source" {
  command = plan
  variables {
    replication = { primary_region = "us-east-1", destinations = { "us-west-2" = {} } }
  }
  expect_failures = [aws_ecr_replication_configuration.create_investigation_lambda[0]]
}

run "multiple_destinations_share_one_filtered_rule" {
  command = plan
  variables {
    enable_lambda_ecr_source = true
    replication              = { primary_region = "us-east-1", destinations = { "us-west-2" = {}, "eu-west-1" = {} } }
  }
  assert {
    condition = (
      length(aws_ecr_replication_configuration.create_investigation_lambda[0].replication_configuration[0].rule) == 1 &&
      toset([for destination in aws_ecr_replication_configuration.create_investigation_lambda[0].replication_configuration[0].rule[0].destination : destination.region]) == toset(["us-west-2", "eu-west-1"])
    )
    error_message = "Additional Regions must use the same account-owned filtered rule."
  }
}

run "replication_rejects_source_region" {
  command = plan
  variables {
    enable_lambda_ecr_source = true
    replication              = { primary_region = "us-east-1", destinations = { "us-east-1" = {} } }
  }
  expect_failures = [var.replication]
}

run "replication_rejects_wrong_primary_region" {
  command = plan
  variables {
    enable_lambda_ecr_source = true
    replication              = { primary_region = "eu-west-1", destinations = { "us-west-2" = {} } }
  }
  expect_failures = [var.replication]
}

run "empty_shared_destinations_do_not_manage_ecr_replication" {
  command = plan
  variables {
    replication = { primary_region = "us-east-1", destinations = {} }
  }
  assert {
    condition     = length(aws_ecr_replication_configuration.create_investigation_lambda) == 0
    error_message = "An empty topology must not manage registry-wide replication."
  }
}

run "s3_readiness_does_not_change_ecr_destinations" {
  command = plan
  variables {
    enable_lambda_ecr_source = true
    replication = {
      primary_region = "us-east-1"
      destinations = {
        us-west-2 = { content = {
          bucket_arn       = "arn:aws:s3:::test-content"
          kms_key_arn      = "arn:aws:kms:us-west-2:123456789012:key/test"
          content_prefixes = { ops-sop = "ops-sop/" }
        } }
        eu-west-1 = {}
      }
    }
  }
  assert {
    condition = toset([
      for destination in aws_ecr_replication_configuration.create_investigation_lambda[0].replication_configuration[0].rule[0].destination : destination.region
    ]) == toset(["us-west-2", "eu-west-1"])
    error_message = "ECR must use every destination key regardless of S3 handoff readiness."
  }
}

# PR plans use existing HCP inputs until the meta-workspace rename is applied.
run "legacy_workspace_input_preserves_existing_replication_before_meta_apply" {
  command = plan
  variables {
    enable_lambda_ecr_source       = true
    lambda_ecr_replication_regions = ["us-west-2"]
  }
  assert {
    condition = (
      length(aws_ecr_replication_configuration.create_investigation_lambda) == 1 &&
      aws_ecr_replication_configuration.create_investigation_lambda[0].replication_configuration[0].rule[0].destination[0].region == "us-west-2"
    )
    error_message = "Legacy HCP inputs must preserve the existing registry replication rule before the meta-workspace migration."
  }
}

run "matching_inputs_are_allowed_during_migration" {
  command = plan
  variables {
    enable_lambda_ecr_source       = true
    lambda_ecr_replication_regions = ["us-west-2"]
    replication                    = { primary_region = "us-east-1", destinations = { us-west-2 = {} } }
  }
  assert {
    condition = (
      length(aws_ecr_replication_configuration.create_investigation_lambda) == 1 &&
      aws_ecr_replication_configuration.create_investigation_lambda[0].replication_configuration[0].rule[0].destination[0].region == "us-west-2"
    )
    error_message = "Matching legacy and generic inputs must retain the same rule."
  }
}

run "conflicting_migration_inputs_are_rejected" {
  command = plan
  variables {
    enable_lambda_ecr_source       = true
    lambda_ecr_replication_regions = ["us-west-2"]
    replication                    = { primary_region = "us-east-1", destinations = { eu-west-1 = {} } }
  }
  expect_failures = [var.lambda_ecr_replication_regions]
}

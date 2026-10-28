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
      length(aws_ecr_lifecycle_policy.create_investigation_lambda_source) == 1 &&
      jsondecode(aws_ecr_lifecycle_policy.create_investigation_lambda_source[0].policy).rules[0].selection.countType == "imageCountMoreThan" &&
      jsondecode(aws_ecr_lifecycle_policy.create_investigation_lambda_source[0].policy).rules[0].selection.countNumber == 25
    )
    error_message = "Pilot must create only a non-cache, encrypted, immutable repository with rollback retention."
  }
}

# Validate session timer inputs on a mocked plan, without rendering unrelated resources.
mock_provider "aws" {
  mock_data "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/boundary-test" }
  }
}
mock_provider "archive" {}

variables {
  aws_account_id       = "123456789012"
  aws_region           = "us-east-1"
  legacy_policy_region = "us-east-1"
  container_image      = "example.com/rosa-boundary:test"
  vpc_id               = "vpc-00000000000000000"
  subnet_ids           = ["subnet-00000000000000000", "subnet-11111111111111111"]
  keycloak_issuer_url  = "https://auth.example.com/auth/realms/EmployeeIDP"
  keycloak_thumbprint  = "0000000000000000000000000000000000000000"
  required_groups      = ["ai-sd-sre"]
  enable_kube_proxy    = false
}

run "eight_hours_is_valid" {
  command = plan
  plan_options {
    target = [aws_lambda_function.create_investigation_zip]
  }
  variables {
    task_timeout_default = 28800
    task_timeout_minimum = 28800
  }
}

run "above_eight_hours_is_invalid" {
  command = plan
  plan_options {
    target = [aws_lambda_function.create_investigation_zip]
  }
  variables {
    task_timeout_default = 28801
    task_timeout_minimum = 28801
  }
  expect_failures = [var.task_timeout_default, var.task_timeout_minimum]
}

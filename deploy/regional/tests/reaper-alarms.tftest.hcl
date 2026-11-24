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
  required_groups          = ["test-group"]
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

run "both_reapers_alarm_without_routing_by_default" {
  command = plan

  assert {
    condition = length(aws_cloudwatch_metric_alarm.reaper_errors) == 2 && alltrue([
      for key, function_name in {
        tasks          = aws_lambda_function.reap_tasks.function_name
        investigations = aws_lambda_function.reap_investigations.function_name
        } : (
        aws_cloudwatch_metric_alarm.reaper_errors[key].dimensions == tomap({ FunctionName = function_name }) &&
        aws_cloudwatch_metric_alarm.reaper_errors[key].namespace == "AWS/Lambda" &&
        aws_cloudwatch_metric_alarm.reaper_errors[key].metric_name == "Errors" &&
        aws_cloudwatch_metric_alarm.reaper_errors[key].statistic == "Sum" &&
        aws_cloudwatch_metric_alarm.reaper_errors[key].threshold == 1 &&
        aws_cloudwatch_metric_alarm.reaper_errors[key].comparison_operator == "GreaterThanOrEqualToThreshold" &&
        aws_cloudwatch_metric_alarm.reaper_errors[key].period == 300 &&
        aws_cloudwatch_metric_alarm.reaper_errors[key].evaluation_periods == 1 &&
        aws_cloudwatch_metric_alarm.reaper_errors[key].treat_missing_data == "notBreaching" &&
        !aws_cloudwatch_metric_alarm.reaper_errors[key].actions_enabled &&
        length(aws_cloudwatch_metric_alarm.reaper_errors[key].alarm_actions) == 0
      )
    ])
    error_message = "Each reaper needs its own native Errors alarm with no default notification route."
  }
}

run "both_alarms_route_to_configured_topic" {
  command = plan
  variables {
    reaper_alarm_sns_topic_arn = "arn:aws:sns:us-west-2:123456789012:test-alerts"
  }

  assert {
    condition = alltrue([
      for alarm in aws_cloudwatch_metric_alarm.reaper_errors :
      alarm.actions_enabled && alarm.alarm_actions == toset([var.reaper_alarm_sns_topic_arn])
    ])
    error_message = "Both reaper alarms must notify only the configured SNS topic."
  }
}

run "reject_out_of_region_topic" {
  command = plan
  variables {
    reaper_alarm_sns_topic_arn = "arn:aws:sns:us-east-1:123456789012:test-alerts"
  }
  expect_failures = [var.reaper_alarm_sns_topic_arn]
}

# Derive both task-role and endpoint permissions from the same per-account
# allowlist. Foundation-model ARNs have no account ID; system profiles do.
locals {
  bedrock_allowed_profiles = {
    for model_id, model in var.bedrock_allowed_models :
    model_id => "arn:${data.aws_partition.current.partition}:bedrock:${var.aws_region}:${data.aws_caller_identity.current.account_id}:inference-profile/${model.profile_id}"
  }

  bedrock_allowed_foundation_models = {
    for model_id, model in var.bedrock_allowed_models :
    model_id => [
      for region in sort(tolist(model.model_regions)) :
      "arn:${data.aws_partition.current.partition}:bedrock:${region}::foundation-model/${model_id}"
    ]
  }

  bedrock_allowed_resources = concat(
    values(local.bedrock_allowed_profiles),
    flatten(values(local.bedrock_allowed_foundation_models))
  )

  # Restrict backing models to their corresponding profile. Direct foundation
  # model calls and requests through a different profile remain denied even if
  # somebody attaches another Bedrock Allow policy to the shared task role.
  bedrock_model_statements = {
    for model_id, profile_arn in local.bedrock_allowed_profiles : model_id => [
      {
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = [profile_arn]
      },
      {
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = local.bedrock_allowed_foundation_models[model_id]
        Condition = {
          StringEquals = { "bedrock:InferenceProfileArn" = profile_arn }
        }
      }
    ]
  }

  bedrock_invoke_statements = flatten(values(local.bedrock_model_statements))

  bedrock_invoke_denies = concat(
    length(local.bedrock_allowed_resources) == 0 ? [{
      Effect   = "Deny"
      Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
      Resource = "*"
    }] : [],
    length(local.bedrock_allowed_resources) > 0 ? [{
      Effect      = "Deny"
      Action      = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
      NotResource = local.bedrock_allowed_resources
    }] : []
  )
}

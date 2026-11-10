# Content publishing and replication identities.
#
# Mocked applies use only ephemeral Terraform test state, never AWS APIs.
#
# These runs assert the trust POLICY DOCUMENT this configuration renders. They
# do not exercise AWS: no mocked test can show that STS refuses a token whose
# subject is a pull request, a fork or another branch. That evidence needs a
# real AssumeRoleWithWebIdentity and belongs to the publisher workflow work.
#
# Two separable things are asserted, and conflating them would overstate the
# guarantee. The SYNTAX runs show inputs cannot carry their own ":" segment,
# a "*" or a full ref, so no input becomes a pull-request, merge-ref or
# environment subject. The RENDERED-SUBJECT runs show the configured sources
# produce exactly the three agreed subjects, which is what excludes an
# unconfigured repository or branch - a fork is excluded by configuration, not
# by validation. Also asserted: StringEquals, a scalar subject, one fixed
# audience and the complete subject set.
mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws", dns_suffix = "amazonaws.com" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
}

variables {
  project                        = "rosa-boundary"
  stage                          = "dev"
  role_name_prefix               = "rosa-boundary-dev"
  legacy_role_tag_region         = "us-west-2"
  bedrock_logging_source_regions = ["us-west-2"]
  tags                           = { Owner = "sre" }
  enable_s3_replication_role     = false
  keycloak_provider_arn          = "arn:aws:iam::123456789012:oidc-provider/auth.example.com/realms/sre"
  stage_keycloak_provider_arn    = ""
  prod_keycloak_provider_arn     = ""
  stage_keycloak_issuer_url      = ""
  prod_keycloak_issuer_url       = ""
  oidc_client_id                 = "rosa-boundary-sre"
  stage_oidc_client_id           = ""
  prod_oidc_client_id            = ""
  oidc_session_duration          = 3600
  enable_uuid_allowlist          = false
  allowed_uuids                  = []
  enable_oidc_group_enforcement  = true
  required_oidc_role             = "ai-sd-sre"

  enable_metrics_read_role            = false
  metrics_read_trusted_principal_arns = []
  metrics_read_session_duration       = 3600

  github_actions_provider_arn        = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  github_actions_audience            = "sts.amazonaws.com"
  content_publisher_session_duration = 3600
  content_publisher_sources = {
    ops-sop               = { repository = "openshift/ops-sop", branch = "master" }
    managed-notifications = { repository = "openshift/managed-notifications", branch = "master" }
    rosa-claude-plugins   = { repository = "openshift-online/rosa-claude-plugins", branch = "main" }
  }
}


run "publishers_are_three_separate_identities_with_exact_subjects" {
  command = apply
  module { source = "./modules/shared-iam" }

  assert {
    condition = toset([for role in aws_iam_role.content_publisher : role.name]) == toset([
      "rosa-boundary-dev-publisher-ops-sop",
      "rosa-boundary-dev-publisher-managed-notifications",
      "rosa-boundary-dev-publisher-rosa-claude-plugins",
    ])
    error_message = "Each source repository must get its own prefix-derived publisher identity."
  }

  # One subject per role, and the three together are exactly the agreed set.
  # Checking the whole set is what rules out a fourth repository or a second
  # subject on one role; checking each separately would not.
  assert {
    condition = (
      toset([for role in aws_iam_role.content_publisher : jsondecode(role.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"]]) == toset([
        "repo:openshift/ops-sop:ref:refs/heads/master",
        "repo:openshift/managed-notifications:ref:refs/heads/master",
        "repo:openshift-online/rosa-claude-plugins:ref:refs/heads/main",
      ]) &&
      jsondecode(aws_iam_role.content_publisher["ops-sop"].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:openshift/ops-sop:ref:refs/heads/master" &&
      jsondecode(aws_iam_role.content_publisher["managed-notifications"].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:openshift/managed-notifications:ref:refs/heads/master" &&
      jsondecode(aws_iam_role.content_publisher["rosa-claude-plugins"].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:openshift-online/rosa-claude-plugins:ref:refs/heads/main"
    )
    error_message = "Trust must name exactly the three agreed repository and default-branch subjects; note rosa-claude-plugins uses main, not master."
  }

  assert {
    condition = alltrue([
      for policy in [for role in aws_iam_role.content_publisher : jsondecode(role.assume_role_policy)] :
      policy.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    ])
    error_message = "Every publisher must require the exact audience sts.amazonaws.com."
  }

  # The audience is threaded from the account root, which also uses it for the
  # provider's client ID list, so the provider and these policies cannot drift.
  assert {
    condition = alltrue([
      for policy in [for role in aws_iam_role.content_publisher : jsondecode(role.assume_role_policy)] :
      policy.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == var.github_actions_audience
    ])
    error_message = "The publisher audience must be the one the account root configured on the OIDC provider."
  }

  # The operator and value types are the control. A list-valued subject would
  # broaden trust without changing a single visible string. StringLike is
  # pinned out not because it widens a literal - it does not, a StringLike
  # value with no metacharacter matches exactly one string - but because it is
  # the operator under which a stored "*" would become a live wildcard.
  assert {
    condition = alltrue([
      for policy in [for role in aws_iam_role.content_publisher : jsondecode(role.assume_role_policy)] : (
        length(policy.Statement) == 1 &&
        policy.Statement[0].Effect == "Allow" &&
        policy.Statement[0].Action == "sts:AssumeRoleWithWebIdentity" &&
        keys(policy.Statement[0].Condition) == ["StringEquals"] &&
        toset(keys(policy.Statement[0].Condition.StringEquals)) == toset([
          "token.actions.githubusercontent.com:aud",
          "token.actions.githubusercontent.com:sub",
        ]) &&
        can(tostring(policy.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"])) &&
        can(tostring(policy.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"]))
      )
    ])
    error_message = "Each publisher trust must be one web-identity statement conditioned only on an exact scalar audience and subject."
  }

  assert {
    condition = alltrue([
      for policy in [for role in aws_iam_role.content_publisher : jsondecode(role.assume_role_policy)] : (
        policy.Statement[0].Principal.Federated == var.github_actions_provider_arn &&
        keys(policy.Statement[0].Principal) == ["Federated"]
      )
    ])
    error_message = "The only trusted principal is the account's GitHub Actions OIDC provider."
  }

  assert {
    condition = alltrue([
      for role in aws_iam_role.content_publisher : (
        role.max_session_duration == 3600 &&
        trimspace(role.description) != "" &&
        role.tags.Region == "us-west-2" &&
        role.tags.Project == "rosa-boundary" &&
        role.tags.Stage == "dev" &&
        role.tags.ManagedBy == "Terraform" &&
        role.tags.Owner == "sre" &&
        role.tags.Name == role.name
      )
    ])
    error_message = "Publisher identities must keep bounded sessions, a description and the account's common tags."
  }
}

run "publishers_reject_pull_request_fork_wildcard_and_wrong_branch_subjects" {
  command = apply
  module { source = "./modules/shared-iam" }

  # Absence is asserted against the decoded documents, not with can(): can()
  # swallows every error, so a shape change would satisfy it silently.
  # Subjects an implementation mistake or a later edit could plausibly
  # produce: a pull-request subject, a merge ref, the other project's default
  # branch, an environment subject, a fork owner and a wildcard. The fork and
  # wrong-branch entries are excluded here by the CONFIGURED sources, not by
  # input validation, which would accept them as an explicit configuration
  # change; this run is what pins the shipped configuration.
  assert {
    condition = length([
      for policy in [for role in aws_iam_role.content_publisher : jsondecode(role.assume_role_policy)] :
      policy if contains([
        "repo:openshift/ops-sop:pull_request",
        "repo:openshift/ops-sop:ref:refs/pull/1/merge",
        "repo:openshift/ops-sop:ref:refs/heads/main",
        "repo:openshift/managed-notifications:ref:refs/heads/main",
        "repo:openshift-online/rosa-claude-plugins:ref:refs/heads/master",
        "repo:openshift/ops-sop:environment:production",
        "repo:someuser/ops-sop:ref:refs/heads/master",
        "repo:openshift/*:ref:refs/heads/master",
        "repo:*:ref:refs/heads/master",
      ], policy.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"])
    ]) == 0
    error_message = "No publisher may trust a pull-request, merge-ref, environment, fork, wildcard or wrong-branch subject."
  }

  # The rendered JSON must not contain these strings anywhere, which also
  # catches a second statement or an extra condition a key lookup would miss.
  assert {
    condition = alltrue(flatten([
      for role in aws_iam_role.content_publisher : [
        for fragment in ["*", ":pull_request", "refs/pull/", ":environment:", "StringLike", "ForAnyValue", "ForAllValues", "sts:TagSession", "sts:AssumeRoleWithSAML"] :
        !strcontains(role.assume_role_policy, fragment)
      ]
    ]))
    error_message = "Publisher trust documents must contain no wildcard, pull-request, fork, environment, session-tagging or wildcard-operator construct."
  }

  # Principal.AWS is absent entirely here, so comparing it to "*" would prove
  # nothing; assert the key set instead, and that no AWS or service principal
  # or account root can appear.
  assert {
    condition = alltrue([
      for policy in [for role in aws_iam_role.content_publisher : jsondecode(role.assume_role_policy)] : (
        !contains(keys(policy.Statement[0].Principal), "AWS") &&
        !contains(keys(policy.Statement[0].Principal), "Service") &&
        !strcontains(policy.Statement[0].Principal.Federated, ":root") &&
        policy.Statement[0].Principal.Federated != "*"
      )
    ])
    error_message = "A publisher must never trust an AWS principal, a service principal, an account root or a bare wildcard."
  }
}

run "content_identities_are_unconditional" {
  command = apply
  module { source = "./modules/shared-iam" }
  assert {
    condition = (
      length(aws_iam_role.content_publisher) == 3 &&
      output.content_replication_role.arn != null &&
      toset(keys(output.content_publisher_roles)) == toset(["ops-sop", "managed-notifications", "rosa-claude-plugins"]) &&
      output.content_replication_role.name == "rosa-boundary-dev-content-replication-role"
    )
    error_message = "Publishers and the dedicated replication identity must always exist."
  }
  # Ownership: the grants belong to the regional root, so this file must be
  # able to create identities and nothing else. The repository-wide guards in
  # baseline.tftest.hcl already forbid policy resources and attachments in
  # every module file; this adds the storage-specific half for this feature.
  assert {
    condition     = length(regexall("aws_s3_bucket|aws_kms_|alias/aws/s3|\"s3:|\"kms:|terraform_remote_state", file("${path.module}/content-publishing.tf"))) == 0
    error_message = "content-publishing.tf must declare identity and trust only, with no bucket, key or remote-state reference."
  }
}

run "content_replication_trust_matches_the_audit_replication_precedent" {
  command = apply
  module { source = "./modules/shared-iam" }
  variables { enable_s3_replication_role = true }

  assert {
    condition = (
      aws_iam_role.content_replication.name == "rosa-boundary-dev-content-replication-role" &&
      aws_iam_role.s3_replication[0].name == "rosa-boundary-dev-s3-replication-role" &&
      aws_iam_role.content_replication.name != aws_iam_role.s3_replication[0].name &&
      output.content_replication_role.arn == aws_iam_role.content_replication.arn
    )
    error_message = "Content replication must be its own identity, never the audit replication role."
  }

  # Structurally identical to the deployed audit role: S3 service trust, no
  # condition. This asserts the document matches that precedent; it makes no
  # claim about how AWS evaluates the trust.
  assert {
    condition = (
      jsondecode(aws_iam_role.content_replication.assume_role_policy) == jsondecode(aws_iam_role.s3_replication[0].assume_role_policy) &&
      jsondecode(aws_iam_role.content_replication.assume_role_policy).Statement[0].Principal.Service == "s3.amazonaws.com" &&
      jsondecode(aws_iam_role.content_replication.assume_role_policy).Statement[0].Action == "sts:AssumeRole" &&
      !contains(keys(jsondecode(aws_iam_role.content_replication.assume_role_policy).Statement[0]), "Condition") &&
      !contains(keys(jsondecode(aws_iam_role.content_replication.assume_role_policy).Statement[0].Principal), "Federated")
    )
    error_message = "Content replication trust must be S3 service only, with no condition and no federated principal."
  }

  assert {
    condition = (
      aws_iam_role.content_replication.tags.Name == "rosa-boundary-dev-content-replication-role" &&
      aws_iam_role.content_replication.tags.Region == "us-west-2" &&
      aws_iam_role.content_replication.tags.Project == "rosa-boundary" &&
      trimspace(aws_iam_role.content_replication.description) != ""
    )
    error_message = "The content replication identity must keep its name, tags and description."
  }
}

run "content_replication_does_not_enable_audit_replication" {
  command = apply
  module { source = "./modules/shared-iam" }
  variables {
    enable_s3_replication_role = false
  }
  assert {
    condition = (
      length(aws_iam_role.s3_replication) == 0 &&
      output.content_replication_role.arn == aws_iam_role.content_replication.arn &&
      length(aws_iam_role.content_publisher) == 3
    )
    error_message = "Content replication must not enable audit replication or remove the unconditional publishers."
  }
}

run "audit_replication_is_unaffected_by_the_content_identities" {
  command = apply
  module { source = "./modules/shared-iam" }
  variables {
    enable_s3_replication_role = true
  }
  assert {
    condition = (
      output.content_replication_role.arn == aws_iam_role.content_replication.arn &&
      aws_iam_role.s3_replication[0].name == "rosa-boundary-dev-s3-replication-role" &&
      jsondecode(aws_iam_role.s3_replication[0].assume_role_policy) == {
        Version   = "2012-10-17"
        Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "s3.amazonaws.com" } }]
      }
    )
    error_message = "The existing audit replication identity must be preserved exactly."
  }
}

run "custom_prefix_is_applied_to_every_content_identity" {
  command = apply
  module { source = "./modules/shared-iam" }
  variables { role_name_prefix = "boundary-shared" }
  assert {
    condition = (
      output.content_publisher_roles["ops-sop"].name == "boundary-shared-publisher-ops-sop" &&
      output.content_publisher_roles["managed-notifications"].name == "boundary-shared-publisher-managed-notifications" &&
      output.content_publisher_roles["rosa-claude-plugins"].name == "boundary-shared-publisher-rosa-claude-plugins" &&
      output.content_replication_role.name == "boundary-shared-content-replication-role"
    )
    error_message = "A deliberate custom prefix must reach every content identity."
  }
}

run "output_contract_is_complete_and_stable" {
  command = apply
  module { source = "./modules/shared-iam" }
  assert {
    condition = (
      toset(keys(output.content_publisher_roles)) == toset(["ops-sop", "managed-notifications", "rosa-claude-plugins"]) &&
      output.content_publisher_roles["ops-sop"].repository == "openshift/ops-sop" &&
      output.content_publisher_roles["ops-sop"].branch == "master" &&
      output.content_publisher_roles["ops-sop"].subject == "repo:openshift/ops-sop:ref:refs/heads/master" &&
      output.content_publisher_roles["managed-notifications"].subject == "repo:openshift/managed-notifications:ref:refs/heads/master" &&
      output.content_publisher_roles["rosa-claude-plugins"].branch == "main" &&
      output.content_publisher_roles["rosa-claude-plugins"].subject == "repo:openshift-online/rosa-claude-plugins:ref:refs/heads/main" &&
      alltrue([for key, role in output.content_publisher_roles : role.arn == aws_iam_role.content_publisher[key].arn])
    )
    error_message = "The published contract must carry each identity's name, ARN, source repository, branch and exact subject."
  }
  # The pre-existing shared identity contract keeps its shape: the content
  # identities are published separately, not folded into it.
  assert {
    condition     = length(output.roles) == 10 && output.roles.s3_replication == null
    error_message = "The shared_roles contract must not change shape when content identities are added."
  }
}

# With the default sources, -publisher-managed-notifications is the longest
# suffix at 32 characters. A 32-character prefix produces a 64-character name.
run "longest_valid_prefix_keeps_content_role_names_legal" {
  command = apply
  module { source = "./modules/shared-iam" }
  variables { role_name_prefix = "12345678901234567890123456789012" }
  assert {
    condition = alltrue(concat(
      [for role in aws_iam_role.content_publisher : length(role.name) <= 64],
      [length(aws_iam_role.content_replication.name) <= 64],
    ))
    error_message = "Content identity names must fit the 64-character IAM limit at the longest permitted role prefix."
  }
}

run "a_module_without_a_provider_fails_closed" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables { github_actions_provider_arn = "" }
  expect_failures = [aws_iam_role.content_publisher]
}

run "rejects_a_publisher_set_with_no_sources" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables { content_publisher_sources = {} }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_a_wildcard_repository" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    content_publisher_sources = {
      ops-sop = { repository = "openshift/*", branch = "master" }
    }
  }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_a_bare_wildcard_repository" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    content_publisher_sources = {
      ops-sop = { repository = "*", branch = "master" }
    }
  }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_a_repository_without_an_owner" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    content_publisher_sources = {
      ops-sop = { repository = "ops-sop", branch = "master" }
    }
  }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_a_repository_with_extra_path_segments" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    content_publisher_sources = {
      ops-sop = { repository = "openshift/ops-sop/extra", branch = "master" }
    }
  }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_a_subject_injected_into_the_repository" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    content_publisher_sources = {
      ops-sop = { repository = "openshift/ops-sop:pull_request", branch = "master" }
    }
  }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_a_wildcard_branch" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    content_publisher_sources = {
      ops-sop = { repository = "openshift/ops-sop", branch = "*" }
    }
  }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_a_full_branch_ref" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    content_publisher_sources = {
      ops-sop = { repository = "openshift/ops-sop", branch = "refs/heads/master" }
    }
  }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_a_pull_request_ref_as_a_branch" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    content_publisher_sources = {
      ops-sop = { repository = "openshift/ops-sop", branch = "refs/pull/1/merge" }
    }
  }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_an_environment_subject_injected_into_the_branch" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    content_publisher_sources = {
      ops-sop = { repository = "openshift/ops-sop", branch = "master:environment:production" }
    }
  }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_an_empty_repository_or_branch" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    content_publisher_sources = {
      ops-sop = { repository = "", branch = "" }
    }
  }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_surrounding_whitespace" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    content_publisher_sources = {
      ops-sop = { repository = "openshift/ops-sop ", branch = "master" }
    }
  }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_two_keys_pointing_at_one_identity" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    content_publisher_sources = {
      ops-sop  = { repository = "openshift/ops-sop", branch = "master" }
      ops-sop2 = { repository = "openshift/ops-sop", branch = "master" }
    }
  }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_a_prefix_that_overflows_a_default_publisher_name" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables { role_name_prefix = "123456789012345678901234567890123" }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_a_source_key_longer_than_21_characters" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables {
    content_publisher_sources = {
      managed-notifications-x = { repository = "openshift/managed-notifications", branch = "master" }
    }
  }
  expect_failures = [var.content_publisher_sources]
}

run "rejects_a_wildcard_audience" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables { github_actions_audience = "*" }
  expect_failures = [var.github_actions_audience]
}

run "rejects_an_empty_audience" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables { github_actions_audience = "" }
  expect_failures = [var.github_actions_audience]
}

run "rejects_an_unbounded_publisher_session" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables { content_publisher_session_duration = 86400 }
  expect_failures = [var.content_publisher_session_duration]
}

run "rejects_a_publisher_session_below_the_minimum" {
  command = plan
  module { source = "./modules/shared-iam" }
  variables { content_publisher_session_duration = 1800 }
  expect_failures = [var.content_publisher_session_duration]
}

"""Test that Terraform EFS policy matches expected structure

This test validates the actual Terraform configuration in deploy/regional/efs.tf
to ensure it hasn't regressed to the broken StringEquals pattern from PR #167.
"""

import pytest
import re
import os


@pytest.mark.integration
def test_terraform_efs_policy_uses_null_condition():
    """Verify deploy/regional/efs.tf uses Null condition, not StringEquals.

    Regression test for PR #167: ensures the Terraform EFS filesystem policy
    doesn't lock down to a specific access point ARN, which would break
    Lambda-created dynamic access points for investigations.
    """
    # Find the Terraform file
    test_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(test_dir, '../../..'))
    efs_tf_path = os.path.join(repo_root, 'deploy/regional/efs.tf')

    assert os.path.exists(efs_tf_path), f"Terraform file not found at {efs_tf_path}"

    with open(efs_tf_path, 'r') as f:
        content = f.read()

    # Find the aws_efs_file_system_policy resource
    policy_match = re.search(
        r'resource\s+"aws_efs_file_system_policy"\s+"sre_home"\s*{(.+?)\n}',
        content,
        re.DOTALL
    )

    assert policy_match, "Could not find aws_efs_file_system_policy resource in efs.tf"

    policy_block = policy_match.group(1)

    # Key assertions: must use Null, must NOT use StringEquals
    # Search the entire policy block for these patterns
    assert 'Null' in policy_block, \
        "Filesystem policy must use Null condition to allow dynamic access points"

    assert '"elasticfilesystem:AccessPointArn"' in policy_block, \
        "Filesystem policy must check for AccessPointArn"

    assert 'StringEquals' not in policy_block, \
        "REGRESSION DETECTED: Filesystem policy uses StringEquals with specific ARN, " \
        "which breaks Lambda-created dynamic access points. Use Null condition instead. " \
        "See PR #167 for context."

    # Validate the Null condition requires access point (value = "false")
    null_pattern = r'Null\s*=\s*{\s*"elasticfilesystem:AccessPointArn"\s*=\s*"false"'
    assert re.search(null_pattern, policy_block), \
        "Null condition must be set to 'false' to require access point presence"

    # Also validate the Bool condition is present
    assert 'Bool' in policy_block, \
        "Filesystem policy must include Bool condition for AccessedViaMountTarget"

    assert 'AccessedViaMountTarget' in policy_block, \
        "Filesystem policy must require access via mount target"


@pytest.mark.integration
def test_terraform_efs_policy_structure_complete():
    """Verify the complete structure of the EFS filesystem policy.

    Validates all required components are present:
    - Principal restricted to task role
    - Required actions (ClientMount, ClientWrite, ClientRootAccess)
    - Bool condition for mount target access
    - Null condition for access point requirement
    """
    test_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(test_dir, '../../..'))
    efs_tf_path = os.path.join(repo_root, 'deploy/regional/efs.tf')

    with open(efs_tf_path, 'r') as f:
        content = f.read()

    # Find the policy jsonencode block
    policy_match = re.search(
        r'policy\s*=\s*jsonencode\({(.+?)}\)',
        content,
        re.DOTALL
    )

    assert policy_match, "Could not find policy jsonencode block"

    policy_content = policy_match.group(1)

    # Validate required components
    required_elements = [
        ('Sid', 'EnforceAccessViaAccessPoint'),
        ('Effect', 'Allow'),
        ('elasticfilesystem:ClientMount', 'ClientMount action'),
        ('elasticfilesystem:ClientWrite', 'ClientWrite action'),
        ('elasticfilesystem:ClientRootAccess', 'ClientRootAccess action'),
        ('aws_iam_role.task.arn', 'task role restriction'),
        ('aws_efs_file_system.sre_home.arn', 'filesystem resource'),
        ('AccessedViaMountTarget', 'mount target requirement'),
    ]

    for element, description in required_elements:
        assert element in policy_content, \
            f"Policy missing required element: {description} ({element})"

    # Validate against the broken pattern
    broken_patterns = [
        (r'StringEquals.*elasticfilesystem:AccessPointArn.*aws_efs_access_point\.sre\.arn',
         'Locks to specific static access point ARN (breaks dynamic APs)'),
        (r'Principal.*=.*"\*"',
         'Allows any principal instead of restricting to task role'),
    ]

    for pattern, description in broken_patterns:
        assert not re.search(pattern, policy_content, re.DOTALL), \
            f"SECURITY ISSUE: {description}"

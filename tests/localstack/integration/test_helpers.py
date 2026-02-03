"""Helper functions for integration tests"""

import json


def get_policy_document(policy_doc_field):
    """
    Extract policy document from IAM response.

    LocalStack may return policies as dicts or JSON strings depending on version.
    This helper handles both cases.

    Args:
        policy_doc_field: The PolicyDocument field from IAM API response

    Returns:
        dict: The policy document as a Python dict
    """
    if isinstance(policy_doc_field, dict):
        return policy_doc_field
    return json.loads(policy_doc_field)

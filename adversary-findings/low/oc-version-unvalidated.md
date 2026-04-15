# L4: oc_version Not Validated in Lambda Handler

- **Severity**: Low
- **Category**: Application — Input Validation
- **File**: `lambda/create-investigation/handler.py:126`

## Issue

The `oc_version` parameter from the request body is accepted without validation and passed directly into the task definition environment variables and task tags. While `validate_identifier()` is called for `investigation_id` and `cluster_id`, `oc_version` is not validated against the set of valid versions (4.14-4.20).

## Impact

A malicious or errant client could inject arbitrary strings into the `OC_VERSION` environment variable and task tags. The entrypoint script does validate the value (`if [ -x "/opt/openshift/${OC_VERSION}/oc" ]`) so invalid versions would fall back to default, but the unvalidated tag value could pollute tagging/auditing.

## Recommendation

Add validation for `oc_version` in the Lambda handler:

```python
VALID_OC_VERSIONS = {'4.14', '4.15', '4.16', '4.17', '4.18', '4.19', '4.20'}
if oc_version not in VALID_OC_VERSIONS:
    return response(400, {'error': f'Invalid oc_version: must be one of {sorted(VALID_OC_VERSIONS)}'})
```

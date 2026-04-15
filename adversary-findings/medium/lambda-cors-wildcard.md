# M7: Lambda CORS Allows All Origins

- **Severity**: Medium
- **Category**: Application — Overly Permissive CORS
- **Files**: `deploy/regional/lambda-create-investigation.tf:165`, `lambda/create-investigation/handler.py:791`

## Issue

Both the Lambda function URL CORS configuration (`allow_origins = ["*"]`) and the Lambda handler's response headers (`Access-Control-Allow-Origin: *`) permit cross-origin requests from any domain. The Terraform comment says "Allow localhost for testing; restrict in production", but this is not stage-gated.

## Impact

A malicious website could make cross-origin requests to the Lambda function URL. Since the primary auth mechanism is SigV4 (which cannot be replicated cross-origin) and the OIDC token is passed as a custom header, actual exploitation risk is low. However, the wildcard CORS combined with `Access-Control-Allow-Headers: content-type, x-oidc-token` means if an attacker obtains a valid OIDC token, they could invoke the function from any origin.

## Recommendation

Restrict CORS origins to known SRE tool domains or remove CORS entirely if the function is only called via direct SDK invocation (which is the current architecture per the lambda-invoker role).

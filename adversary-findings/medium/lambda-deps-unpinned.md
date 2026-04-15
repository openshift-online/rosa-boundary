# M9: Python Lambda Dependencies Use >= Version Pinning

- **Severity**: Medium
- **Category**: Application — Unpinned Dependency Version
- **File**: `lambda/create-investigation/pyproject.toml:6-9`

## Issue

Lambda dependencies use `>=` version specifiers: `PyJWT>=2.8.0`, `cryptography>=41.0.0`, `requests>=2.31.0`, `boto3>=1.34.0`. Each Lambda deployment could install different versions depending on when the build runs, potentially pulling in a compromised or buggy release.

## Impact

Supply chain risk: a compromised version of PyJWT, cryptography, or requests could be automatically pulled in during a Lambda build. The `cryptography` package in particular has been targeted in supply chain attacks.

## Recommendation

Pin exact versions with hashes for the Lambda deployment package:

```toml
dependencies = [
    "PyJWT==2.8.0",
    "cryptography==42.0.8",
    "requests==2.32.3",
    "boto3==1.34.150",
]
```

Consider using a lockfile or `uv.lock` for reproducible builds in the Lambda build pipeline.

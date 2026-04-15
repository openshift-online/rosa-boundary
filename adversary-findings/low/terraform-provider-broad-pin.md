# L5: Terraform AWS Provider Broadly Pinned

- **Severity**: Low
- **Category**: Infrastructure — Unpinned Dependency Version
- **File**: `deploy/regional/main.tf:7`

## Issue

The AWS provider is pinned with `version = "~> 5.0"`, which allows any 5.x release. Combined with no `.terraform.lock.hcl` committed to the repository, different Terraform runs could use different provider versions.

## Impact

A compromised or buggy provider release within the 5.x range could be automatically used. Low risk since Terraform providers are signed and verified, but tighter pinning is a defense-in-depth measure.

## Recommendation

Pin to a more specific range (e.g., `"~> 5.80"`) and commit the `.terraform.lock.hcl` file to the repository.

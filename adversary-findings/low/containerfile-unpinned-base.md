# L6: Unpinned Fedora Base Image

- **Severity**: Low
- **Category**: Infrastructure — Unpinned Image Tag
- **File**: `Containerfile:3`

## Issue

The base image `FROM fedora:43` is pinned to the major version but not to a specific digest. While `fedora:43` is better than `fedora:latest`, the tag can be overwritten when new builds of Fedora 43 are published.

## Impact

Rebuilds of the container could silently pull a different base image with different packages or configurations. For a security-sensitive SRE tooling container, reproducible builds are important.

## Recommendation

Pin to a digest:

```dockerfile
FROM fedora:43@sha256:<digest>
```

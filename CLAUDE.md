# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

Multi-architecture container for AWS Fargate that provides tools for managing AWS and OpenShift (ROSA) clusters. The container runs with `sleep infinity` entrypoint and is accessed via ECS Exec.

## Building

```bash
# Build both architectures and create manifest list
make all

# Build single architecture
make build-amd64
make build-arm64

# Create manifest list from existing builds
make manifest

# Remove all images and manifests
make clean
```

## Container Architecture

### Multi-Architecture Build System

The Containerfile uses `TARGETARCH` build argument (automatically set by podman/buildx) to handle architecture-specific differences:

- **x86_64 (amd64)**: Uses `x86_64` for AWS CLI, no suffix for OpenShift downloads
- **ARM64 (aarch64)**: Uses `aarch64` for AWS CLI, `-arm64` suffix for OpenShift downloads

Architecture variables are stored in temp files (`/tmp/aws_cli_arch`, `/tmp/oc_suffix`) during build and consumed by subsequent RUN commands.

### Tool Installation via Alternatives System

The container uses Linux alternatives system to manage multiple versions:

**AWS CLI**:
- Fedora RPM (`/usr/bin/aws`) - priority 10, family "fedora"
- Official AWS CLI v2 (`/opt/aws-cli-official/v2/current/bin/aws`) - priority 20, family "aws-official" (default)

**OpenShift CLI**:
- 7 versions installed to `/opt/openshift/{version}/oc`
- Priorities: 14-19 for versions 4.14-4.19, priority 100 for 4.20 (default)
- All downloaded from `https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable-{version}/`

### Critical URLs

- **AWS CLI**: `https://awscli.amazonaws.com/awscli-exe-linux-{arch}.zip`
- **OpenShift CLI**: `https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable-{version}/openshift-client-linux{suffix}.tar.gz`

## Testing Containers Locally

```bash
# Run with bash shell
podman run -it --entrypoint /bin/bash rosa-boundary:latest

# Verify tool versions
podman run --rm --entrypoint /bin/bash rosa-boundary:latest -c "aws --version && oc version --client"

# Check alternatives configuration
podman run --rm --entrypoint /bin/bash rosa-boundary:latest -c "alternatives --display aws && alternatives --display oc"
```

## Adding New OpenShift Versions

1. Add version to loop in Containerfile:58 (e.g., `4.21`)
2. Add alternatives registration with appropriate priority (e.g., priority 21 for 4.21)
3. Update highest version priority to 100 if it should be the new default
4. Update README.md version list

## Manifest List Structure

The `make manifest` target creates an OCI image index containing both architectures. Podman/Docker automatically selects the correct platform when pulling `rosa-boundary:latest`.

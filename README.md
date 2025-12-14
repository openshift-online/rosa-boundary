# ROSA Boundary Container

Multi-architecture container based on Fedora 43 for working with AWS and OpenShift clusters. Designed for AWS Fargate with ECS Exec support.

## Features

- **AWS CLI**: Both Fedora RPM and official AWS CLI v2 with alternatives support
- **OpenShift CLI**: Versions 4.14 through 4.20 from stable channels
- **ECS Exec Ready**: Designed for AWS Fargate with ECS Exec support
- **Multi-architecture**: Supports both x86_64 (amd64) and ARM64 (aarch64)

## Building

### Build all architectures and create manifest
```bash
make all
```

### Build specific architecture
```bash
make build-amd64   # Build x86_64 only
make build-arm64   # Build ARM64 only
```

### Create manifest list
```bash
make manifest      # Combines both architectures
```

### Clean up
```bash
make clean         # Remove all images and manifests
```

## Tool Management

### AWS CLI Alternatives

The container includes two AWS CLI versions managed with alternatives:

- **fedora** (priority 10): Fedora RPM package
- **aws-official** (priority 20): Official AWS CLI v2 (default)

```bash
# View current AWS CLI configuration
alternatives --display aws

# Switch to Fedora version
alternatives --set aws /usr/bin/aws

# Switch to official version
alternatives --set aws /opt/aws-cli-official/v2/current/bin/aws
```

### OpenShift CLI Versions

Seven OpenShift CLI versions are available (4.14-4.20), with 4.20 as the default:

```bash
# View available oc versions
alternatives --display oc

# Switch to a specific version
alternatives --set oc /opt/openshift/4.17/oc
alternatives --set oc /opt/openshift/4.19/oc
```

## Usage

### Running locally
```bash
# Run the container with overridden entrypoint
podman run -it --entrypoint /bin/bash rosa-boundary:latest

# Check tool versions
podman run --rm --entrypoint /bin/bash rosa-boundary:latest -c "aws --version && oc version --client"
```

### Fargate Deployment

This container is designed to run as an AWS Fargate task with ECS Exec for remote access:

1. Push to your container registry
2. Create Fargate task definition using this image (platform version 1.4.0+)
3. Enable ECS Exec on the task definition
4. Configure SSM permissions in task IAM role
5. Connect via `aws ecs execute-command`

The container uses `sleep infinity` as the entrypoint. ECS Exec automatically handles SSM agent setup - no manual installation needed.

## Image Details

- **Base**: Fedora 43
- **AWS CLI**: v2.32.16+ (official), v2.27.0 (Fedora RPM)
- **OpenShift CLI**: 4.14.x, 4.15.x, 4.16.x, 4.17.x, 4.18.x, 4.19.x, 4.20.x

## Architecture Support

The manifest list automatically selects the appropriate image for your platform:
- `linux/amd64` - x86_64 architecture
- `linux/arm64` - ARM64/aarch64 architecture (Graviton)

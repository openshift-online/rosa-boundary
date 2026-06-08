# SRE Investigation Environment

This is an ephemeral container for ROSA cluster investigation and AWS infrastructure troubleshooting.

## Container Information

**Purpose**: Secure SRE workspace with pre-configured AWS and OpenShift tooling
**Runtime**: AWS Fargate (ECS)
**Storage**: /home/sre is EFS-mounted and persists across container restarts

## Available Tools

### AWS CLI

Official AWS CLI v2 installed at `/opt/aws-cli-official/v2/current/bin/aws`, accessible as `aws`.

### OpenShift CLI (oc)

Multiple versions installed (4.14-4.20). Default: 4.20

**Switch versions at runtime**:
```bash
# Via environment variable at container start
export OC_VERSION=4.18

# Or manually switch
alternatives --set oc /opt/openshift/4.18/oc

# Verify version
oc version --client
```

**Available versions**: 4.14, 4.15, 4.16, 4.17, 4.18, 4.19, 4.20

### Claude Code

Installed via native installer. Configured to use Amazon Bedrock via IAM for authentication.

**Region detection**: Automatically detects the AWS region from ECS task metadata.
**Override region**: Set `AWS_REGION` environment variable if cross-region Bedrock access is needed.

## ROSA Cluster Context

<!-- Update this section with cluster-specific information -->

**Cluster Name**: [TODO: Fill in]
**AWS Account**: [TODO: Fill in]
**Region**: [TODO: Fill in]
**Version**: [TODO: Fill in]
**API Endpoint**: [TODO: Fill in]

**Authentication**:
```bash
# Login to cluster (adjust for your setup)
oc login --token=<token> --server=<api-endpoint>
```

## SRE Investigation Workflows

### Initial Assessment

1. **Verify cluster access**:
   ```bash
   oc whoami
   oc get nodes
   oc get clusterversion
   ```

2. **Check cluster health**:
   ```bash
   oc get co  # cluster operators
   oc get nodes -o wide
   oc adm top nodes
   ```

3. **Review recent events**:
   ```bash
   oc get events --all-namespaces --sort-by='.lastTimestamp' | tail -n 50
   ```

### Common ROSA Troubleshooting Commands

**Cluster Operators**:
```bash
# List all cluster operators and their status
oc get co

# Detailed status of degraded operator
oc describe co <operator-name>

# Check operator logs
oc logs -n openshift-<namespace> <pod-name>
```

**Node Investigation**:
```bash
# Node details
oc describe node <node-name>

# SSH to node (if debug pods enabled)
oc debug node/<node-name>

# Check node logs
oc adm node-logs <node-name>
oc adm node-logs <node-name> -u kubelet
oc adm node-logs <node-name> -u crio
```

**Pod Investigation**:
```bash
# Get pod details
oc describe pod <pod-name> -n <namespace>

# Check pod logs
oc logs <pod-name> -n <namespace>
oc logs <pod-name> -n <namespace> --previous  # previous container

# Get pod events
oc get events -n <namespace> --field-selector involvedObject.name=<pod-name>
```

**Network Debugging**:
```bash
# Test pod connectivity
oc run test-pod --image=registry.redhat.io/rhel8/support-tools --rm -it -- /bin/bash

# DNS testing
oc run -it --rm debug --image=registry.redhat.io/rhel8/support-tools --restart=Never -- nslookup kubernetes.default

# Service endpoints
oc get endpoints -n <namespace>
```

### Log Collection

**Application logs**:
```bash
# Collect logs to file in /home/sre (persists to EFS)
oc logs <pod-name> -n <namespace> > /home/sre/logs/<pod-name>.log

# Stream logs
oc logs -f <pod-name> -n <namespace>

# All pods in deployment
for pod in $(oc get pods -n <namespace> -l app=<label> -o name); do
  oc logs $pod -n <namespace> > /home/sre/logs/${pod}.log
done
```

### Must-Gather

Collect comprehensive cluster diagnostics:

```bash
# Standard must-gather
oc adm must-gather --dest-dir=/home/sre/must-gather/$(date +%Y%m%d-%H%M%S)

# Network-specific must-gather
oc adm must-gather --image=quay.io/openshift/origin-network-must-gather --dest-dir=/home/sre/must-gather/network-$(date +%Y%m%d-%H%M%S)

# Storage must-gather
oc adm must-gather --image=registry.redhat.io/ocs4/ocs-must-gather-rhel8 --dest-dir=/home/sre/must-gather/storage-$(date +%Y%m%d-%H%M%S)
```

**Important**: Must-gather outputs are large. 

### AWS Resource Inspection

**ROSA cluster resources**:
```bash
# List EC2 instances for cluster
aws ec2 describe-instances \
  --filters "Name=tag:api.openshift.com/name,Values=<cluster-name>" \
  --region <region>

# Check ELBs
aws elb describe-load-balancers --region <region> | grep <cluster-name>
aws elbv2 describe-load-balancers --region <region> | grep <cluster-name>

# VPC and subnets
aws ec2 describe-vpcs \
  --filters "Name=tag:Name,Values=<cluster-name>*" \
  --region <region>

# Security groups
aws ec2 describe-security-groups \
  --filters "Name=tag:Name,Values=*<cluster-name>*" \
  --region <region>
```

## Best Practices

### Preserving Evidence

1. **Store all investigation artifacts in /home/sre**:
   - Logs: `/home/sre/logs/`
   - Must-gathers: `/home/sre/must-gather/`
   - Scripts: `/home/sre/scripts/`
   - Notes: `/home/sre/notes/`

2. **Document steps in /home/sre/investigation.md**:
   ```bash
   echo "## $(date)" >> /home/sre/investigation.md
   echo "Checked cluster operators, found kube-apiserver degraded" >> /home/sre/investigation.md
   ```

### Security

- Never store credentials in /home/sre (use IAM roles)
- Use `oc whoami -t` tokens carefully (short-lived)

### Performance

- Use `--limit` and `--tail` flags for large log queries

## Additional Resources

- [ROSA Documentation](https://docs.openshift.com/rosa/)
- [OpenShift CLI Reference](https://docs.openshift.com/container-platform/latest/cli_reference/openshift_cli/getting-started-cli.html)
- [AWS CLI Reference](https://docs.aws.amazon.com/cli/)
- [Must-Gather Guide](https://docs.openshift.com/container-platform/latest/support/gathering-cluster-data.html)

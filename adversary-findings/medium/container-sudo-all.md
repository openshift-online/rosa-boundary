# M8: Container Grants Passwordless Sudo ALL

- **Severity**: Medium
- **Category**: Application — Container Privilege Escalation
- **File**: `Containerfile:66`

## Issue

The SRE user is granted `NOPASSWD: ALL` sudo access: `echo 'sre ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/sre`. This allows any user who connects via ECS Exec to escalate to root inside the container.

## Impact

A compromised SRE session or an SRE acting maliciously can escalate to root inside the container. While Fargate containers are ephemeral and network-isolated, root access enables modification of the entrypoint/cleanup scripts (bypassing S3 audit sync), installing additional tools, or attempting to pivot via the task role's IAM permissions. The task role credentials are available to any user in the container regardless of sudo, so the incremental risk is moderate.

## Recommendation

If root access is required for specific operations (e.g., `alternatives --set`), restrict sudo to specific commands:

```
sre ALL=(ALL) NOPASSWD: /usr/sbin/alternatives
```

The entrypoint already runs as root and handles alternatives switching, so the SRE user may not need sudo at all.

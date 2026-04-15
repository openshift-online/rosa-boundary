# L3: Example Script Uses assignPublicIp=ENABLED

- **Severity**: Low
- **Category**: Infrastructure — Network Exposure
- **File**: `deploy/regional/examples/launch_task.sh:62`

## Issue

The example launch script uses `assignPublicIp=ENABLED` when launching Fargate tasks. The production Lambda handler correctly uses `DISABLED`.

## Impact

If an operator copies this example script for production use, Fargate tasks would receive public IP addresses, exposing the SSM agent and container services to the internet. The example is in `examples/` and is not used by automation, but it sets a risky precedent.

## Recommendation

Change to `assignPublicIp=DISABLED` in the example script, or add a warning comment explaining the security implications.

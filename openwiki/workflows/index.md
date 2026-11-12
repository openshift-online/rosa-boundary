# Files

- [Investigation lifecycle](investigation-lifecycle.md) - Traces investigation workspace creation, session launch/handover, operator connection, timeout enforcement, garbage collection, and closing across the CLI, Lambda, ECS, and EFS, including how the create-investigation Lambda's own ZIP/container-image packaging fits into the trigger path.
- [Trusted Actions execution pipeline](trusted-actions-execution.md) - Traces a trusted action from CLI/API request (rta action run or any direct POST .../{action}/run) through persistence, worker-pool claiming, scope-based authorization, and cluster execution, to the always-written audit record and the polled result.

# CLI Workflow Flowcharts

These flows describe the named-profile CLI. Select an approved Boundary account and region using `--profile <name>` or `config use-profile <name>` before operating. See the [user access guide](runbooks/user-access-guide.md) and [investigation workflow](runbooks/investigation-workflow.md) for prerequisites, audit checks, and recovery. An investigation workspace can outlive multiple sessions; a Boundary session ID identifies an ECS task, **not** its ECS Exec/SSM connection.

```mermaid
flowchart TD
    PROFILE["config init / config use-profile<br/>Select named deployment profile"] --> AUTH["OIDC login<br/>browser PKCE or human-approved device flow"]
    AUTH --> CREATE{"Operation?"}
    CREATE -->|"investigation create &lt;cluster-id&gt;"| INVOKER["Assume Lambda invoker role with OIDC ID token"]
    CREATE -->|"session create &lt;cluster-id&gt;"| INVOKER
    INVOKER --> LAMBDA["Lambda validates identity, required groups and ABAC claim"]
    LAMBDA --> EFS["Create or reuse EFS investigation access point"]
    EFS -->|"create: skip task"| IDLE["Idle investigation workspace"]
    EFS -->|"start: launch"| TASK["Register task definition and launch ECS task"]
    TASK --> SRE["Assume temporary SRE role"]
    SRE --> WAIT["Wait for RUNNING, unless --no-wait"]
    WAIT --> CRED{"Waited and OCM enabled?"}
    CRED -->|Yes, by default| OCM["Fresh OCM approval and task-scoped credential injection"]
    CRED -->|No: --no-wait or --with-credentials none| READY["Report session ID; --no-wait warns credentials skipped"]
    OCM -->|Failure: warn with retry command| READY
    OCM --> READY
    READY -->|"default connection or session join &lt;session-id&gt;"| EXEC["ECS Exec ABAC check; session-manager-plugin shell"]
    EXEC --> EXIT["exit disconnects shell; ECS task keeps running"]
    EXIT --> STOP["session close &lt;session-id&gt; --wait"]
    STOP --> AUDIT["Verify CloudWatch logs, container sync and S3 evidence separately"]
    AUDIT --> PLAN["investigation close &lt;cluster-id&gt; &lt;investigation-id&gt; --dry-run"]
    PLAN --> CLOSE["Authorized SRE confirms request after all shells detach"]
    CLOSE --> VERIFY["Reaper waits for quiet and verifies backup before cleanup"]
    VERIFY --> IDLEDONE["EFS data remains; workspace no longer accessible via access point"]
```

The `session close --wait` result proves only STOPPED, not S3 sync; the investigation remains open. An attached shell blocks a new investigation close request, even the requester's own: disconnect and retry. A running task without a shell does not block acceptance. If a shell is observed after acceptance, the reaper waits without a new request. `--force` grants consent to stop tasks, not to interrupt shells or skip backup verification. A background reaper can stop a shell-less session at its configured timeout or any managed session at eight hours of task age; it does not replace explicit audit verification.

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
    WAIT --> CRED{"--with-credentials ocm?"}
    CRED -->|Yes| OCM["Fresh OCM approval and task-scoped credential injection"]
    CRED -->|No| READY["Report session ID"]
    OCM --> READY
    READY -->|"--connect or session join &lt;session-id&gt;"| EXEC["ECS Exec ABAC check; session-manager-plugin shell"]
    EXEC --> EXIT["exit disconnects shell; ECS task keeps running"]
    EXIT --> STOP["session close &lt;session-id&gt; --wait"]
    STOP --> AUDIT["Verify CloudWatch logs, container sync and S3 evidence separately"]
    AUDIT --> PLAN["investigation close &lt;cluster-id&gt; &lt;investigation-id&gt; --dry-run"]
    PLAN --> CLOSE["Creator confirms close; CLI rechecks plan and removes access point"]
    CLOSE --> IDLEDONE["EFS data remains; workspace no longer accessible via access point"]
```

The `session close --wait` result proves only STOPPED, not S3 sync; the investigation remains open. `investigation close` without `--force` refuses active or still-stopping sessions; with `--force`, it waits for STOPPED before deleting the access point. The CLI checks the creator's `oidc_sub` tag, but regional IAM does not enforce that owner boundary for other AWS clients. Creation racing with close remains possible. A background reaper stops sessions past their tagged deadline; it does not replace explicit audit verification.

# CLI Workflow Flowcharts

This document shows the end-to-end flows for common rosa-boundary CLI operations. All OIDC-authenticated paths require a valid Keycloak token; the two-step role assumption (invoker role → SRE ABAC role) is transparent to the user.

```mermaid
flowchart TD
    subgraph "Create Investigation & Start Task"
        CI["**rosa-boundary create-investigation**"]
        ST["**rosa-boundary start-task**"]

        CI --> AUTH
        ST --> AUTH

        AUTH["OIDC Auth\n(Keycloak PKCE browser flow)"]
        AUTH --> INVOKER["Assume Invoker Role\n(STS + OIDC token)"]
        INVOKER --> LAMBDA["Invoke Lambda"]
        LAMBDA --> VALIDATE["Lambda validates token\n& checks sre-team group"]
        VALIDATE --> SKIP{"skip_task?"}

        SKIP -->|"true\n(create-investigation)"| EFS_ONLY["Create EFS Access Point only"]
        SKIP -->|"false\n(start-task)"| EFS_TASK["Create EFS Access Point\n+ Task Definition\n+ ECS Task"]

        EFS_ONLY --> DONE1(["done"])

        EFS_TASK --> ABAC["Assume SRE ABAC Role"]
        ABAC --> WAIT["Wait for RUNNING state"]
        WAIT --> CONNECT{"--connect?"}

        CONNECT -->|"Yes"| JOIN["**rosa-boundary join-task**"]
        CONNECT -->|"No"| DONE2(["done"])

        JOIN --> RUNNING(["Task Running"])
    end

    subgraph "Attach to a Running Task"
        LT["**rosa-boundary list-tasks**"]
        LT --> VIEW["View running tasks\n(cluster, investigation, username)"]
        VIEW --> JT["**rosa-boundary join-task** &lt;task-id&gt;"]
        JT --> EXEC["ECS ExecuteCommand\n(ABAC: username tag must match caller)"]
        EXEC --> SMP["session-manager-plugin\n(process replacement via exec)"]
        SMP --> SHELL["Interactive Shell\n(/bin/bash as sre user)"]
        SHELL --> WORK["User works in container"]
        WORK --> EXIT["exit"]

        EXIT --> CLEANUP{"cleanup path"}
        CLEANUP -->|"stop only"| STOP["**rosa-boundary stop-task**\n(S3 sync on container exit)"]
        CLEANUP -->|"full teardown"| CLOSE["**rosa-boundary close-investigation**\nStop tasks + deregister task defs\n+ delete EFS access point"]

        STOP --> STOPPED(["Task Stopped"])
        CLOSE --> STOPPED
    end

    subgraph "Reaper Lambda (background)"
        EB["EventBridge\n(every 15 min)"]
        EB --> REAPER["reap-tasks Lambda\nList RUNNING tasks\nCheck 'deadline' tag"]
        REAPER --> EXPIRED{"deadline\npassed?"}
        EXPIRED -->|"Yes"| FORCE_STOP["ecs:StopTask\n(deadline exceeded)"]
        EXPIRED -->|"No"| SKIP_TASK["skip (check next task)"]
        FORCE_STOP --> STOPPED
    end

    RUNNING -.->|"task already running"| JT
```

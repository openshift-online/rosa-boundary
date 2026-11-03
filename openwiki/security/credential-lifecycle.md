---
type: security
title: Credential lifecycle and task-scoped state
description: Traces the short-lived OCM access-token handoff over ECS Exec and the task-side validation, isolated storage, cleanup, and audit-sync exclusions that contain credential state.
tags: [credentials, ocm, ecs-exec, isolation, security]
sources:
  - id: openwiki-source-f1bd1e0a9201f149b775a09c
    resource: repo://deploy/regional/ecs.tf
  - id: openwiki-source-e9906b078522ed0a08c64ff1
    resource: repo://entrypoint.sh
  - id: openwiki-source-d7354d29c32fc341220a6474
    resource: repo://internal/cmd/credentials_ocm.go
  - id: openwiki-source-b123c673a5b90ca2010ffe64
    resource: repo://internal/cmd/start_task.go
  - id: openwiki-source-eca4b2873500f4fd4beb595a
    resource: repo://internal/credentials/ocm/auth_test.go
  - id: openwiki-source-3850d0f3cd234df78e878ee6
    resource: repo://internal/credentials/ocm/auth.go
  - id: openwiki-source-21c70a2f73642c7cd6de7cc0
    resource: repo://internal/credentials/ocm/request.go
  - id: openwiki-source-716f140eaf7debf8f0d9c2e5
    resource: repo://internal/credentials/ocm/transfer_test.go
  - id: openwiki-source-d4da704e445d83f85e926aea
    resource: repo://internal/credentials/ocm/transfer.go
  - id: openwiki-source-6ec62643545a8bc315d38b31
    resource: repo://tests/shell/credential-helper.bats
  - id: openwiki-source-b696734e098932f3853bbb51
    resource: repo://tests/shell/entrypoint.bats
  - id: openwiki-source-c04443047d939230f4be0809
    resource: repo://utils/rosa-boundary-credential-helper
generated: { by: "openwiki/0.7.1", at: "2026-11-03T16:15:29.447Z" }
verified:
  - by: openwiki/0.7.1
    at: 2026-11-03T16:15:29.447Z
---

# Credential lifecycle and task-scoped state

OCM credentials are deliberately handled separately from the persistent investigation home. The CLI obtains a fresh OCM access token, transfers a minimal request over an ECS Exec session, and the in-container helper validates and installs an access-token-only OCM configuration. The OCM config and kubeconfig live on empty task-scoped volumes mounted over EFS-backed home paths; they are removed when the task ends and are excluded from the container's S3 audit sync.

## Acquisition and request preparation

`credentials configure ocm <task-id>` and `start-task --with-credentials ocm` both resolve to the shared `configureOCMForTask` helper, so both entrypoints follow the identical acquire -> transfer -> install sequence; `start-task` only runs it once the task is `RUNNING` and ECS Exec is confirmed ready, preserving as much of the fresh token's useful lifetime as possible.

The `Authenticator.Acquire` method selects between an authorization-code flow (`FlowAuthCode`) and a device flow (`FlowDevice`); any other value is rejected. Neither flow reads or writes a token cache. The default flow is derived from the existing `--use-device-code`/config preference, but both `credentials configure ocm` (`--auth-flow`) and `start-task` (`--ocm-auth-flow`) accept an OCM-only override that selects `auth-code` or `device` independently of that global default; `auth-code` requires a local callback listener, while `device` never opens a browser. The authorization-code implementation binds a local callback listener on `127.0.0.1:9998`, validates OAuth state with a constant-time comparison, uses PKCE, and exchanges the code for a token that is immediately reduced to its access token and expiry via `accessTokenOnly`, which also clears the SDK `oauth2.Token`'s `AccessToken` and `RefreshToken` fields. The device flow validates the device-authorization challenge (code, user code, verification URL, expiry) before polling for a token and applies the same reduction. When an `authstatus.Reporter` is attached (JSON output mode), `Acquire` emits provider-tagged `authenticated`/`device_authorization`/failure events on stderr instead of (or alongside) human status text; auth failures deliberately avoid wrapping the underlying OAuth error, since `oauth2.RetrieveError` can carry a raw token-endpoint response body.

Before transfer, `configureOCMForTask` calls `prepareCredentialTask`, which verifies the task is `RUNNING` and waits for the ECS Exec agent in the `rosa-boundary` container before any token is requested. Only after that readiness check does it acquire the token, resolve the OCM environment to an approved canonical API URL, and call `MarshalRequest` to serialize exactly `access_token` and `url`. The in-memory token's access-token field is cleared immediately after marshaling, and the serialized request buffer is zeroed byte-by-byte in a deferred cleanup once the ECS Exec transfer completes (success or failure).

<!-- openwiki: mermaid parse failed and this diagram was converted to a text fence so it does not break rendering. Fix the diagram source and restore the mermaid fence. Parser error: Parse error on line 11: ...); clear token field CLI->>ECS: Exec Expecting '()', 'SOLID_OPEN_ARROW', 'DOTTED_OPEN_ARROW', 'SOLID_ARROW', 'SOLID_ARROW_TOP', 'SOLID_ARROW_BOTTOM', 'STICK_ARROW_TOP', 'STICK_ARROW_BOTTOM', 'SOLID_ARROW_TOP_DOTTED', 'SOLID_ARROW_BOTTOM_DOTTED', 'STICK_ARROW_TOP_DOTTED', 'STICK_ARROW_BOTTOM_DOTTED', 'SOLID_ARROW_TOP_REVERSE', 'SOLID_ARROW_BOTTOM_REVERSE', 'STICK_ARROW_TO -->
```text
sequenceDiagram
    participant CLI as rosa-boundary CLI
    participant OCMAuth as OCM Authenticator
    participant ECS as ECS Exec Session
    participant Helper as credential-helper (task)

    CLI->>ECS: DescribeTask / WaitForExecAgent
    ECS-->>CLI: RUNNING, exec agent ready
    CLI->>OCMAuth: Acquire(flow)
    OCMAuth-->>CLI: access token, expiry
    CLI->>CLI: MarshalRequest(access_token, url); clear token field
    CLI->>ECS: ExecuteCommand(configure ocm)
    CLI->>Helper: send base64 request after ready marker
    Helper->>Helper: validate with ocm whoami, install candidate config
    Helper-->>CLI: success marker
    CLI->>CLI: close stdin, zero request buffer
```
*Acquire-to-install flow: the CLI never sends the credential payload until the task and Exec agent are confirmed ready, and clears both the token and the serialized request as soon as each is no longer needed.*

## Bounded ECS Exec protocol

The CLI's transfer protocol starts Session Manager with explicit streams and a timeout. For configuration, it waits for the helper's readiness marker before sending one base64-encoded request line, then keeps stdin open until the helper reports success. It closes stdin only after success so the task-side validation is not interrupted. Duplicate/out-of-order markers, early EOF, output over the configured maximum, cancellation, timeout, and unsuccessful plugin exit fail the transfer; protocol errors do not echo the credential payload.

The clear operation sends no credential payload and requires only the success marker. Both operations invoke fixed task-side commands rather than accepting arbitrary helper commands from the request.

## Task-side validation and persistence

The helper disables terminal echo, limits input to 65,536 bytes, uses a restrictive umask, and stores temporary request/candidate files inside the task-scoped OCM directory with mode `0600`. It accepts only an object with exactly the `access_token` and `url` keys and allows only the production, staging, or integration canonical API URL. It builds an OCM config with the fixed OCM client ID, `openid` scope, and token endpoint; no refresh or offline token is admitted. It runs `ocm whoami` against the candidate config with OCM environment overrides unset and discards both output streams, then moves the candidate into place only after validation succeeds. Temporary files are removed and terminal echo restored on exit.

Clear removes the installed OCM config, helper temporary files, and `/home/sre/.kube/config`, because kubeconfig may itself contain OCM-derived authentication state. The entrypoint fails closed if the two credential directories are missing mounts or are backed by NFS/EFS, initializes them with `sre` ownership and mode `0700`, and the audit sync excludes both directory trees.

## Verification

Go tests cover token reduction, OAuth state/PKCE, environment allowlisting, token-only request shape, and the framed transfer protocol including timeout/size/protocol failures without credential leakage. bats tests exercise the task helper's exact input schema, canonical URL checks, failed-validation rollback, file permissions, cleanup, and startup/S3 mount exclusions.

## Evidence-backed claims

- OCM acquisition supports fresh auth-code and device flows without a cache, selected by an explicit per-command override or a global device-code default; both flows reduce OAuth results to the access token and expiry while clearing the access/refresh fields on the SDK token object. [flow selection and authenticator](repo://internal/credentials/ocm/auth.go#L22-L88) · [access-token reduction](repo://internal/credentials/ocm/auth.go#L374-L382) · [auth tests](repo://internal/credentials/ocm/auth_test.go#L42-L103)
- Before any ECS Exec transfer, the CLI confirms the task is `RUNNING` and the Exec agent is ready, then serializes only the access token and approved URL, clears the in-memory token field, and zeroes the serialized request buffer after transfer completes. [task readiness check](repo://internal/cmd/credentials_ocm.go#L188-L209) · [token acquisition and request lifecycle](repo://internal/cmd/credentials_ocm.go#L130-L186) · [request shape and checks](repo://internal/credentials/ocm/request.go#L8-L23)
- Configure transfer waits for a readiness marker before sending the request, requires helper success, bounds output and time, and rejects malformed protocol completion. [stream protocol](repo://internal/credentials/ocm/transfer.go#L43-L200) · [protocol tests](repo://internal/credentials/ocm/transfer_test.go#L19-L129)
- The task helper accepts only bounded JSON with exactly access-token and URL fields at approved API URLs, validates a candidate using `ocm whoami` before replacing the active config, and clears OCM and kubeconfig state on request. [configure validation/install](repo://utils/rosa-boundary-credential-helper#L49-L141) · [clear operation](repo://utils/rosa-boundary-credential-helper#L143-L151) · [helper tests](repo://tests/shell/credential-helper.bats#L66-L162)
- Credential paths are separate empty ECS volumes overlaying the persistent EFS home, and startup rejects missing or NFS-backed overlays; S3 sync excludes both credential trees and does not follow symlinks. [task volume definitions](repo://deploy/regional/ecs.tf#L71-L93) · [mount guard](repo://entrypoint.sh#L46-L80) · [audit sync](repo://entrypoint.sh#L3-L34) · [entrypoint tests](repo://tests/shell/entrypoint.bats#L15-L47) · [sync exclusion tests](repo://tests/shell/entrypoint.bats#L88-L174)

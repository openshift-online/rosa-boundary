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
generated: { by: "opencode", at: "2026-10-05T17:08:59.471Z" }
verified:
  - by: openwiki/0.7.0
    at: 2026-10-05T19:18:44.075Z
---

# Credential lifecycle and task-scoped state

OCM credentials are deliberately handled separately from the persistent investigation home. The CLI obtains a fresh OCM access token, transfers a minimal request over an ECS Exec session, and the in-container helper validates and installs an access-token-only OCM configuration. The OCM config and kubeconfig live on empty task-scoped volumes mounted over EFS-backed home paths; they are removed when the task ends and are excluded from the container's S3 audit sync.

## Acquisition and request preparation

`credentials configure ocm <task-id>` supports an authorization-code flow or device flow. The authenticator does not read or write a token cache. The authorization-code implementation binds a local callback listener, checks OAuth state, uses PKCE, and reduces the OAuth response to its access token and expiry; the device flow likewise returns only that reduced value. `start-task --with-credentials ocm` uses the same process after the ECS task and Exec agent are ready, preserving as much of the fresh token's useful lifetime as possible.

Before transfer, the CLI resolves an OCM environment to an approved canonical API URL. It marshals exactly `access_token` and `url`, clears the in-memory token field, and zeroes the serialized request buffer after use. It verifies the task is `RUNNING` and waits for the ECS Exec agent in the `rosa-boundary` container before requesting the fixed helper configure command.

## Bounded ECS Exec protocol

The CLI's transfer protocol starts Session Manager with explicit streams and a timeout. For configuration, it waits for the helper's readiness marker before sending one base64-encoded request line, then keeps stdin open until the helper reports success. It closes stdin only after success so the task-side validation is not interrupted. Duplicate/out-of-order markers, early EOF, output over the configured maximum, cancellation, timeout, and unsuccessful plugin exit fail the transfer; protocol errors do not echo the credential payload.

The clear operation sends no credential payload and requires only the success marker. Both operations invoke fixed task-side commands rather than accepting arbitrary helper commands from the request.

## Task-side validation and persistence

The helper disables terminal echo, limits input to 65,536 bytes, uses a restrictive umask, and stores temporary request/candidate files inside the task-scoped OCM directory with mode `0600`. It accepts only an object with exactly the `access_token` and `url` keys and allows only the production, staging, or integration canonical API URL. It builds an OCM config with the fixed OCM client ID, `openid` scope, and token endpoint; no refresh or offline token is admitted. It runs `ocm whoami` against the candidate config with OCM environment overrides unset and discards both output streams, then moves the candidate into place only after validation succeeds. Temporary files are removed and terminal echo restored on exit.

Clear removes the installed OCM config, helper temporary files, and `/home/sre/.kube/config`, because kubeconfig may itself contain OCM-derived authentication state. The entrypoint fails closed if the two credential directories are missing mounts or are backed by NFS/EFS, initializes them with `sre` ownership and mode `0700`, and the audit sync excludes both directory trees.

## Verification

Go tests cover token reduction, OAuth state/PKCE, environment allowlisting, token-only request shape, and the framed transfer protocol including timeout/size/protocol failures without credential leakage. bats tests exercise the task helper's exact input schema, canonical URL checks, failed-validation rollback, file permissions, cleanup, and startup/S3 mount exclusions.

## Evidence-backed claims

- OCM acquisition supports auth-code and device flows without a cache; both reduce OAuth results to the access token and expiry while clearing access/refresh values from the SDK token object. [acquisition and flows](repo://internal/credentials/ocm/auth.go#L20-L65) · [access-token reduction](repo://internal/credentials/ocm/auth.go#L340-L347) · [auth tests](repo://internal/credentials/ocm/auth_test.go#L42-L103)
- The CLI validates task/Exec readiness, serializes only the access token and approved URL, clears the token field, zeroes the request bytes, then uses a fixed ECS Exec command. [task preparation and transfer](repo://internal/cmd/credentials_ocm.go#L120-L188) · [request shape and checks](repo://internal/credentials/ocm/request.go#L8-L23)
- Configure transfer waits for a readiness marker before sending the request, requires helper success, bounds output and time, and rejects malformed protocol completion. [stream protocol](repo://internal/credentials/ocm/transfer.go#L43-L200) · [protocol tests](repo://internal/credentials/ocm/transfer_test.go#L19-L129)
- The task helper accepts only bounded JSON with exactly access-token and URL fields at approved API URLs, validates a candidate using `ocm whoami` before replacing the active config, and clears OCM and kubeconfig state on request. [configure validation/install](repo://utils/rosa-boundary-credential-helper#L49-L141) · [clear operation](repo://utils/rosa-boundary-credential-helper#L143-L151) · [helper tests](repo://tests/shell/credential-helper.bats#L66-L162)
- Credential paths are separate empty ECS volumes overlaying the persistent EFS home, and startup rejects missing or NFS-backed overlays; S3 sync excludes both credential trees and does not follow symlinks. [task volume definitions](repo://deploy/regional/ecs.tf#L71-L93) · [mount guard](repo://entrypoint.sh#L46-L80) · [audit sync](repo://entrypoint.sh#L3-L34) · [entrypoint tests](repo://tests/shell/entrypoint.bats#L15-L47) · [sync exclusion tests](repo://tests/shell/entrypoint.bats#L88-L174)

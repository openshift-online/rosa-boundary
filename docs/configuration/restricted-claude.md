# Restricted-scope Claude in Boundary

`boundary-claude` adds an optional OpenAPPA guardrail to the existing investigation
container. It uses the same Claude Code binary, Bedrock configuration and local
SRE tools. It does not change human shell access, IAM, cluster authorization,
credential configuration, the laptop CLI, Lambda or Trusted Actions.

## Use

Inside an investigation shell, as the non-root `sre` user:

```sh
boundary-claude "Investigate why the ingress operator is degraded"
boundary-claude --print "Summarize the local investigation notes"
```

The only options are `--help` and `-p`/`--print`, plus an optional prompt. The
launcher intentionally does not forward arbitrary Claude arguments. There is no
public-scope switch, custom configuration, model override, delegation or resume
flag. Use ordinary `claude` for work outside this guarded profile; it remains
explicitly unprotected by this integration.

## Policy

Every guarded session starts with audience `internal`, a conservative symbolic
restriction for operational information. It is **not** a membership lookup or a
claim that every employee may read every customer's data.

The policy declares `WebFetch` and `WebSearch` as public sinks. Both are denied
even before the first evidence read: the URL or query could contain restricted
information. There is no human approval authority, model classifier, sanitizer
or public-declassification route. Do public documentation research in a separate
session without customer information.

The declared local tools are Bash, Read, Write, Edit, Glob, Grep, TodoWrite and
AskUserQuestion. APPA does not grant native Claude permissions or bypass service
authorization. All other tools lack a contract and are refused before execution.

Bash itself is allowed with its native permissions and is **not** restricted from
reaching the network. Gating egress by matching the command string was considered
and rejected: APPA sees only the command text, so a glob cannot distinguish an
exfiltrating `curl` from a legitimate internal `curl http://metrics`, nor a `curl`
binary from the word `curl` in a `grep` argument. Such a rule is both trivially
bypassable (base64, interpreters, write-then-run) and breaks real investigation.
Egress is therefore a network-layer concern (see [Boundaries](#boundaries)).
The initial launcher disables MCP connections, skills and delegation rather than
assuming unknown connectors or children are covered. New tool integrations need
reviewed source/sink contracts and tests before enabling them.

## Managed launch and storage

- OpenAPPA is pinned in `Containerfile`, downloaded with published SHA256
  verification and copied into the image. Nothing is downloaded or installed
  when starting an investigation.
- The policy and generated, version-matched hook settings live in
  `/etc/rosa-boundary/openappa/`. They are supplied explicitly; the launcher does
  not edit existing EFS-backed `.claude` settings or rely on no-clobber skeleton
  updates. User/project **settings** are not loaded in guarded mode; their broad
  tool permissions cannot override this profile. This is not a promise to mediate
  every implicit instruction/context read.
- The launcher starts the image's native Claude executable with `APPA_GATE=1`
  and the complete APPA lifecycle hooks. APPA 0.40.1's upstream `protected-launch`
  injects `--messaging-socket-path`, which Boundary's Claude 2.1.199 does not
  support. This deliberately narrower fresh-session profile does not need its
  peer messaging, delegation or resume tracking. Ordinary `claude` is unchanged.
- The SessionStart hook lazily starts a loopback runtime at `127.0.0.1:8787`, with
  complete call/result/failure/turn hooks and upstream timeout budgets. A failed
  preflight/runtime blocks the guarded flow; no plain-Claude fallback starts.
- SQLite state and runtime diagnostics live in the mode-0700, `sre`-owned
  `/var/lib/rosa-boundary/openappa/` on the task-local container filesystem, not
  the EFS home. APPA uses SQLite WAL; do not relocate its live database to EFS.
  A terminal disconnect does not stop the task/runtime. State disappears with
  task replacement and is not included in the existing home-directory S3 sync.
- This small profile exposes fresh launches only, not cross-task conversation
  restoration. Do not import old conversations expecting historical labels to
  be reconstructed. All sessions opened by this policy start restricted; no
  policy path makes them public. There is no new immutable audit stream.
- APPA diagnostic reporting is disabled. The launcher disables OTEL export and
  preserves existing Bedrock model/IAM configuration; no provider key or shared
  credential is added. Existing ECS Exec/model logging still has its own scope.

## Boundaries

This controls the declared Claude tool boundaries, **not all network traffic**.
An approved Bash command or CLI can perform arbitrary HTTP requests or publish
data; this policy does not parse shell code, classify destinations or enforce
egress. Model-provider requests, final prose, implicit/pre-hook reads, host/plugin
side effects and manually entered commands are not comprehensively mediated.

There is currently **no task-level egress allowlist**: the Fargate security group
in `deploy/regional/ecs.tf` permits all outbound traffic (`0.0.0.0/0`). A
default-deny egress allowlist (Bedrock plus approved internal services) is the
only control that actually confines exfiltration regardless of how a command is
invoked, and it is a **separate, not-yet-implemented requirement** — not a
protection this policy provides or assumes. Until it exists, treat this profile
as reducing the assistant's *autonomous* public-web reach (WebFetch/WebSearch),
not as an exfiltration boundary.

The existing `sre` user has sudo and equivalent ungated tools. Image-owned files
and a loopback hook endpoint are not an anti-compromise isolation boundary. Keep
existing authorization, credential mounts and audits; do not claim this makes
Boundary exfiltration-proof, customer-ACL-aware or newly compliance-authorized.

## Verify and troubleshoot

`make test-github-dl` includes offline packaging, generated-hook, policy-shape and
launcher tests in `build/test_openappa.py`. Real policy replay is optional locally:

```sh
APPA_BIN=/path/to/pinned/appa python3 -m pytest build/test_openappa.py
```

With the image's binary, the policy can be checked without a model or tool call:

```sh
appa describe --config /etc/rosa-boundary/openappa/appa.toml --check
```

The opt-in real-harness check uses only a local scripted model endpoint and dummy
credentials. Set both paths to verified copies of the versions pinned in the image:

```sh
APPA_BIN=/path/to/appa CLAUDE_BIN=/path/to/claude \
  python3 -m pytest tests/openappa/test_claude_gate.py
```

It checks actual evidence reads, APPA audience denials for WebFetch/WebSearch and
an allowed local write. It does not use a provider account or paid model. It is
not an AWS/ECS Exec or complete network-confinement test.

Successful configuration validation does not prove tool discovery, hook execution,
Claude-version compatibility, Fargate behavior or deployed audit delivery. Verify
the pinned Claude version with a deterministic local model fixture before relying
on a new APPA pin, then use the separately approved personal-dev workflow for
Fargate assertions. Never add bypass permissions to make that check green.

If startup fails, check the packaged configuration, executable and local state
ownership. Runtime diagnostics are in the local state directory; treat them as
sensitive. The human shell remains available. Changes to the image require new
tasks through the existing reviewed delivery path; running tasks are not updated.

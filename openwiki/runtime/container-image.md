---
type: runtime
title: Container image and task runtime
description: Explains the multi-architecture image build and the Fargate container's initialization, privilege boundary, optional kube-proxy, and shutdown audit behavior.
tags: [container, build, runtime, fargate, multi-architecture]
sources:
  - id: openwiki-source-0c8fbb0cb792daa3e3dfb497
    resource: repo://build/sre_tools.py
  - id: openwiki-source-d2ae434eb1428f3dfb4125f1
    resource: repo://build/verify_sre_tools.py
  - id: openwiki-source-8ea12a05c67ed54e49e49437
    resource: repo://Containerfile
  - id: openwiki-source-f1bd1e0a9201f149b775a09c
    resource: repo://deploy/regional/ecs.tf
  - id: openwiki-source-e9906b078522ed0a08c64ff1
    resource: repo://entrypoint.sh
  - id: openwiki-source-012f2c78e3b1446dfc35803f
    resource: repo://Makefile
  - id: openwiki-source-b696734e098932f3853bbb51
    resource: repo://tests/shell/entrypoint.bats
generated: { by: "opencode", at: "2026-11-13T18:18:24.408Z" }
verified:
  - by: openwiki/0.7.0
    at: 2026-11-13T18:18:24.408Z
---

# Container image and task runtime

The image built from `Containerfile` is the operator environment run by ECS Fargate for ephemeral SRE investigations. It is based on a digest-pinned UBI 9 image and built from separate tool/download stages; only the final stage is shipped. The final image includes the SRE command-line toolchain, Claude Code, tmux, shell setup, the OCM credential helper, and the entrypoint. As the `Containerfile`'s own header documents, SREs connect to a running task via SSM/ECS Exec as the non-root `sre` user, never as root; the entrypoint itself stays root only for the privileged setup it needs and then drops the requested workload to `sre` (see [Container startup and workload](#container-startup-and-workload) and `entrypoint.sh` for that runtime behavior).

## Build and architecture selection

The root Makefile's `build-amd64` and `build-arm64` targets each invoke `podman build` with `--platform linux/amd64` / `linux/arm64` against the root `Containerfile`, forwarding GitHub credentials as build secrets (`GITHUB_TOKEN` and the three `GITHUB_APP_*` values) only when those environment variables are set. The `manifest` target depends on `build` (both architecture builds) and then uses `podman manifest create`/`add` to combine the two per-architecture tags (`rosa-boundary:latest-amd64`, `rosa-boundary:latest-arm64`) into one manifest list; `all` runs `build` followed by `manifest`. `verify-image-tools` separately runs the already-built image's own filesystem, unprivileged and network-isolated, through the embedded tool-inventory check rather than rebuilding anything.

The Containerfile pins its UBI 9 base image by digest (`ARG BASE_IMAGE=registry.access.redhat.com/ubi9/ubi@sha256:...`), a pin that Renovate keeps current rather than tracking a floating tag, and defines five stages — `tools-base`, `sre-tools`, `claude-builder`, `tmux-builder`, and a `final` production stage that alone is shipped. `tools-base` installs `github_dl` (`build/github_dl.py`) and `platform_convert` (`build/platforms.sh`) and asserts that `TARGETARCH` matches what `platform_convert` reports for the architecture Podman actually built for, failing the build rather than mislabeling a host-architecture binary. `platform_convert` resolves `@@PLATFORM@@` placeholders from the real build platform: it reads `uname -m` (`x86_64`/`amd64` or `aarch64`/`arm64`) and substitutes a caller-supplied ARM or x86 string into either a positional argument or a file in place. Per the Containerfile's own header comment, only `sre-tools` and `claude-builder` depend on `tools-base`; `tmux-builder` depends solely on `BASE_IMAGE`. With BuildKit or `podman build --layers`, stages 2 through 5 (`sre-tools`, `claude-builder`, `tmux-builder`, and `final`) therefore run in parallel once their respective dependencies complete, instead of strictly serializing all five stages.

The `sre-tools` stage installs `ocm` (the OCM CLI), `ocm-backplane`, `osdctl`, `yq`, `oc`, and the AWS CLI, each via a pinned `ARG …_VERSION` consumed by `build/sre_tools.py`, a fixed-source installer kept separate from `github_dl`'s own verification path. The build secrets mounted into each `sre_tools.py` invocation (`GITHUB_TOKEN` and the three `rosa-boundary-github-app/GITHUB_APP_*` values) feed straight through to `github_dl`, which prefers a GitHub App token when the three app secrets are present and otherwise falls back to the bare `GITHUB_TOKEN`, so the GitHub-hosted downloads can authenticate either way. For the four GitHub-hosted CLIs (`ocm`, `ocm-backplane`, `osdctl`, `yq`), `sre_tools.py` shells out to `github_dl download --exact_asset <arch-specific-name>` so GitHub credentials and checksum verification stay in `github_dl`; `aws` and `oc` are fetched directly instead: AWS CLI verifies its detached publisher signature with a pinned signer, while the OpenShift release verifies its signed checksum manifest with a pinned Red Hat signer. Every tool install is followed by a separate `--network=none` `--validate-installed` run of `sre_tools.py` that re-derives the installed binary's actual version and architecture from its own output and compares them against the pinned, recorded values, so verification never shares a build step with network access; the stage ends by running `build/verify_sre_tools.py combine` to merge the six per-tool inventory records into one `/opt/tool-versions.json`. `claude-builder` downloads Claude Code the same way, directly through `github_dl download --platform ... --checksum_file SHASUMS256.txt`, which lists the release's assets, resolves the matching SHA256 record, downloads that exact asset, and hashes the bytes before accepting them. `tmux-builder` is independent of `tools-base`: it downloads a pinned tmux source tarball, checks it against a hard-coded SHA256 before extracting or compiling it, and builds tmux from source because UBI 9's repositories do not carry it.

The `final` stage installs runtime packages, copies only the selected outputs from `sre-tools` (including the combined `tool-versions.json`), `claude-builder`, and `tmux-builder` (never the builder stages' secrets or verification tooling), registers the AWS CLI through `alternatives`, generates shell completions, creates the non-root `sre` user with passwordless `sudo`, and copies `skel/sre/` to `/etc/skel-sre` for the entrypoint to seed `/home/sre` at first run. A final `--network=none` bind-mounted `RUN` runs `build/verify_sre_tools.py runtime` as `sre` to re-verify the shipped filesystem offline — checking ELF architecture, pinned versions, signer identities, and the absence of removed tools — before the image is tagged, and `ENTRYPOINT`/`CMD` wire the image to `entrypoint.sh` with a default command of `sleep infinity`. (The entrypoint also contains an `OC_VERSION`-driven `alternatives --set oc` switch over per-version binaries under `/opt/openshift/<version>/oc`; the current `final` stage installs only the single pinned `oc` build directly at `/usr/local/bin/oc` and does not populate that directory, so this switch is presently a no-op that falls through to its "using default" warning unless `/opt/openshift` is populated some other way.)

Trusted Actions, a separate component under `components/trusted-actions/`, ships its own `Containerfile` and Make targets (a Go build image layered onto a minimal runtime image) that this page and the root Makefile do not build or cover; see that component's own build tooling for details.

## Container startup and workload

The entrypoint sets root's `HOME` to `/root` to avoid root-created files in the persistent EFS home and installs traps for SIGTERM, SIGINT, and SIGHUP. Before any workload is started, it checks that `/home/sre/.config/ocm` and `/home/sre/.kube` are mounted and not backed by NFS/EFS, then creates those directories with `sre` ownership and mode `0700`. It can switch the OpenShift CLI alternative, write a localhost kubeconfig for an enabled kube-proxy sidecar, and copy skeleton files without overwriting existing user files.

The Terraform task definition can include a `kube-proxy` sidecar. It writes the cluster kubeconfig to temporary storage, starts `oc proxy` on loopback, and exposes a health check; the main container depends on that health check when the option is enabled. Claude Code's Bedrock environment and default model are set on the task definition; the entrypoint can discover `AWS_REGION` from ECS task metadata and otherwise uses its configured fallback.

After setup, the entrypoint backgrounds the requested command (default `sleep infinity`) as `sre` and waits so the root shell can handle signals. On normal exit and trapped shutdown it attempts an S3 sync of `/home/sre`, bounded by `SYNC_TIMEOUT`; sync excludes OCM and kubeconfig state and uses `--no-follow-symlinks`. This audit copy is best-effort: a missing destination warns, and a failed or timed-out sync does not block the container's exit indefinitely.

<!-- openwiki: mermaid parse failed and this diagram was converted to a text fence so it does not break rendering. Fix the diagram source and restore the mermaid fence. Parser error: Heuristic: an unescaped angle bracket inside a label breaks rendering; rephrase the label. -->
```text
flowchart TD
    Start["entrypoint starts as root\n(HOME=/root, traps installed)"]
    OcVersion{"OC_VERSION set and installed?"}
    SwitchOc["alternatives --set oc"]
    VerifyMounts{"OCM/.kube paths are\ntask-scoped, non-EFS mounts?"}
    FailClosed["print error, exit nonzero\n(no workload started)"]
    InitMounts["mkdir/chown sre/chmod 0700\nfor OCM and kube paths"]
    KubeProxy{"KUBE_PROXY_PORT set?"}
    WriteKubeconfig["write localhost kubeconfig"]
    CopySkel["copy /etc/skel-sre to\n/home/sre (no clobber)"]
    DropPriv["runuser -u sre -- COMMAND &\nCHILD_PID=$!"]
    WaitChild["wait CHILD_PID\n(root shell blocks here)"]
    Signal["SIGTERM/SIGINT/SIGHUP\ntrapped -> cleanup()"]
    NormalExit["child exits normally"]
    SyncS3["sync_to_s3\n(bounded by SYNC_TIMEOUT,\nexcludes OCM/.kube, no-follow-symlinks)"]
    KillChild["kill -TERM CHILD_PID"]
    Exit["exit with child's exit code\n(or 0 from signal path)"]

    Start --> OcVersion
    OcVersion -- yes --> SwitchOc --> VerifyMounts
    OcVersion -- no --> VerifyMounts
    VerifyMounts -- no --> FailClosed
    VerifyMounts -- yes --> InitMounts --> KubeProxy
    KubeProxy -- yes --> WriteKubeconfig --> CopySkel
    KubeProxy -- no --> CopySkel
    CopySkel --> DropPriv --> WaitChild
    WaitChild -- normal exit --> NormalExit --> SyncS3 --> Exit
    Signal -.-> SyncS3
    SyncS3 -.-> KillChild -.-> Exit
```
*Entrypoint control flow: privileged setup and mount verification happen before the privilege drop; the root shell then blocks on `wait` so a trapped signal or the workload's own exit both reach the same bounded S3 sync before the container exits.*

## Tests and operational linkage

The bats suite sources the entrypoint without running it, checks that startup rejects missing or EFS-backed credential overlays, and verifies both explicit and auto-generated S3 destinations retain credential exclusions and symlink protections. ECS task-definition source supplies the mount paths, stop timeout, Bedrock variables, and optional sidecar behavior consumed by the script.

## Related pages

- [System overview and boundaries](../architecture/system-overview.md) places the container within the CLI/Lambda/ECS request flow.
- [Trusted Actions overview](../architecture/trusted-actions-overview.md) describes that component's own, much simpler Containerfile and build, which this page does not cover.
- [ROSA Boundary auditing and logging flows](../operations/audit-and-logging.md) covers the S3 audit escrow alongside CloudWatch and CloudTrail evidence.
- [Verification and testing](../testing/verification.md) describes how the bats suite fits the broader test strategy.
- [Investigation lifecycle](../workflows/investigation-lifecycle.md) covers how a task reaches this container and how it is torn down.

## Evidence-backed claims

- The root Makefile's `build-amd64`/`build-arm64` targets build separate AMD64 and ARM64 images with Podman and the `manifest` target assembles their tags into one manifest list; the Containerfile uses a digest-pinned, Renovate-managed UBI 9 base and five stages (`tools-base`, `sre-tools`, `claude-builder`, `tmux-builder`, `final`) where only `final` ships, and only `final`'s dependency on the other three builder stages' outputs forces it to wait — `sre-tools`/`claude-builder` (via `tools-base`) and `tmux-builder` (via `BASE_IMAGE` directly) can otherwise build in parallel under BuildKit/`podman build --layers`. [build-amd64/build-arm64](repo://Makefile#L30-L50) · [manifest target](repo://Makefile#L67-L75) · [base and tools-base stage](repo://Containerfile#L1-L23) · [final stage](repo://Containerfile#L191-L274)
- `sre_tools.py` (run from the `sre-tools` stage with `GITHUB_TOKEN`/GitHub App secrets mounted) calls `github_dl` to fetch exact, architecture-named release assets for GitHub-hosted CLIs (`ocm`, `ocm-backplane`, `osdctl`, `yq`) while verifying AWS CLI with a detached signature and `oc` against a signed checksum manifest; `github_dl` itself prefers a GitHub App token when all three app secrets are present and otherwise falls back to `GITHUB_TOKEN`, and matches a checksum record to the requested asset and hashes the downloaded bytes before accepting them. `verify_sre_tools.py` combines per-tool inventories at build time and re-verifies the shipped filesystem offline as `sre` before tagging. Claude Code is fetched the same way via `github_dl` in `claude-builder`, and tmux's source tarball is SHA256-checked before compilation in the independent `tmux-builder` stage. [sre-tools stage](repo://Containerfile#L52-L121) · [claude-builder/tmux-builder stages](repo://Containerfile#L123-L188) · [final-stage runtime verification](repo://Containerfile#L263-L268) · [github_dl asset/checksum matching](repo://build/github_dl.py#L225-L271) · [github_dl auth priority](repo://build/github_dl.py#L1-L58) · [verify_sre_tools runtime/combine](repo://build/verify_sre_tools.py#L54-L95)
- The entrypoint rejects credential paths that are missing or EFS-backed, prepares them as mode `0700`, then runs the requested workload as `sre` while the root shell retains signal handling. [mount verification/setup](repo://entrypoint.sh#L46-L80) · [workload process and traps](repo://entrypoint.sh#L82-L93) · [drop privilege and wait](repo://entrypoint.sh#L167-L183)
- Both normal exit and signal cleanup use a bounded S3 sync that excludes OCM and kubeconfig paths and disables symlink following; bats tests assert those protections. [sync and cleanup](repo://entrypoint.sh#L3-L44) · [sync tests](repo://tests/shell/entrypoint.bats#L88-L134) · [exit-path test](repo://tests/shell/entrypoint.bats#L176-L204)
- The ECS task definition configures a persistent home with task-scoped OCM/kubeconfig overlays and can gate startup on a healthy loopback kube-proxy sidecar. [task mounts and dependency](repo://deploy/regional/ecs.tf#L103-L159) · [proxy sidecar](repo://deploy/regional/ecs.tf#L175-L224)

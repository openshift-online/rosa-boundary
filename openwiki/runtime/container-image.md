---
type: runtime
title: Container image and task runtime
description: Explains the multi-architecture image build and the Fargate container's initialization, privilege boundary, optional kube-proxy, and shutdown audit behavior.
tags: [container, build, runtime, fargate, multi-architecture]
sources:
  - id: openwiki-source-2188e4afa97798d92e1476cf
    resource: repo://build/github_dl.py
  - id: openwiki-source-5bbd0f06f9c4be6fd19a6126
    resource: repo://build/platforms.sh
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
generated: { by: "opencode", at: "2026-10-05T17:08:59.471Z" }
verified:
  - by: openwiki/0.7.0
    at: 2026-10-05T19:18:44.075Z
---

# Container image and task runtime

The image built from `Containerfile` is the operator environment run by ECS Fargate. It is based on a digest-pinned UBI 9 image and built from separate tool/download stages; only the final stage is shipped. The final image includes the SRE command-line toolchain, Claude Code, tmux, shell setup, the OCM credential helper, and the entrypoint. ECS Exec launches an interactive login as the non-root `sre` user, while the entrypoint remains root only for initialization and then drops the requested workload to `sre`.

## Build and architecture selection

The root Makefile builds AMD64 and ARM64 variants with Podman and can assemble them into one manifest list. `platform_convert` resolves architecture placeholders from the target build platform (`x86_64`/`aarch64`); the Containerfile uses this for the backplane-tools and Claude release assets. The backplane-tools installer and Claude Code are downloaded in independent builder stages through `github_dl`, which locates release assets and validates the selected asset against a published checksum. GitHub credentials are passed through build secret mounts. tmux is built separately from a pinned source tarball and checked against its SHA256 before compilation.

The final stage installs runtime packages, copies only selected outputs from the builder stages, sets up alternatives and shell completions, creates the `sre` user, and places the skeleton home under `/etc/skel-sre` for first-run initialization. OpenShift client versions are installed under `/opt/openshift` and selected by the entrypoint when `OC_VERSION` names an installed version.

## Container startup and workload

The entrypoint sets root's `HOME` to `/root` to avoid root-created files in the persistent EFS home and installs traps for SIGTERM, SIGINT, and SIGHUP. Before any workload is started, it checks that `/home/sre/.config/ocm` and `/home/sre/.kube` are mounted and not backed by NFS/EFS, then creates those directories with `sre` ownership and mode `0700`. It can switch the OpenShift CLI alternative, write a localhost kubeconfig for an enabled kube-proxy sidecar, and copy skeleton files without overwriting existing user files.

The Terraform task definition can include a `kube-proxy` sidecar. It writes the cluster kubeconfig to temporary storage, starts `oc proxy` on loopback, and exposes a health check; the main container depends on that health check when the option is enabled. Claude Code's Bedrock environment and default model are set on the task definition; the entrypoint can discover `AWS_REGION` from ECS task metadata and otherwise uses its configured fallback.

After setup, the entrypoint backgrounds the requested command (default `sleep infinity`) as `sre` and waits so the root shell can handle signals. On normal exit and trapped shutdown it attempts an S3 sync of `/home/sre`, bounded by `SYNC_TIMEOUT`; sync excludes OCM and kubeconfig state and uses `--no-follow-symlinks`. This audit copy is best-effort: a missing destination warns, and a failed or timed-out sync does not block the container's exit indefinitely.

## Tests and operational linkage

The bats suite sources the entrypoint without running it, checks that startup rejects missing or EFS-backed credential overlays, and verifies both explicit and auto-generated S3 destinations retain credential exclusions and symlink protections. ECS task-definition source supplies the mount paths, stop timeout, Bedrock variables, and optional sidecar behavior consumed by the script.

## Evidence-backed claims

- The root Makefile builds separate AMD64 and ARM64 images and assembles their tags into a manifest; the Containerfile uses a pinned UBI 9 digest and builder stages feeding one final image. [build targets](repo://Makefile#L24-L59) · [base and stages](repo://Containerfile#L1-L23) · [final stage](repo://Containerfile#L167-L244)
- The image build resolves architecture-specific assets and validates GitHub release assets against published checksums using secret-mounted credentials; tmux source is SHA256 checked before compile. [platform resolution](repo://build/platforms.sh#L115-L140) · [GitHub checksum verification](repo://build/github_dl.py#L187-L235) · [Containerfile download stages](repo://Containerfile#L47-L124) · [tmux build](repo://Containerfile#L127-L164)
- The entrypoint rejects credential paths that are missing or EFS-backed, prepares them as mode `0700`, then runs the requested workload as `sre` while the root shell retains signal handling. [mount verification/setup](repo://entrypoint.sh#L46-L80) · [workload process and traps](repo://entrypoint.sh#L82-L93) · [drop privilege and wait](repo://entrypoint.sh#L167-L183)
- Both normal exit and signal cleanup use a bounded S3 sync that excludes OCM and kubeconfig paths and disables symlink following; bats tests assert those protections. [sync and cleanup](repo://entrypoint.sh#L3-L44) · [sync tests](repo://tests/shell/entrypoint.bats#L88-L134) · [exit-path test](repo://tests/shell/entrypoint.bats#L176-L204)
- The ECS task definition configures a persistent home with task-scoped OCM/kubeconfig overlays and can gate startup on a healthy loopback kube-proxy sidecar. [task mounts and dependency](repo://deploy/regional/ecs.tf#L103-L159) · [proxy sidecar](repo://deploy/regional/ecs.tf#L175-L224)

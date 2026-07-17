# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  ROSA Boundary — Multi-Stage Multi-Arch Container Build                    ║
# ║                                                                            ║
# ║  Produces an ephemeral SRE investigation container for AWS ECS Fargate.    ║
# ║  SREs connect via SSM/ECS Exec as the non-root 'sre' user.                ║
# ║                                                                            ║
# ║  Stages:                                                                   ║
# ║    tools-base       → shared build environment (curl, python3, helpers)    ║
# ║    backplane-tools  → SRE CLI tools via backplane-tools install all        ║
# ║    oc-versions      → OC 4.14-4.20 with checksum verification             ║
# ║    claude-builder   → Claude Code from GitHub Releases + SHASUMS256.txt    ║
# ║    tmux-builder     → tmux binary from CentOS Stream 9 (not in UBI9)      ║
# ║    final            → production image (only this stage ships)             ║
# ║                                                                            ║
# ║  Stages 2-5 run in parallel — no interdependencies.                        ║
# ║  All GitHub API calls are authenticated via --mount=type=secret.           ║
# ║  All externally downloaded binaries are checksum-verified.                  ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# ──────────────────────────────────────────────────────────────────────────────
# Base image — pinned by digest for reproducibility. Renovate updates this.
# ──────────────────────────────────────────────────────────────────────────────
ARG BASE_IMAGE=registry.access.redhat.com/ubi9/ubi@sha256:bcfca170da4fe08c0b70aa76ca4ee63f0e724db1574712cbc6c6a77fea6b21dc


# ══════════════════════════════════════════════════════════════════════════════
# Stage 1: tools-base
# Shared build environment for all builder stages. Installs download tools,
# Python (for github_dl.py), and the platform_convert + github_dl helpers.
# ══════════════════════════════════════════════════════════════════════════════
FROM ${BASE_IMAGE} AS tools-base

# curl-minimal is already in the UBI9 base image — do not install curl
RUN dnf install --assumeyes --nodocs \
        gzip \
        jq \
        python3 \
        python3-pip \
        tar \
        unzip \
    && dnf clean all \
    && rm --recursive --force /var/cache/yum

# requests: required by github_dl.py for authenticated GitHub API calls
RUN python3 -m pip install --no-cache-dir requests

COPY build/platforms.sh /usr/local/bin/platform_convert
COPY build/github_dl.py /usr/local/bin/github_dl
RUN chmod +x /usr/local/bin/platform_convert /usr/local/bin/github_dl


# ══════════════════════════════════════════════════════════════════════════════
# Stage 2: backplane-tools
# Downloads the backplane-tools binary, then runs `backplane-tools install all`
# to fetch the full SRE CLI toolchain: oc, ocm, ocm-backplane, osdctl,
# ocm-addons, yq, and AWS CLI v2.
# Output: /opt/ contains all tool binaries and AWS CLI dist.
# ══════════════════════════════════════════════════════════════════════════════
FROM tools-base AS backplane-tools

ARG BACKPLANE_TOOLS_VERSION="tags/v1.4.0"
ENV BACKPLANE_TOOLS_URL_SLUG="openshift/backplane-tools"
ENV BACKPLANE_TOOLS_URL="https://api.github.com/repos/${BACKPLANE_TOOLS_URL_SLUG}/releases/${BACKPLANE_TOOLS_VERSION}"
ENV BACKPLANE_TOOLS_CHECKSUM_FILE="checksums.txt"
ENV BACKPLANE_TOOLS_CHECKSUM_ALGORITHM="sha256"
ENV BACKPLANE_TOOLS_PLATFORM_PREFIX="linux_"
ENV BACKPLANE_BIN_DIR="/root/.local/bin/backplane"
ARG OUTPUT_DIR="/opt"

RUN mkdir --parents /backplane-tools
WORKDIR /backplane-tools

# Download backplane-tools binary with checksum verification
RUN --mount=type=secret,id=GITHUB_TOKEN \
    --mount=type=secret,id=read-only-github-pat/token \
    github_dl download \
        --url "${BACKPLANE_TOOLS_URL}" \
        --checksum_file "${BACKPLANE_TOOLS_CHECKSUM_FILE}" \
        --checksum_algorithm "${BACKPLANE_TOOLS_CHECKSUM_ALGORITHM}" \
        --platform "${BACKPLANE_TOOLS_PLATFORM_PREFIX}$(platform_convert "@@PLATFORM@@" --amd64 --arm64)"

# Extract and install to /usr/local/bin
RUN tar --extract --gunzip --no-same-owner --directory /usr/local/bin --file ./*.tar.gz

# Run backplane-tools install all to download the full SRE toolchain
RUN --mount=type=secret,id=GITHUB_TOKEN \
    --mount=type=secret,id=read-only-github-pat/token \
    if [ -f /run/secrets/read-only-github-pat/token ]; then \
        GITHUB_TOKEN=$(cat /run/secrets/read-only-github-pat/token) /usr/local/bin/backplane-tools install all; \
    elif [ -f /run/secrets/GITHUB_TOKEN ]; then \
        GITHUB_TOKEN=$(cat /run/secrets/GITHUB_TOKEN) /usr/local/bin/backplane-tools install all; \
    else \
        /usr/local/bin/backplane-tools install all; \
    fi

# Copy installed binaries to /opt for the final stage COPY
# -H follows symlinks (backplane installs as symlinks in latest/)
RUN cp -Hv "${BACKPLANE_BIN_DIR}/latest/"* "${OUTPUT_DIR}/"

# Copy AWS CLI dist separately (it's not a single binary)
RUN cp --recursive "${BACKPLANE_BIN_DIR}"/aws/*/aws-cli/dist "${OUTPUT_DIR}/aws_dist"


# ══════════════════════════════════════════════════════════════════════════════
# Stage 3: oc-versions
# Downloads OpenShift CLI versions 4.14-4.20 with SHA256 checksum verification
# from mirror.openshift.com. These are registered as alternatives in the final
# stage, allowing runtime version switching via OC_VERSION env var.
# Output: /opt/openshift/{version}/oc for each version.
# ══════════════════════════════════════════════════════════════════════════════
FROM tools-base AS oc-versions

# Download and verify each OC version
# Architecture suffix: empty for x86_64, "-arm64" for aarch64
RUN if [ "$(uname -m)" = "aarch64" ]; then OC_SUFFIX="-arm64"; else OC_SUFFIX=""; fi \
    && for version in 4.14 4.15 4.16 4.17 4.18 4.19 4.20; do \
        echo "=== Downloading OC ${version} (suffix: ${OC_SUFFIX}) ===" \
        && TARBALL="openshift-client-linux${OC_SUFFIX}.tar.gz" \
        && BASE_URL="https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable-${version}" \
        && mkdir --parents "/opt/openshift/${version}" \
        && curl --silent --location --fail \
            "${BASE_URL}/sha256sum.txt" \
            --output "/tmp/sha256sum-${version}.txt" \
        && curl --silent --location --fail \
            "${BASE_URL}/${TARBALL}" \
            --output "/tmp/${TARBALL}" \
        && cd /tmp \
        && grep "${TARBALL}" "/tmp/sha256sum-${version}.txt" \
            | sha256sum --check --status \
        && tar --extract --gzip --file="/tmp/${TARBALL}" \
            --directory="/opt/openshift/${version}" oc \
        && chmod +x "/opt/openshift/${version}/oc" \
        && rm --force "/tmp/${TARBALL}" "/tmp/sha256sum-${version}.txt" \
        && echo "=== OC ${version} verified and installed ==="; \
    done


# ══════════════════════════════════════════════════════════════════════════════
# Stage 4: claude-builder
# Downloads Claude Code from the official anthropics/claude-code GitHub
# Releases with SHA256 checksum verification against SHASUMS256.txt.
# Output: /opt/claude/claude binary.
# ══════════════════════════════════════════════════════════════════════════════
FROM tools-base AS claude-builder

# Pin Claude Code version — Renovate updates this ARG via PR
ARG CLAUDE_CODE_VERSION="2.1.199"

RUN mkdir --parents /opt/claude /tmp/claude-dl
WORKDIR /tmp/claude-dl

# Determine the correct asset name for this architecture
# x86_64 → claude-linux-x64.tar.gz, aarch64 → claude-linux-arm64.tar.gz
RUN CLAUDE_ARCH=$(platform_convert "@@PLATFORM@@" --custom-amd64 "x64" --custom-arm64 "arm64") \
    && TARBALL="claude-linux-${CLAUDE_ARCH}.tar.gz" \
    && echo "${TARBALL}" > /tmp/claude-dl/asset-name

# Download the tarball and checksum file from GitHub Releases (authenticated)
RUN --mount=type=secret,id=GITHUB_TOKEN \
    --mount=type=secret,id=read-only-github-pat/token \
    TARBALL=$(cat /tmp/claude-dl/asset-name) \
    && TOKEN="" \
    && if [ -f /run/secrets/read-only-github-pat/token ]; then \
        TOKEN=$(cat /run/secrets/read-only-github-pat/token); \
    elif [ -f /run/secrets/GITHUB_TOKEN ]; then \
        TOKEN=$(cat /run/secrets/GITHUB_TOKEN); \
    fi \
    && AUTH_HEADER="" \
    && if [ -n "${TOKEN}" ]; then AUTH_HEADER="Authorization: Bearer ${TOKEN}"; fi \
    && curl --silent --location --fail \
        ${AUTH_HEADER:+--header "${AUTH_HEADER}"} \
        "https://github.com/anthropics/claude-code/releases/download/v${CLAUDE_CODE_VERSION}/${TARBALL}" \
        --output "/tmp/claude-dl/${TARBALL}" \
    && curl --silent --location --fail \
        ${AUTH_HEADER:+--header "${AUTH_HEADER}"} \
        "https://github.com/anthropics/claude-code/releases/download/v${CLAUDE_CODE_VERSION}/SHASUMS256.txt" \
        --output /tmp/claude-dl/SHASUMS256.txt

# Verify checksum and extract
RUN TARBALL=$(cat /tmp/claude-dl/asset-name) \
    && cd /tmp/claude-dl \
    && grep "${TARBALL}" SHASUMS256.txt | sha256sum --check --status \
    && tar --extract --gzip --file="${TARBALL}" --directory=/opt/claude \
    && chmod +x /opt/claude/claude


# ══════════════════════════════════════════════════════════════════════════════
# Stage 5: tmux-builder
# tmux is not in UBI9 repos (it's in RHEL 9 BaseOS, which requires a
# subscription). Build from source against UBI9's system libevent and ncurses.
# The runtime shared libs (libevent, ncurses-libs) are already in the UBI9
# base image used by the final stage.
# ══════════════════════════════════════════════════════════════════════════════
FROM ${BASE_IMAGE} AS tmux-builder

ARG TMUX_VERSION="3.5a"
ARG TMUX_SHA256="16216bd0877170dfcc64157085ba9013610b12b082548c7c9542cc0103198951"

RUN dnf install --assumeyes --nodocs \
        autoconf \
        automake \
        gcc \
        libevent-devel \
        make \
        ncurses-devel \
    && dnf clean all \
    && rm --recursive --force /var/cache/yum

WORKDIR /build

# Release tarballs ship pre-generated parser files (cmd-parse.c) so yacc/bison
# is not actually invoked during make. Provide a dummy to satisfy configure.
RUN curl --silent --location --fail \
        "https://github.com/tmux/tmux/releases/download/${TMUX_VERSION}/tmux-${TMUX_VERSION}.tar.gz" \
        --output tmux.tar.gz \
    && echo "${TMUX_SHA256}  tmux.tar.gz" | sha256sum --check --status \
    && tar --extract --gzip --file tmux.tar.gz \
    && ln --symbolic /usr/bin/true /usr/local/bin/yacc \
    && cd "tmux-${TMUX_VERSION}" \
    && ./configure --prefix=/usr \
    && make -j "$(nproc)" \
    && make install DESTDIR=/build/out \
    && strip --strip-all /build/out/usr/bin/tmux


# ══════════════════════════════════════════════════════════════════════════════
# Stage 6: final
# Production image. Only this stage ships. Combines dnf packages with
# artifacts COPY'd from all builder stages.
# ══════════════════════════════════════════════════════════════════════════════
FROM ${BASE_IMAGE} AS final

# ── OCI Labels ───────────────────────────────────────────────────────────────
LABEL org.opencontainers.image.title="rosa-boundary" \
      org.opencontainers.image.description="Ephemeral SRE investigation container for ROSA clusters on AWS ECS Fargate" \
      org.opencontainers.image.source="https://github.com/openshift-online/rosa-boundary" \
      org.opencontainers.image.vendor="Red Hat"

# ── DNF Packages ─────────────────────────────────────────────────────────────
# Single layer: all packages, documentation excluded, cache cleaned.
RUN dnf install --assumeyes --nodocs \
        alternatives \
        bash-completion \
        bind-utils \
        git \
        gzip \
        jq \
        openssl \
        python3 \
        python3-pip \
        sudo \
        tar \
        unzip \
        util-linux \
        vim-enhanced \
        wget \
        xz \
    && dnf clean all \
    && rm --recursive --force /var/cache/yum

# ── Backplane Tools (SRE CLI toolchain) ─────────────────────────────────────
# Binaries from backplane-tools install all: ocm, ocm-backplane, oc, osdctl,
# ocm-addons, yq. AWS CLI dist is a directory, not a single binary.
COPY --from=backplane-tools /opt/aws_dist           /usr/local/aws-cli/v2/current
COPY --from=backplane-tools /opt/ocm                /usr/local/bin/
COPY --from=backplane-tools /opt/ocm-backplane      /usr/local/bin/
COPY --from=backplane-tools /opt/oc                 /usr/local/bin/oc-backplane
COPY --from=backplane-tools /opt/osdctl             /usr/local/bin/
COPY --from=backplane-tools /opt/ocm-addons         /usr/local/bin/
COPY --from=backplane-tools /opt/yq                 /usr/local/bin/

# ── OpenShift CLI Versions ──────────────────────────────────────────────────
# Multiple OC versions for runtime switching via alternatives + OC_VERSION env.
COPY --from=oc-versions /opt/openshift /opt/openshift

# ── Claude Code ─────────────────────────────────────────────────────────────
# AI-assisted investigation tool. Binary only, no Node.js runtime needed.
COPY --from=claude-builder /opt/claude /usr/local/lib/claude-code

# ── tmux ────────────────────────────────────────────────────────────────────
# Built from source in a UBI9 stage. Runtime deps (libevent, ncurses-libs)
# are already in the UBI9 base image.
COPY --from=tmux-builder /build/out/usr/bin/tmux /usr/bin/tmux

# ── Alternatives Registration ───────────────────────────────────────────────
# Register AWS CLI and OC versions with the alternatives system.
# OC 4.20 gets priority 100 (default); others get their minor version number.
# Claude Code gets a symlink from /usr/local/bin/claude.
RUN alternatives --install /usr/local/bin/aws aws /usr/local/aws-cli/v2/current/aws 20 \
    && alternatives --install /usr/local/bin/oc oc /usr/local/bin/oc-backplane 10 \
    && alternatives --install /usr/local/bin/oc oc /opt/openshift/4.14/oc 14 \
    && alternatives --install /usr/local/bin/oc oc /opt/openshift/4.15/oc 15 \
    && alternatives --install /usr/local/bin/oc oc /opt/openshift/4.16/oc 16 \
    && alternatives --install /usr/local/bin/oc oc /opt/openshift/4.17/oc 17 \
    && alternatives --install /usr/local/bin/oc oc /opt/openshift/4.18/oc 18 \
    && alternatives --install /usr/local/bin/oc oc /opt/openshift/4.19/oc 19 \
    && alternatives --install /usr/local/bin/oc oc /opt/openshift/4.20/oc 100 \
    && ln --symbolic /usr/local/lib/claude-code/claude /usr/local/bin/claude

# ── Build-Time Completions ──────────────────────────────────────────────────
# Generate bash completions for all CLI tools at build time.
RUN ocm completion bash > /etc/bash_completion.d/ocm \
    && ocm backplane completion bash > /etc/bash_completion.d/ocm-backplane \
    && oc completion bash > /etc/bash_completion.d/oc \
    && osdctl completion bash --skip-version-check > /etc/bash_completion.d/osdctl \
    && ocm addons completion bash > /etc/bash_completion.d/ocm-addons

# ── SRE User ────────────────────────────────────────────────────────────────
# Non-root user for ECS Exec sessions. Home directory is EFS-mounted at
# runtime by the per-investigation task definition.
RUN useradd --create-home --shell /bin/bash sre \
    && echo 'sre ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/sre \
    && chown root:root /etc/sudoers.d/sre \
    && chmod 0440 /etc/sudoers.d/sre \
    && visudo --check --file /etc/sudoers

# ── Skeleton Config ─────────────────────────────────────────────────────────
# Copied to /home/sre at runtime by the entrypoint (cp --no-clobber).
COPY skel/sre/ /etc/skel-sre/

# ── Entrypoint ──────────────────────────────────────────────────────────────
COPY --chmod=755 entrypoint.sh /usr/local/bin/entrypoint.sh

# ── Environment ─────────────────────────────────────────────────────────────
# EDITOR: system-wide default editor for interactive use.
ENV HOME=/home/sre
ENV EDITOR=vim

# ── Non-Root User ──────────────────────────────────────────────────────────
# Run the entrypoint and PID 1 as the sre user (UID 1000) for least privilege.
# The one privileged operation (alternatives --set) uses sudo via NOPASSWD.
USER sre

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sleep", "infinity"]

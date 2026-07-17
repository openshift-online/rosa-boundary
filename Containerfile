# ROSA Boundary — Multi-Stage Multi-Arch Container Build
#
# Ephemeral SRE investigation container for AWS ECS Fargate.
# SREs connect via SSM/ECS Exec as the non-root 'sre' user.
#
# Stages:
#   tools-base       — shared build environment (curl, python3, helpers)
#   backplane-tools  — SRE CLI tools via github_dl (SHA256 verified)
#   claude-builder   — Claude Code via github_dl (SHA256 verified)
#   oc-versions      — OC 4.14-4.20 with checksum verification
#   tmux-builder     — tmux built from source (not in UBI9 repos)
#   final            — production image (only this stage ships)
#
# backplane-tools, claude-builder, and oc-versions depend on tools-base.
# tmux-builder depends only on BASE_IMAGE. With BuildKit or podman --layers,
# stages 2-5 run in parallel once their dependencies complete.

# Base image pinned by digest for reproducibility. Renovate updates this.
ARG BASE_IMAGE=registry.access.redhat.com/ubi9/ubi@sha256:bcfca170da4fe08c0b70aa76ca4ee63f0e724db1574712cbc6c6a77fea6b21dc


# Stage 1: tools-base
# Shared build environment for all builder stages.
FROM ${BASE_IMAGE} AS tools-base

RUN dnf install --assumeyes --nodocs \
        gzip \
        jq \
        python3 \
        python3-pip \
        tar \
        unzip \
    && dnf clean all \
    && rm --recursive --force /var/cache/yum

RUN python3 -m pip install --no-cache-dir requests

COPY build/platforms.sh /usr/local/bin/platform_convert
COPY build/github_dl.py /usr/local/bin/github_dl
RUN chmod +x /usr/local/bin/platform_convert /usr/local/bin/github_dl


# Stage 2: backplane-tools
# SRE CLI toolchain: ocm, ocm-backplane, oc, osdctl, ocm-addons, yq, AWS CLI v2
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

RUN --mount=type=secret,id=GITHUB_TOKEN \
    --mount=type=secret,id=read-only-github-pat/token \
    github_dl download \
        --url "${BACKPLANE_TOOLS_URL}" \
        --checksum_file "${BACKPLANE_TOOLS_CHECKSUM_FILE}" \
        --checksum_algorithm "${BACKPLANE_TOOLS_CHECKSUM_ALGORITHM}" \
        --platform "${BACKPLANE_TOOLS_PLATFORM_PREFIX}$(platform_convert "@@PLATFORM@@" --amd64 --arm64)"

RUN tar --extract --gunzip --no-same-owner --directory /usr/local/bin --file ./*.tar.gz

# backplane-tools install all fetches the SRE toolchain (ocm, oc, osdctl, etc.)
RUN --mount=type=secret,id=GITHUB_TOKEN \
    --mount=type=secret,id=read-only-github-pat/token \
    if [ -f /run/secrets/read-only-github-pat/token ]; then \
        GITHUB_TOKEN=$(cat /run/secrets/read-only-github-pat/token) /usr/local/bin/backplane-tools install all; \
    elif [ -f /run/secrets/GITHUB_TOKEN ]; then \
        GITHUB_TOKEN=$(cat /run/secrets/GITHUB_TOKEN) /usr/local/bin/backplane-tools install all; \
    else \
        /usr/local/bin/backplane-tools install all; \
    fi

# -H follows symlinks (backplane installs as symlinks in latest/)
RUN cp -Hv "${BACKPLANE_BIN_DIR}/latest/"* "${OUTPUT_DIR}/"

# AWS CLI dist is a directory, not a single binary
RUN cp --recursive "${BACKPLANE_BIN_DIR}"/aws/*/aws-cli/dist "${OUTPUT_DIR}/aws_dist"


# Stage 3: claude-builder
# Claude Code downloaded via github_dl with SHASUMS256.txt verification.
FROM tools-base AS claude-builder

ENV CLAUDE_CODE_VERSION="2.1.199"
ENV CLAUDE_CODE_URL_SLUG="anthropics/claude-code"
ENV CLAUDE_CODE_URL="https://api.github.com/repos/${CLAUDE_CODE_URL_SLUG}/releases/tags/v${CLAUDE_CODE_VERSION}"
ENV CLAUDE_CODE_CHECKSUM_FILE="SHASUMS256.txt"
ENV CLAUDE_CODE_CHECKSUM_ALGORITHM="sha256"

RUN mkdir --parents /claude-dl
WORKDIR /claude-dl

RUN --mount=type=secret,id=GITHUB_TOKEN \
    --mount=type=secret,id=read-only-github-pat/token \
    github_dl download \
        --url "${CLAUDE_CODE_URL}" \
        --checksum_file "${CLAUDE_CODE_CHECKSUM_FILE}" \
        --checksum_algorithm "${CLAUDE_CODE_CHECKSUM_ALGORITHM}" \
        --platform "claude-linux-$(platform_convert "@@PLATFORM@@" --custom-amd64 "x64" --custom-arm64 "arm64")"

RUN mkdir --parents /opt/claude \
    && tar --extract --gzip --file ./claude-linux-*.tar.gz --directory=/opt/claude \
    && chmod +x /opt/claude/claude


# Stage 4: oc-versions
# OC 4.14-4.20 with SHA256 checksum verification from mirror.openshift.com.
# Registered as alternatives in the final stage for runtime version switching.
FROM tools-base AS oc-versions

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


# Stage 5: tmux-builder
# tmux is not in UBI9 repos (it's in RHEL 9 BaseOS, which requires a
# subscription). Build from source against UBI9's libevent and ncurses.
# Runtime shared libs are already in the UBI9 base image.
#
# TODO: Figure out how to use RHEL 9 entitlements to install the tmux RPM
# directly (dnf install tmux) instead of building from source. The RPM is in
# RHEL 9 BaseOS and would work on entitled build hosts (Konflux, OpenShift CI).
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

# Release tarballs ship pre-generated parser files so yacc/bison is not
# invoked during make. Provide a dummy to satisfy configure.
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


# Stage 6: final
# Production image. Only this stage ships.
FROM ${BASE_IMAGE} AS final

LABEL org.opencontainers.image.title="rosa-boundary" \
      org.opencontainers.image.description="Ephemeral SRE investigation container for ROSA clusters on AWS ECS Fargate" \
      org.opencontainers.image.source="https://github.com/openshift-online/rosa-boundary" \
      org.opencontainers.image.vendor="Red Hat"

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

# Backplane tools: ocm, ocm-backplane, oc, osdctl, ocm-addons, yq, AWS CLI v2
COPY --from=backplane-tools /opt/aws_dist           /usr/local/aws-cli/v2/current
COPY --from=backplane-tools /opt/ocm                /usr/local/bin/
COPY --from=backplane-tools /opt/ocm-backplane      /usr/local/bin/
COPY --from=backplane-tools /opt/oc                 /usr/local/bin/oc-backplane
COPY --from=backplane-tools /opt/osdctl             /usr/local/bin/
COPY --from=backplane-tools /opt/ocm-addons         /usr/local/bin/
COPY --from=backplane-tools /opt/yq                 /usr/local/bin/

# OC versions for runtime switching via alternatives + OC_VERSION env var
COPY --from=oc-versions /opt/openshift /opt/openshift

# Claude Code binary
COPY --from=claude-builder /opt/claude /usr/local/lib/claude-code

# tmux built from source (not in UBI9 repos)
COPY --from=tmux-builder /build/out/usr/bin/tmux /usr/bin/tmux

# Register tools with alternatives. OC 4.20 is default (priority 100).
# backplane-tools OC is fallback (priority 10).
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

# Generate bash completions at build time
RUN ocm completion bash > /etc/bash_completion.d/ocm \
    && ocm backplane completion bash > /etc/bash_completion.d/ocm-backplane \
    && oc completion bash > /etc/bash_completion.d/oc \
    && osdctl completion bash --skip-version-check > /etc/bash_completion.d/osdctl \
    && ocm addons completion bash > /etc/bash_completion.d/ocm-addons

# Non-root user for ECS Exec sessions
RUN useradd --create-home --shell /bin/bash sre \
    && echo 'sre ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/sre \
    && chown root:root /etc/sudoers.d/sre \
    && chmod 0440 /etc/sudoers.d/sre \
    && visudo --check --file /etc/sudoers

# Skeleton config copied to /home/sre at runtime by the entrypoint
COPY skel/sre/ /etc/skel-sre/

COPY --chmod=755 entrypoint.sh /usr/local/bin/entrypoint.sh

ENV HOME=/home/sre

USER sre

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sleep", "infinity"]

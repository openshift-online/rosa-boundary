# ROSA Boundary — Multi-Stage Multi-Arch Container Build
#
# Ephemeral SRE investigation container for AWS ECS Fargate.
# SREs connect via SSM/ECS Exec as the non-root 'sre' user.
#
# Stages:
#   tools-base       — shared build environment (curl, python3, helpers)
#   sre-tools        — directly pinned SRE tools (SHA256/signature verified)
#   claude-builder   — Claude Code via github_dl (SHA256 verified)
#   tmux-builder     — tmux built from source (not in UBI9 repos)
#   final            — production image (only this stage ships)
#
# sre-tools and claude-builder depend on tools-base.
# tmux-builder depends only on BASE_IMAGE. With BuildKit or podman --layers,
# stages 2-5 run in parallel once their dependencies complete.

# Base image pinned by digest for reproducibility. Renovate updates this.
ARG BASE_IMAGE=registry.access.redhat.com/ubi9/ubi@sha256:bcfca170da4fe08c0b70aa76ca4ee63f0e724db1574712cbc6c6a77fea6b21dc


# Stage 1: tools-base
# Shared build environment for all builder stages.
FROM ${BASE_IMAGE} AS tools-base

ARG REQUIRE_GITHUB_TOKEN="false"
ENV REQUIRE_GITHUB_TOKEN=${REQUIRE_GITHUB_TOKEN}

RUN dnf install --assumeyes --nodocs \
        gzip \
        jq \
        python3 \
        python3-pip \
        tar \
        unzip \
    && dnf clean all \
    && rm --recursive --force /var/cache/yum

# PyJWT[crypto] provides RS256 JWT signing for GitHub App token generation
# in github_dl.py (used when GITHUB_APP_ID/PEM/INSTALL_ID are set).
RUN python3 -m pip install --no-cache-dir requests "PyJWT[crypto]"

COPY build/platforms.sh /usr/local/bin/platform_convert
COPY build/github_dl.py /usr/local/bin/github_dl
RUN chmod +x /usr/local/bin/platform_convert /usr/local/bin/github_dl

# Fail instead of labeling host-architecture binaries as another platform.
# The pinned base must actually support the requested target architecture.
ARG TARGETARCH
RUN test "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)" = "${TARGETARCH}"


# Stage 2: sre-tools
# Exact, verified SRE releases. Keys and verification tooling never ship.
FROM tools-base AS sre-tools

RUN dnf install --assumeyes --nodocs gnupg2 \
    && dnf clean all \
    && rm --recursive --force /var/cache/yum
COPY build/sre_tools.py build/verify_sre_tools.py /usr/local/share/sre-tools/
COPY build/keys/ /usr/local/share/sre-tools/keys/

# renovate: datasource=github-releases depName=openshift-online/ocm-cli
ARG OCM_VERSION="v1.0.17"
RUN --mount=type=secret,id=GITHUB_TOKEN \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_ID \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_PEM \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_INSTALL_ID \
    python3 /usr/local/share/sre-tools/sre_tools.py ocm \
        --version "${OCM_VERSION}" --arch "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)"
RUN --network=none python3 /usr/local/share/sre-tools/sre_tools.py ocm \
        --version "${OCM_VERSION}" --arch "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)" --validate-installed

# renovate: datasource=github-releases depName=openshift/backplane-cli
ARG BACKPLANE_CLI_VERSION="v1.1.0"
RUN --mount=type=secret,id=GITHUB_TOKEN \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_ID \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_PEM \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_INSTALL_ID \
    python3 /usr/local/share/sre-tools/sre_tools.py ocm-backplane \
        --version "${BACKPLANE_CLI_VERSION}" --arch "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)"
RUN --network=none python3 /usr/local/share/sre-tools/sre_tools.py ocm-backplane \
        --version "${BACKPLANE_CLI_VERSION}" --arch "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)" --validate-installed

# renovate: datasource=github-releases depName=openshift/osdctl
ARG OSDCTL_VERSION="v0.67.0"
RUN --mount=type=secret,id=GITHUB_TOKEN \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_ID \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_PEM \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_INSTALL_ID \
    python3 /usr/local/share/sre-tools/sre_tools.py osdctl \
        --version "${OSDCTL_VERSION}" --arch "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)"
RUN --network=none python3 /usr/local/share/sre-tools/sre_tools.py osdctl \
        --version "${OSDCTL_VERSION}" --arch "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)" --validate-installed

# renovate: datasource=github-releases depName=mikefarah/yq
ARG YQ_VERSION="v4.54.2"
RUN --mount=type=secret,id=GITHUB_TOKEN \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_ID \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_PEM \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_INSTALL_ID \
    python3 /usr/local/share/sre-tools/sre_tools.py yq \
        --version "${YQ_VERSION}" --arch "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)"
RUN --network=none python3 /usr/local/share/sre-tools/sre_tools.py yq \
        --version "${YQ_VERSION}" --arch "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)" --validate-installed

# renovate: datasource=custom.openshift-stable depName=openshift/oc
ARG OC_VERSION="4.22.22"
RUN python3 /usr/local/share/sre-tools/sre_tools.py oc \
        --version "${OC_VERSION}" --arch "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)"
RUN --network=none python3 /usr/local/share/sre-tools/sre_tools.py oc \
        --version "${OC_VERSION}" --arch "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)" --validate-installed

# renovate: datasource=github-tags depName=aws/aws-cli
ARG AWSCLI_VERSION="2.39.6"
RUN python3 /usr/local/share/sre-tools/sre_tools.py aws \
        --version "${AWSCLI_VERSION}" --arch "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)"
RUN --network=none python3 /usr/local/share/sre-tools/sre_tools.py aws \
        --version "${AWSCLI_VERSION}" --arch "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)" --validate-installed

RUN python3 /usr/local/share/sre-tools/verify_sre_tools.py combine /opt/inventory /opt/tool-versions.json


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
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_ID \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_PEM \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_INSTALL_ID \
    github_dl download \
        --url "${CLAUDE_CODE_URL}" \
        --checksum_file "${CLAUDE_CODE_CHECKSUM_FILE}" \
        --checksum_algorithm "${CLAUDE_CODE_CHECKSUM_ALGORITHM}" \
        --platform "claude-linux-$(platform_convert "@@PLATFORM@@" --custom-amd64 "x64" --custom-arm64 "arm64").tar.gz"

RUN mkdir --parents /opt/claude \
    && tar --extract --gzip --file ./claude-linux-*.tar.gz --directory=/opt/claude \
    && chmod +x /opt/claude/claude


# Stage 4: tmux-builder
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

# Directly installed tools: ocm, ocm-backplane, oc, osdctl, yq, AWS CLI v2
COPY --from=sre-tools /opt/aws_dist           /usr/local/aws-cli/v2/current
COPY --from=sre-tools /opt/ocm                /usr/local/bin/
COPY --from=sre-tools /opt/ocm-backplane      /usr/local/bin/
COPY --from=sre-tools /opt/oc                 /usr/local/bin/
COPY --from=sre-tools /opt/osdctl             /usr/local/bin/
COPY --from=sre-tools /opt/yq                 /usr/local/bin/

COPY --from=sre-tools /opt/tool-versions.json /usr/local/share/rosa-boundary/tool-versions.json

# Claude Code binary
COPY --from=claude-builder /opt/claude /usr/local/lib/claude-code

# tmux built from source (not in UBI9 repos)
COPY --from=tmux-builder /build/out/usr/bin/tmux /usr/bin/tmux

# Register the verified AWS distribution with alternatives.
RUN alternatives --install /usr/local/bin/aws aws /usr/local/aws-cli/v2/current/aws 20 \
    && ln --symbolic /usr/local/lib/claude-code/claude /usr/local/bin/claude

# Generate bash completions at build time
RUN ocm completion bash > /etc/bash_completion.d/ocm \
    && ocm backplane completion bash > /etc/bash_completion.d/ocm-backplane \
    && oc completion bash > /etc/bash_completion.d/oc \
    && osdctl completion bash --skip-version-check > /etc/bash_completion.d/osdctl

# Non-root user for ECS Exec sessions
RUN useradd --create-home --shell /bin/bash sre \
    && echo 'sre ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/sre \
    && chown root:root /etc/sudoers.d/sre \
    && chmod 0440 /etc/sudoers.d/sre \
    && visudo --check --file /etc/sudoers

# Skeleton config copied to /home/sre at runtime by the entrypoint
COPY skel/sre/ /etc/skel-sre/

# The credential helper accepts only fixed OCM configure/clear operations and
# writes exclusively to task-scoped mounts overlaid below the EFS-backed home.
COPY --chmod=755 utils/rosa-boundary-credential-helper /usr/local/bin/
COPY --chmod=755 entrypoint.sh /usr/local/bin/entrypoint.sh

ENV HOME=/home/sre

# Test the final filesystem offline as sre; helper and pins are read-only mounts,
# not runtime contents. External acceptance must also reconcile both inventories.
RUN --network=none --mount=type=bind,source=build,target=/verify \
    --mount=type=bind,source=Containerfile,target=/verify-Containerfile \
    runuser --user sre -- python3 /verify/verify_sre_tools.py runtime \
        --containerfile /verify-Containerfile

# The entrypoint runs as root for privileged setup (alternatives --set, chown,
# runuser). ECS Exec sessions drop to the sre user via the CLI's default
# command: "runuser -u sre -- sh -c 'cd ~ && exec bash --login'"
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sleep", "infinity"]

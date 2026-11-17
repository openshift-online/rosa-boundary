# ROSA Boundary — Multi-Stage Multi-Arch Container Build
#
# Ephemeral SRE investigation container for AWS ECS Fargate.
# SREs connect via SSM/ECS Exec as the non-root 'sre' user.
#
# Stages:
#   tools-base       — shared build environment (curl, python3, helpers)
#   sre-tools        — directly pinned SRE tools (SHA256/signature verified)
#   claude-builder   — Claude Code via github_dl (SHA256 verified)
#   opencode-builder — OpenCode via github_dl (SHA256 verified)
#   codex-builder    — OpenAI Codex CLI via github_dl (SHA256 verified)
#   pi-builder       — pi coding agent via github_dl (SHA256 verified)
#   search-builder   — fd and ripgrep (published SHA256 verified)
#   tmux-builder     — tmux built from source (not in UBI9 repos)
#   final            — production image (only this stage ships)
#
# sre-tools and the coding-agent builders depend on tools-base.
# tmux-builder depends only on BASE_IMAGE. With BuildKit or podman --layers,
# stages 2-8 run in parallel once their dependencies complete.

# Base image pinned by digest for reproducibility. Renovate updates this.
ARG BASE_IMAGE=registry.access.redhat.com/ubi9/ubi@sha256:1e9f0ed9fceafb40878bc1705ff124aa150e3fed873f18c42cdc2dded319e0a8


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
ARG YQ_VERSION="v4.54.3"
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
ARG AWSCLI_VERSION="2.40.0"
RUN python3 /usr/local/share/sre-tools/sre_tools.py aws \
        --version "${AWSCLI_VERSION}" --arch "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)"
RUN --network=none python3 /usr/local/share/sre-tools/sre_tools.py aws \
        --version "${AWSCLI_VERSION}" --arch "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)" --validate-installed

RUN python3 /usr/local/share/sre-tools/verify_sre_tools.py combine /opt/inventory /opt/tool-versions.json


# Stage 3: claude-builder
# Claude Code downloaded via github_dl with SHASUMS256.txt verification.
FROM tools-base AS claude-builder

# renovate: datasource=github-releases depName=anthropics/claude-code
ENV CLAUDE_CODE_VERSION="2.1.323"
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


# Stage 4: opencode-builder
# OpenCode downloaded via github_dl with SHA256SUMS verification.
# The project moved to the anomalyco organization; sst/opencode redirects there.
FROM tools-base AS opencode-builder

# renovate: datasource=github-releases depName=anomalyco/opencode
ENV OPENCODE_VERSION="2.3.0"
ENV OPENCODE_URL_SLUG="anomalyco/opencode"
ENV OPENCODE_URL="https://api.github.com/repos/${OPENCODE_URL_SLUG}/releases/tags/v${OPENCODE_VERSION}"
ENV OPENCODE_CHECKSUM_FILE="SHA256SUMS"
ENV OPENCODE_CHECKSUM_ALGORITHM="sha256"

RUN mkdir --parents /opencode-dl
WORKDIR /opencode-dl

# The glibc archive matches the UBI9 runtime; the -musl and -baseline variants
# target other hosts. Select the exact asset, never a platform substring: the
# release also publishes -musl, -baseline and desktop assets per architecture.
RUN --mount=type=secret,id=GITHUB_TOKEN \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_ID \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_PEM \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_INSTALL_ID \
    github_dl download \
        --url "${OPENCODE_URL}" \
        --checksum_file "${OPENCODE_CHECKSUM_FILE}" \
        --checksum_algorithm "${OPENCODE_CHECKSUM_ALGORITHM}" \
        --exact_asset "opencode-linux-$(platform_convert "@@PLATFORM@@" --custom-amd64 "x64" --custom-arm64 "arm64").tar.gz"

# The archive holds exactly one flat executable named 'opencode'. Extract with
# build-controlled ownership and modes rather than the uploader's.
RUN mkdir --parents /opt/opencode \
    && tar --extract --gzip --no-same-owner --no-same-permissions \
        --file ./opencode-linux-*.tar.gz --directory=/opt/opencode \
    && chmod 0755 /opt/opencode/opencode


# Stage 5: codex-builder
# OpenAI Codex CLI downloaded via github_dl with codex-package_SHA256SUMS
# verification. Upstream tags Codex releases 'rust-v<version>'.
#
# The canonical package archive is the only Linux Codex artifact covered by a
# published SHA256 manifest: the bare binary ships a Sigstore bundle and the
# DotSlash descriptor uses blake3 over .tar.zst, neither of which this image's
# verified-download helper supports. It is also what upstream's own install.sh
# downloads and verifies, and it carries the helpers Codex resolves relative to
# itself at runtime (codex-path/rg, the code-mode and exec servers, and the
# codex-resources/ sandbox helper). Keep the layout intact.
FROM tools-base AS codex-builder

# renovate: datasource=github-releases depName=openai/codex
ENV CODEX_VERSION="0.169.0"
ENV CODEX_URL_SLUG="openai/codex"
ENV CODEX_URL="https://api.github.com/repos/${CODEX_URL_SLUG}/releases/tags/rust-v${CODEX_VERSION}"
ENV CODEX_CHECKSUM_FILE="codex-package_SHA256SUMS"
ENV CODEX_CHECKSUM_ALGORITHM="sha256"

RUN mkdir --parents /codex-dl
WORKDIR /codex-dl

# Codex publishes only statically linked musl builds for Linux; they run on UBI9.
RUN --mount=type=secret,id=GITHUB_TOKEN \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_ID \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_PEM \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_INSTALL_ID \
    github_dl download \
        --url "${CODEX_URL}" \
        --checksum_file "${CODEX_CHECKSUM_FILE}" \
        --checksum_algorithm "${CODEX_CHECKSUM_ALGORITHM}" \
        --exact_asset "codex-package-$(platform_convert "@@PLATFORM@@" --x86_64 --aarch64)-unknown-linux-musl.tar.gz"

# Reproduce upstream's documented package install: keep the whole payload, set
# the executables upstream's installer sets, and add the relative
# 'codex -> bin/codex' link it creates. Ownership and modes come from this
# build, not from the uploader, and no setuid, setgid or capability is added:
# the bundled bwrap stays an ordinary unprivileged executable. The chmod names
# every executable the package ships, so a changed upstream layout fails the
# build for review instead of silently shipping a different package.
RUN mkdir --parents /opt/codex \
    && tar --extract --gzip --no-same-owner --no-same-permissions \
        --file ./codex-package-*.tar.gz --directory=/opt/codex \
    && chmod 0755 /opt/codex/bin/* /opt/codex/codex-path/rg /opt/codex/codex-resources/bwrap \
    && ln --symbolic --no-target-directory bin/codex /opt/codex/codex


# Stage 6: pi-builder
# pi coding agent downloaded via github_dl with SHA256SUMS verification.
FROM tools-base AS pi-builder

# renovate: datasource=github-releases depName=earendil-works/pi
ENV PI_VERSION="1.5.2"
ENV PI_URL_SLUG="earendil-works/pi"
ENV PI_URL="https://api.github.com/repos/${PI_URL_SLUG}/releases/tags/v${PI_VERSION}"
ENV PI_CHECKSUM_FILE="SHA256SUMS"
ENV PI_CHECKSUM_ALGORITHM="sha256"

RUN mkdir --parents /pi-dl
WORKDIR /pi-dl

RUN --mount=type=secret,id=GITHUB_TOKEN \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_ID \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_PEM \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_INSTALL_ID \
    github_dl download \
        --url "${PI_URL}" \
        --checksum_file "${PI_CHECKSUM_FILE}" \
        --checksum_algorithm "${PI_CHECKSUM_ALGORITHM}" \
        --exact_asset "pi-linux-$(platform_convert "@@PLATFORM@@" --custom-amd64 "x64" --custom-arm64 "arm64").tar.gz"

# The archive wraps everything in a single 'pi/' directory: the self-contained
# executable plus the theme, schema and asset files it loads relative to itself.
# Strip that wrapper so the payload lands directly in /opt/pi.
RUN mkdir --parents /opt/pi \
    && tar --extract --gzip --no-same-owner --no-same-permissions \
        --file ./pi-linux-*.tar.gz --directory=/opt/pi --strip-components=1 \
    && chmod 0755 /opt/pi/pi


# Stage 7: search-builder
# Pi uses fd and rg from PATH. Neither is available in the UBI9 repositories.
FROM tools-base AS search-builder

# Stable releases and GitHub-published asset SHA256 digests checked 2026-11-17.
# Update fd's version and both hashes together: upstream has no checksum asset.
ENV FD_VERSION="10.5.2"
ARG FD_SHA256_AMD64="7e2d07fa2b8807642aaec67b7e2972a9fbe4db26fcb340a7372392db42b26694"
ARG FD_SHA256_ARM64="63ea52cb31586e6d98efa2f06d73d542f16c7d0c4af0f07b579aaf9714cf907a"
ENV RIPGREP_VERSION="15.2.0"

WORKDIR /search-dl
RUN --mount=type=secret,id=GITHUB_TOKEN \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_ID \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_PEM \
    --mount=type=secret,id=rosa-boundary-github-app/GITHUB_APP_INSTALL_ID \
    arch="$(platform_convert "@@PLATFORM@@" --x86_64 --aarch64)" \
    && case "${arch}" in x86_64) fd_sha="${FD_SHA256_AMD64}" ;; aarch64) fd_sha="${FD_SHA256_ARM64}" ;; *) exit 1 ;; esac \
    && github_dl download \
        --url "https://api.github.com/repos/sharkdp/fd/releases/tags/v${FD_VERSION}" \
        --sha256 "${fd_sha}" \
        --exact_asset "fd-v${FD_VERSION}-${arch}-unknown-linux-musl.tar.gz" \
    && github_dl download \
        --url "https://api.github.com/repos/BurntSushi/ripgrep/releases/tags/${RIPGREP_VERSION}" \
        --checksum_file "ripgrep-${RIPGREP_VERSION}-${arch}-unknown-linux-musl.tar.gz.sha256" \
        --exact_asset "ripgrep-${RIPGREP_VERSION}-${arch}-unknown-linux-musl.tar.gz"

# Extract only the named executables; archive paths and ownership never reach
# the filesystem. No downloaded tool runs while GitHub secrets are mounted.
RUN arch="$(platform_convert "@@PLATFORM@@" --x86_64 --aarch64)" \
    && mkdir --parents /opt/search \
    && tar --extract --gzip --to-stdout \
        --file "fd-v${FD_VERSION}-${arch}-unknown-linux-musl.tar.gz" \
        "fd-v${FD_VERSION}-${arch}-unknown-linux-musl/fd" > /opt/search/fd \
    && tar --extract --gzip --to-stdout \
        --file "ripgrep-${RIPGREP_VERSION}-${arch}-unknown-linux-musl.tar.gz" \
        "ripgrep-${RIPGREP_VERSION}-${arch}-unknown-linux-musl/rg" > /opt/search/rg \
    && chmod 0755 /opt/search/fd /opt/search/rg


# Stage 8: tmux-builder
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


# Stage 9: final
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
        findutils \
        git \
        gzip \
        jq \
        openssl \
        procps-ng \
        python3 \
        python3-pip \
        rsync \
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

# Additional coding agents, installed under the same pinned, checksum-verified
# contract as Claude Code. Each keeps its upstream payload layout because the
# executables resolve bundled resources relative to themselves.
COPY --from=opencode-builder /opt/opencode /usr/local/lib/opencode
COPY --from=codex-builder    /opt/codex    /usr/local/lib/codex
COPY --from=pi-builder       /opt/pi       /usr/local/lib/pi

# Explicit PATH dependencies for pi's find/grep tools.
COPY --from=search-builder /opt/search/fd /opt/search/rg /usr/local/bin/

# tmux built from source (not in UBI9 repos)
COPY --from=tmux-builder /build/out/usr/bin/tmux /usr/bin/tmux

# Register the verified AWS distribution with alternatives.
RUN alternatives --install /usr/local/bin/aws aws /usr/local/aws-cli/v2/current/aws 20 \
    && ln --symbolic /usr/local/lib/claude-code/claude /usr/local/bin/claude \
    && ln --symbolic /usr/local/lib/opencode/opencode /usr/local/bin/opencode \
    && ln --symbolic /usr/local/lib/codex/bin/codex /usr/local/bin/codex \
    && ln --symbolic /usr/local/lib/pi/pi /usr/local/bin/pi

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
# Run the unprivileged rsync loop independently of interactive shells.
COPY --chmod=755 utils/rosa-boundary-skill-sync.sh /usr/local/libexec/rosa-boundary-skill-sync.sh
# Seed provider defaults without persisting AWS credential material.
COPY --chmod=755 utils/rosa-boundary-agent-defaults.py /usr/local/libexec/rosa-boundary-agent-defaults.py
COPY --chmod=755 entrypoint.sh /usr/local/bin/entrypoint.sh

ENV HOME=/home/sre

# Test the final filesystem offline as sre; helper and pins are read-only mounts,
# not runtime contents. External acceptance must also reconcile both inventories.
# Mount the context directory to avoid Buildah's single-file bind-mount issue.
RUN --network=none --mount=type=bind,source=.,target=/verify-src,ro \
    runuser --user sre -- python3 /verify-src/build/verify_sre_tools.py runtime \
        --containerfile /verify-src/Containerfile

# The entrypoint runs as root for privileged setup (alternatives --set, chown,
# runuser). ECS Exec sessions drop to the sre user via the CLI's default
# command: "runuser -u sre -- sh -c 'cd ~ && exec bash --login'"
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sleep", "infinity"]

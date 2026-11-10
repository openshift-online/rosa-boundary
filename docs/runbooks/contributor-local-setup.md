# Contributor local setup

Human-readable setup instructions; the resumable agent entry point is the
[onboarding skill](../../.agents/skills/onboarding/SKILL.md). Run commands from
the repository root. Local testing needs no real AWS or Keycloak login.

## 1. Set up your development tools

Install Git and Make, clone this repository, and run the following commands from
its root. Read [development standards](../development-standards.md) before
changing code or infrastructure.

### Recommended: mise

Install [mise](https://mise.jdx.dev/getting-started.html), the tool/version and
project-dependency manager. On macOS:

```bash
brew install mise
```

Follow mise's shell activation instructions. For example, add
`eval "$(mise activate zsh)"` to your `~/.zshrc`, then open a new shell. For Bash,
use `eval "$(mise activate bash)"` in your shell startup file instead.

Ensure [uv](https://docs.astral.sh/uv/getting-started/installation/) is available
before running the dependency providers; it is not currently declared in the
repository's mise tool list. Then, after reviewing and trusting the repository
configuration:

```bash
mise trust
mise install
mise deps
uv sync --group localstack
uv run --group localstack pre-commit install
```

- `mise install` installs the tool versions selected in [mise.toml](../../mise.toml),
  including Python.
- `mise deps` installs project dependencies through the configured uv and Go
  providers. This command is experimental; use a recent mise release that
  supports it. The repository enables the required experimental setting.
- `uv sync --group localstack` explicitly includes the optional integration-test
  dependencies from the root [pyproject.toml](../../pyproject.toml) and [uv.lock](../../uv.lock).
  No separate `pip install` or virtualenv activation is needed for the test targets.
  The nested LocalStack project remains only as a Python 3.11 CI-install adapter;
  it reads this same dependency group and is not another local setup step.
- Pre-commit installation enables the repository's hooks for future commits.
  Hooks can rewrite files; review the resulting diff.

**The mise configuration is not yet a complete workstation bootstrap.** Some
selectors currently use `latest`, rather than an exact version. Tools not declared
there must still be installed separately. In particular, check that you have:

- `uv` available for dependency installation; Python is managed by mise.
- Podman for LocalStack and container builds.
- `staticcheck` and `golangci-lint` for the full quality gates.
  `jq` and `shfmt` are already included in the mise tool list.
- GNU coreutils and GNU sed for the Linux-oriented shell tests. On macOS,
  `make test-shell` expects their Homebrew installations and sets their PATH only
  for the test process:
  ```bash
  brew install coreutils gnu-sed
  ```

#### Linux (Fedora/RHEL) notes

The commands above show macOS (Homebrew). On Linux:

- Install mise with its installer (`curl https://mise.run | sh`), then activate it in
  your shell startup file (`eval "$(~/.local/bin/mise activate bash)"` or `zsh`).
  Open a new shell. Until you run `mise deps` once, each new prompt prints
  `mise WARN deps: ... run mise deps`.
- Install `staticcheck` and `golangci-lint` with Go, for example
  `go install honnef.co/go/tools/cmd/staticcheck@latest` and the
  [golangci-lint installer](https://golangci-lint.run/docs/welcome/install/),
  and add `$(go env GOPATH)/bin` (usually `~/go/bin`) to your `PATH`.
- Coding agents may not inherit your shell's mise activation. If a tool appears
  missing only in the agent's shell, put the mise-managed tools on its `PATH`
  (for example `eval "$(mise env -s bash)"`) or restart the agent from an
  activated shell.
- GNU coreutils and GNU sed are already the Linux defaults.
- On SELinux-enforcing hosts (Fedora, RHEL), see
  [local container build problems](#local-container-build-problems-linux).

The root Python dependencies include `podman-compose`, `pre-commit`, and Skillsaw.
If invoking the Compose wrapper without an activated virtualenv, run it through
`uv run --group localstack bash tests/localstack/compose.sh ...`, or ensure
`podman-compose` is otherwise on PATH. Mise's configured virtualenv activation
normally makes the project executables available in an activated shell.

### Without mise

Install tools using their official installers or your OS package manager. Use
these files as the source of truth instead of guessing versions:

| What to install | Where to find the requirements |
|---|---|
| Tool versions | [mise.toml](../../mise.toml); `latest` entries are not exact pins |
| Python | [mise.toml](../../mise.toml) selects the version; root [pyproject.toml](../../pyproject.toml) declares compatibility |
| Go toolchain and modules | [go.mod](../../go.mod), including its `toolchain` directive |
| Python tools and LocalStack test dependencies | Root [pyproject.toml](../../pyproject.toml) and [uv.lock](../../uv.lock) |
| Lambda-specific Python dependencies | [lambda/create-investigation/pyproject.toml](../../lambda/create-investigation/pyproject.toml) and its lockfile |
| Pre-commit hook versions | [.pre-commit-config.yaml](../../.pre-commit-config.yaml) |
| Additional test/build tools | Root [Makefile](../../Makefile) and [testing guide](../testing.md) |

You still need `uv`: the Make targets invoke it directly. After installing the
required runtimes/tools, run `go mod download`, `uv sync --group localstack`, and
`uv run --group localstack pre-commit install`. Lambda test targets manage their
own dependency setup. You do not need real AWS credentials for unit tests or
LocalStack integration. CLI integration fixtures use an isolated synthetic
identity and emulated STS, not a running Keycloak server or your personal SSO
cache. See the [testing guide](../testing.md) for these fixtures and their
identity/authorization verification limits.

### Install workstation-wide CLI tools

`mise install` and `mise deps` do **not** install every CLI used by contributors.
Install the following workstation tools separately and ensure their executables
are on your shell's PATH; they are not Boundary container/runtime dependencies.
This step applies whether or not you use mise for the repository toolchain.

#### OpenWiki

Install [OpenWiki](https://docs.langchain.com/oss/openwiki/overview#get-started)
for working with the repository's generated `openwiki/` evidence index and
coding-agent integrations. The upstream
[quickstart](https://docs.langchain.com/oss/openwiki/quickstart) requires
**Node.js 22.22.0 or later**. Node.js and OpenWiki are not currently declared in
`mise.toml`. With mise, install a current Node.js 22 release globally, then install
the OpenWiki CLI using npm:

```bash
mise use --global node@22
node --version
npm install --global openwiki
openwiki --version
```

Without mise, install a supported Node.js version using its official installation
instructions, then run the same npm installation and version check. Use a
user-owned Node/npm installation rather than `sudo npm install`. The upstream
command installs the current OpenWiki release; this repository does not yet pin
its version. Global npm packages belong to the selected Node installation, so
reinstall/check OpenWiki if you switch Node versions.

This repository already has a wiki: **do not run `openwiki --init` as an onboarding
step**, because it regenerates existing documentation. Follow the OpenWiki
retrieval guidance in [AGENTS.md](../../AGENTS.md) and read current source/tests to verify
claims. For an intentional regeneration, use the approved CI workflow; consult
the upstream quickstart for provider credentials and
[coding-agent integrations](https://docs.langchain.com/oss/openwiki/integrations)
for your agent's setup. Installing the CLI does not configure model credentials
or automatically enable an agent integration. Keep credentials out of Git.

#### AWS and GitHub tooling

For the required personal-AWS deployment later in this guide, also install:

- **AWS CLI v2** and authenticate through your approved account-access tooling.
  Verify the selected account with `aws sts get-caller-identity`.
- **AWS Session Manager plugin** (`session-manager-plugin`) for interactive
  ECS Exec sessions through the Boundary CLI.
- **GitHub CLI** (`gh`) if using the documented PR commands or obtaining an image
  build token from an authenticated GitHub session.

See the [personal-dev bootstrap guide](../runbooks/personal-dev-bootstrap.md)
for deployment/build prerequisites and the
[user access guide](../runbooks/user-access-guide.md) for CLI access setup.
These tools do not replace the Podman, lint tools, or platform-specific utilities
listed above. OpenWiki installation is separate from the automated local tests;
`make test-all` does not install or configure it.

## 2. Request LocalStack access

The integration suite uses **LocalStack Pro** for ECS and EFS support. Ask your
team lead or tooling/license administrator for access to the team's licensed
LocalStack workspace. The repository does not identify a universal license owner
or internal request queue. If there is no existing subscription, arrange an
appropriate license through your team's procurement process.

Once invited, select the correct workspace and obtain your auth token from:

https://app.localstack.cloud/workspace/auth-tokens

Configure it locally:

```bash
cp tests/localstack/.env.example tests/localstack/.env
```

A personal LocalStack token works only if its account has a **Pro** licence
(ECS and EFS); startup reports "LocalStack Pro ready with ECS and EFS support"
when it does. Otherwise use the team workspace's token.

Edit `tests/localstack/.env` and set `LOCALSTACK_AUTH_TOKEN` to your token. Never
commit it, print it in shared logs, or put it in shell history. An exported shell
variable overrides the file; `unset LOCALSTACK_AUTH_TOKEN` if an old exported
value is causing license activation failures. The image version is selected in
[tests/localstack/compose.yml](../../tests/localstack/compose.yml), not by a globally
installed LocalStack CLI.

On macOS, initialize a Podman machine once if you do not already have one:

```bash
podman machine init
podman machine start
```

On rootless Linux, enable the socket:

```bash
systemctl --user enable --now podman.socket
```

Start LocalStack from the repository root:

```bash
make localstack-up
```

On macOS, if GNU `timeout` is not on your shell's PATH, use this invocation
instead (unlike `make test-shell`, startup does not adjust PATH automatically):

```bash
PATH="$(brew --prefix coreutils)/libexec/gnubin:$PATH" make localstack-up
```

Integration tests check live HTTP health and required-service readiness before
running. You can assert readiness yourself with `make localstack-ready`; a stale
tracker file cannot bypass the check. Missing/unhealthy LocalStack is a failure,
not an accepted skip.

The Compose wrapper discovers the active Podman engine's socket, including its
path inside the macOS VM. Do not hardcode your user ID or globally change
`XDG_RUNTIME_DIR`. For diagnosis:

```bash
make localstack-logs
# Or bypass Compose entirely:
podman logs --tail=100 localstack_localstack_1
```

Exit code 55 with "License activation failed" means you need to check the token
and workspace entitlement; increasing the startup timeout will not fix it.
See the [LocalStack guide](../../tests/localstack/README.md) for details.

## 3. Arrange access for the full Terraform/build checks

`test-all` validates HCP Terraform configurations that reference private modules.
Request the appropriate HCP organization/team access from the platform team, then:

```bash
terraform login app.terraform.io
```

See [staging access instructions](../staging-deployment.md#user-access) for the
`hp-platform-engineering` organization and SSO/group membership process. This
login is for module-registry access, not permission to deploy. Container builds
also need network/registry access to their base images and tool downloads; ask
the relevant registry owner if an approved image requires authentication.

`terraform login` opens your browser at HCP Terraform. Sign in, create a **user API
token**, and paste it into the terminal prompt that is waiting (`Enter a value:`;
input is hidden). Never paste it into chat or a file. Harmless browser errors such
as `zygote ... Broken pipe` may be printed. Success prints the "Welcome to HCP
Terraform!" banner. Module access is proven only by `make test-all`.

Do not change staging workspace variables directly in HCP or run local staging
applies. Follow the reviewed Git/PR delivery path.

## Local container build problems (Linux)

These affect the `container-build-both-architectures` and `lambda-container-build`
gates of `make test-all`. **No Red Hat subscription or RHEL registration is
needed**; the images use free UBI repositories.

**`Permission denied` on `/verify/...` during the image build (SELinux).** On a
SELinux-enforcing host, containers cannot read project files labeled
`user_home_t`, and the Containerfile's bind mounts do not relabel them. Confirm with
`podman run --rm -v "$PWD/build:/v:ro" registry.access.redhat.com/ubi9/ubi-minimal ls /v`.
Relabel only the two mounted paths (reversible with `restorecon -R build Containerfile`):

```bash
chcon -R -t container_file_t build Containerfile
```

A `git checkout` that rewrites these files can drop the label; reapply it.
Avoid disabling SELinux system-wide.

**`403` from `cdn.redhat.com` in `microdnf install` (stale entitlement).** Podman
copies host subscription secrets (`/usr/share/rhel/secrets`, which links to
`/etc/pki/entitlement`) into builds. If the host has expired RHEL certificates
(check with `openssl x509 -enddate -noout -in /etc/pki/entitlement/<id>.pem`),
`microdnf` tries subscription-only repos and fails. Stop podman injecting them for
your user only, without touching the host or `dnf`:

```bash
mkdir -p ~/.config/containers && : > ~/.config/containers/mounts.conf
```

Delete that file to revert.

## 4. Run all local tests and checks

Run `make test-all` after the previous prerequisites pass. Follow the
[testing guide](../testing.md#exhaustive-local-validation) for the authoritative
scope, private logs/JSON summary, exit statuses and INCOMPLETE coverage policy.
Resolve failed or blocked gates and rerun to completion; never count skips as
verified coverage. Review changes made by hooks before committing.

For shorter loops use `make test` or `make check`; neither replaces the full run.
After testing, follow the [LocalStack Quick Start](../../tests/localstack/README.md#quick-start)
for shutdown without volume deletion. `make localstack-down` requests deletion
of Compose-managed volumes; do not use it when preservation is intended.

Local gates do not prove live AWS behavior. Continue with
[personal-dev bootstrap](personal-dev-bootstrap.md) and separately approved live
verification before opening a PR, as required in [CONTRIBUTING.md](../../CONTRIBUTING.md).

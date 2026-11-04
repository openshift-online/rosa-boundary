# Contributing to ROSA Boundary

## 1. Set up your development tools

Install Git and Make, clone this repository, and run the following commands from
its root. Read [development standards](docs/development-standards.md) before
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

- `mise install` installs the tool versions selected in [mise.toml](mise.toml),
  including Python.
- `mise deps` installs project dependencies through the configured uv and Go
  providers. This command is experimental; use a recent mise release that
  supports it. The repository enables the required experimental setting.
- `uv sync --group localstack` explicitly includes the optional integration-test
  dependencies from the root [pyproject.toml](pyproject.toml) and [uv.lock](uv.lock).
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
| Tool versions | [mise.toml](mise.toml); `latest` entries are not exact pins |
| Python | [mise.toml](mise.toml) selects the version; root [pyproject.toml](pyproject.toml) declares compatibility |
| Go toolchain and modules | [go.mod](go.mod), including its `toolchain` directive |
| Python tools and LocalStack test dependencies | Root [pyproject.toml](pyproject.toml) and [uv.lock](uv.lock) |
| Lambda-specific Python dependencies | [lambda/create-investigation/pyproject.toml](lambda/create-investigation/pyproject.toml) and its lockfile |
| Pre-commit hook versions | [.pre-commit-config.yaml](.pre-commit-config.yaml) |
| Additional test/build tools | Root [Makefile](Makefile) and [testing guide](docs/testing.md) |

You still need `uv`: the Make targets invoke it directly. After installing the
required runtimes/tools, run `go mod download`, `uv sync --group localstack`, and
`uv run --group localstack pre-commit install`. Lambda test targets manage their
own dependency setup. You do not need real AWS credentials for unit tests or
LocalStack integration. CLI integration fixtures use an isolated synthetic
identity and emulated STS, not a running Keycloak server or your personal SSO
cache. See the [testing guide](docs/testing.md) for these fixtures and their
identity/authorization verification limits.

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

Edit `tests/localstack/.env` and set `LOCALSTACK_AUTH_TOKEN` to your token. Never
commit it, print it in shared logs, or put it in shell history. An exported shell
variable overrides the file; `unset LOCALSTACK_AUTH_TOKEN` if an old exported
value is causing license activation failures. The image version is selected in
[tests/localstack/compose.yml](tests/localstack/compose.yml), not by a globally
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
See the [LocalStack guide](tests/localstack/README.md) for details.

## 3. Arrange access for the full Terraform/build checks

`test-all` validates HCP Terraform configurations that reference private modules.
Request the appropriate HCP organization/team access from the platform team, then:

```bash
terraform login app.terraform.io
```

See [staging access instructions](docs/staging-deployment.md#user-access) for the
`hp-platform-engineering` organization and SSO/group membership process. This
login is for module-registry access, not permission to deploy. Container builds
also need network/registry access to their base images and tool downloads; ask
the relevant registry owner if an approved image requires authentication.

Do not change staging workspace variables directly in HCP or run local staging
applies. Follow the reviewed Git/PR delivery path.

## 4. Run all local tests and checks

With the prerequisites installed and LocalStack running:

```bash
make test-all
```

This runs the automated local suites, lint/format and pre-commit checks, isolated
Terraform validation/mocked tests, LocalStack integration, and both workspace
image architectures plus the Lambda image build. It attempts independent gates
even after failures, saves complete logs and a JSON summary in a private temporary
directory, and exits nonzero for failed or blocked gates. Builds can take time
and download substantial data; pre-commit may modify files.

**LocalStack skips are reported as INCOMPLETE, not failed tests.** Some tests
require a container executor, unsupported LocalStack features, or deployed
infrastructure. These gaps remain prominent in the console and JSON summary but
do not make a normal local run nonzero. To require complete coverage:

```bash
make test-all TEST_ALL_ARGS=--require-complete
```

Failed tests, missing/invalid/empty reports, and unavailable services always fail the
run. Skipped tests never count as verified coverage. The aggregate never
deploys AWS resources, publishes images, uploads coverage/SARIF, or runs external
CI scanners/live AWS verification. It does create emulated LocalStack resources
and local images; it leaves LocalStack running. See [testing](docs/testing.md)
for the full scope and limitations.

For shorter iteration loops:

```bash
make test    # Go, Lambda, build-helper, and Bats tests; no LocalStack needed
make check   # Those tests plus strict lint, Staticcheck, and pre-commit
```

Review `git diff` before submitting your PR. When finished, stop LocalStack without
requesting volume deletion:

```bash
uv run --group localstack bash tests/localstack/compose.sh down
```

`make localstack-down` instead uses `down -v`, requesting removal of Compose-managed
volumes. Never include credentials or unredacted investigation data in a PR.

## 5. Open a PR from an upstream branch

Create feature branches directly in `openshift-online/rosa-boundary` and open PRs
from those branches against its `main` branch, **not from a fork**. HCP Terraform
only runs speculative plans for PRs from branches in the connected upstream
repository; fork PRs do not trigger those plans.

For example, if your `upstream` remote points to
`git@github.com:openshift-online/rosa-boundary.git`:

```bash
git fetch upstream
git switch -c my-change upstream/main
# Make your changes, run checks, and commit them.
git push -u upstream my-change
gh pr create --repo openshift-online/rosa-boundary --base main --head my-change
```

Use your configured remote name if it differs, and verify its URL with
`git remote -v` before pushing. If you do not have upstream write access, ask a
maintainer to push the reviewed changes to an upstream branch and open the PR
there so speculative plans can run.

For infrastructure changes, review the applicable HCP Terraform plan checks
before merging. Local Terraform validation is not a substitute for these plans.
See the [staging delivery workflow](docs/staging-deployment.md#how-a-code-change-becomes-live)
for plan, review, and apply behavior.

## Further reading

- [Testing guide](docs/testing.md): complete suite coverage, prerequisites, skip
  handling, synthetic identity and test-only CLI fixtures, and the boundary
  between local checks and live AWS verification.
- [LocalStack guide](tests/localstack/README.md): integration fixtures, emulator
  limitations, and troubleshooting.
- [User access guide](docs/runbooks/user-access-guide.md): authentication and
  group access for a real Boundary deployment; separate from local test setup.

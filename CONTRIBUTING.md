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
retrieval guidance in [AGENTS.md](AGENTS.md) and read current source/tests to verify
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

See the [personal-dev bootstrap guide](docs/runbooks/personal-dev-bootstrap.md)
for deployment/build prerequisites and the
[user access guide](docs/runbooks/user-access-guide.md) for CLI access setup.
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

## 5. Deploy and verify in your personal AWS development account

**Required after local tests and checks pass, and before opening a PR:** deploy
your changes to your personal AWS development account and verify the affected
behavior there. Local tests and LocalStack are prerequisites, not substitutes for
a real AWS deployment and live verification. If access, configuration, or a local
check blocks you, resolve it before proceeding; do not treat the live step as
optional or report unverified behavior as passed.

Follow the [personal-dev bootstrap guide](docs/runbooks/personal-dev-bootstrap.md)
for the complete sequence: account IAM/OIDC → network → image build/publication
→ regional infrastructure → isolated CLI configuration and an approved smoke test.
Bootstrap once, then update the affected components for each changeset; reuse
existing infrastructure only after verifying the target account/region and
deployed artifact provenance. Review plans and obtain explicit approval before
AWS changes or investigation creation. Record the tested revision/artifacts,
live results, audit evidence and cleanup status for your PR.
See also the [account infrastructure guide](deploy/account/README.md) and
[regional infrastructure guide](deploy/regional/README.md). Staging instead uses
the [Git/PR → HCP delivery path](docs/staging-deployment.md); never use these
local commands against staging or production.

### Populate account-specific tfvars from your AWS session

First authenticate into **your personal account**, then run this block from the
repository root using Bash. Set `REGION` explicitly (or configure your AWS CLI
region). Optionally set `BUDGET_EMAIL` to override email discovery. The block
preserves an existing notification email, otherwise uses your Red Hat Git email
when available, falling back to `$(whoami)@redhat.com`. It does not require access
to AWS Organizations or the account owner's email.
It makes only an STS identity request, writes a private, gitignored local file,
and never runs Terraform or creates AWS resources.

Use this only for a **new personal dev installation**, before any applies. It
preserves existing OIDC, trust, budget amount, and model settings, but sets the
initial region/region-tag fields together. Do not use it to migrate an existing
state between regions. An existing file for a different account or a non-dev
stage is rejected rather than silently retargeted.

```bash
set -euo pipefail
export REGION="${REGION:-$(aws configure get region || true)}"
: "${REGION:?Set REGION to your approved personal-dev AWS region}"
export ACCOUNT="$(aws sts get-caller-identity --region "$REGION" --query Account --output text)"

python3 - <<'PY'
import json
import os
from pathlib import Path
import re
import subprocess

path = Path("deploy/account/terraform.tfvars")
existing = path.exists()
source = path if existing else path.with_name("terraform.tfvars.example")
content = source.read_text()
account, region = os.environ["ACCOUNT"], os.environ["REGION"]
if not re.fullmatch(r"[0-9]{12}", account):
    raise SystemExit("STS did not return a valid AWS account ID")
if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", region):
    raise SystemExit("Invalid AWS region")

def current(key):
    match = re.search(r'^\s*' + re.escape(key) + r'\s*=\s*("[^"\n]*")', content, re.M)
    return json.loads(match[1]) if match else None

if existing and current("aws_account_id") != account:
    raise SystemExit("Existing tfvars account differs from AWS session; review it manually")
if existing and current("stage") != "dev":
    raise SystemExit("Existing tfvars is not explicitly dev; refusing to retarget it")

email = os.environ.get("BUDGET_EMAIL")
if not email:
    saved = current("bedrock_budget_notification_email") if existing else None
    git = subprocess.run(["git", "config", "user.email"], capture_output=True, text=True)
    candidate = git.stdout.strip()
    username = subprocess.check_output(["whoami"], text=True).strip()
    email = saved or (candidate if candidate.endswith("@redhat.com") else username + "@redhat.com")
if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
    raise SystemExit("Set BUDGET_EMAIL to a valid notification address")

values = dict(aws_account_id=account, aws_region=region, stage="dev",
              legacy_policy_region=region, legacy_role_tag_region=region,
              bedrock_budget_tag_region=region, bedrock_budget_notification_email=email)
for key, value in values.items():
    pattern = r"(?m)^" + re.escape(key) + r"[ \t]*=[^\n]*$"
    if len(re.findall(pattern, content)) != 1:
        raise SystemExit("Expected exactly one assignment for " + key + "; review tfvars manually")
    content = re.sub(pattern, lambda _: key + " = " + json.dumps(value), content)

os.umask(0o077)
path.write_text(content)
path.chmod(0o600)
print("Updated", path, "for account", account, "in", region, "(no AWS resources created)")
PY
```

Review the file privately before planning. Confirm access to the example dev
Keycloak provider, verify its current TLS thumbprint and client configuration
(or replace them with your approved provider), choose your budget amount, and
confirm notification delivery. Budget alerts do **not**
cap spending. Never commit tfvars, `.env`, Terraform state, or credentials.

### Provision and connect the layers

Use a dedicated checkout/state for your account. Inspect each root's Makefile,
then initialize and plan the account baseline:

```bash
make -C deploy/account init
make -C deploy/account validate
make -C deploy/account plan
# Only after reviewing/approving the plan:
make -C deploy/account apply
```

If you have no suitable VPC, follow the bootstrap guide's **Network** step to
create `deploy/network/terraform.tfvars` with your account/region, `stage = "dev"`,
non-overlapping CIDRs and at least two availability zones in your region. Override
the network root's account/stage defaults. Run `make -C deploy/network init plan`,
review before `make -C deploy/network apply`, then use
`make -C deploy/network output` for the VPC and **private** subnet IDs. A single
NAT gateway is the cost-optimized dev option, but still incurs hourly/data charges
and is not highly available. Do not automatically adopt an existing default VPC.

Build/publish a revision-specific image **before** regional apply. Populate
`deploy/regional/terraform.tfvars` with those network outputs and your image digest,
matching account identity settings. The regional Makefile also requires a trusted
root `.env`; explicitly set `KEYCLOAK_ISSUER_URL`, `TF_VAR_abac_tag_key` and
`TF_VAR_enable_kube_proxy` as described in the bootstrap guide, since its defaults
can override tfvars. Review each plan before applying. Audit retention locks and
account/region-wide Bedrock invocation logging require particular attention.

Continue with the guide's CLI setup, smoke-test evidence and cleanup steps;
leaving an ECS Exec shell does not stop its task or prove audit upload succeeded.

## 6. Open a PR from an upstream branch

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

- [Personal-dev bootstrap](docs/runbooks/personal-dev-bootstrap.md): fresh-account
  IAM/OIDC, VPC, image publication, regional deployment, CLI setup and live cleanup.
- [Testing guide](docs/testing.md): complete suite coverage, prerequisites, skip
  handling, synthetic identity and test-only CLI fixtures, and the boundary
  between local checks and live AWS verification.
- [LocalStack guide](tests/localstack/README.md): integration fixtures, emulator
  limitations, and troubleshooting.
- [User access guide](docs/runbooks/user-access-guide.md): authentication and
  group access for a real Boundary deployment; separate from local test setup.

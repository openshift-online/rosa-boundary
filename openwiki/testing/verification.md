---
type: testing-guide
title: Testing and verification
description: Guide to choosing among ROSA Boundary's Go unit tests, Lambda Python unit tests, Terraform tftest suites, LocalStack integration tests, and shell/bats suites; explains scripts/test_all.py as the aggregating entry point, the LocalStack-vs-Prow CI split, and documented test-boundary limitations.
tags: [testing, terraform, tftest, localstack, go, bats, ci, mock-provider, lambda]
verified:
  - by: openwiki/0.7.1
    at: 2026-11-19T16:04:15.171Z
sources:
  - id: openwiki-source-7afccf6bb50a66b861c2b750
    resource: repo://deploy/account/Makefile
  - id: openwiki-source-e0e8c15f232fd81f46f03e41
    resource: repo://deploy/account/modules/shared-iam/iam.tf
  - id: openwiki-source-65e02007ebea688b767a848b
    resource: repo://deploy/account/modules/shared-iam/lambda-create-investigation.tf
  - id: openwiki-source-f4745022f20c2f39d1db313b
    resource: repo://deploy/account/modules/shared-iam/lambda-reap-investigations.tf
  - id: openwiki-source-ca5deb97ae20b796aad13c09
    resource: repo://deploy/account/modules/shared-iam/lambda-reap-tasks.tf
  - id: openwiki-source-13bc46f3694506473af729bc
    resource: repo://deploy/account/tests/baseline.tftest.hcl
  - id: openwiki-source-88ce5728cbec2814062ae8aa
    resource: repo://deploy/account/tests/content-publishing.tftest.hcl
  - id: openwiki-source-6064e356e2f17b6ca9a00336
    resource: repo://deploy/account/tests/ecr-lambda.tftest.hcl
  - id: openwiki-source-e63bbacd264bc409c45ddf07
    resource: repo://deploy/account/tests/shared-iam.tftest.hcl
  - id: openwiki-source-45c9b8ed543efe3e46e09b07
    resource: repo://deploy/account/tests/test_replication_topology.py
  - id: openwiki-source-24fedbdafcbd69ef0dd59e6c
    resource: repo://deploy/regional/iam-content-files.tf
  - id: openwiki-source-d176128a85129af793772942
    resource: repo://deploy/regional/lambda-create-investigation.tf
  - id: openwiki-source-b1c5e619d9ef5b51db452442
    resource: repo://deploy/regional/Makefile
  - id: openwiki-source-92cccd8107e9e4386a317d7a
    resource: repo://deploy/regional/tests/claude_default_model.tftest.hcl
  - id: openwiki-source-5a5ae915c751279579694710
    resource: repo://deploy/regional/tests/content-files.tftest.hcl
  - id: openwiki-source-e331ce49d4745096eb9b7376
    resource: repo://deploy/regional/tests/content-storage.tftest.hcl
  - id: openwiki-source-d47764bc2ef3fe0e490a1747
    resource: repo://deploy/regional/tests/ecr-lambda-destination.tftest.hcl
  - id: openwiki-source-1599d372a558b44029d5589b
    resource: repo://deploy/regional/tests/iam-ownership.tftest.hcl
generated: { by: "openwiki/0.7.1", at: "2026-11-19T16:04:15.171Z" }
---

# Testing and verification

ROSA Boundary's root Go module (not the separately-moduled [Trusted Actions
component](trusted-actions-testing.md), which has its own Make targets and
Codecov gate) is covered by five independent test families, each with a
different framework, a different mocking boundary, and a different relationship
to CI:

| Suite | Framework | Scope | Touches real AWS? |
| --- | --- | --- | --- |
| Go unit tests | `go test` (standard library `testing`) | CLI commands, Lambda invocation client, config derivation, AWS endpoint plumbing | No |
| Lambda unit tests | pytest (`create-investigation`) / `unittest` (`reap-tasks`, `reap-investigations`) | The three Lambda handlers, with `moto`/mocked `boto3` clients | No |
| Terraform `.tftest.hcl` suites | `terraform test` with `mock_provider "aws"` | `deploy/account` and `deploy/regional` root configuration shape: IAM ownership, S3/content storage, ECR/Lambda wiring, input-variable guards | No (mocked plan/apply only) |
| LocalStack integration tests | pytest (`tests/localstack/integration/`) | AWS service interactions against LocalStack Pro's emulated APIs | No (emulated AWS) |
| Shell/Bats suites | Bats (`tests/shell/`, plus `tests/localstack/ci-run.bats`/`compose.bats`) | Credential helper, entrypoint watchdog, agent-instructions/skill-sync tooling, mocked Podman socket discovery | No |

Choose the suite that matches what you changed: Go-only logic changes need only
`make test-cli`/`make test-coverage`; a Lambda handler change needs its
`test_handler.py` suite; a `deploy/account` or `deploy/regional` Terraform
change needs the corresponding `.tftest.hcl` suite (see
[Regional runtime infrastructure](../infrastructure/regional-runtime.md) for
what the regional root deploys); an AWS-service-interaction change (ECS task
lifecycle, EFS access points, S3 Files mounts, IAM/KMS wiring) needs the
LocalStack integration suite; and a shell-script or entrypoint change needs the
Bats suites. `scripts/test_all.py` (`make test-all`) is the single entry point
that runs all of the above together, plus linting and formatting.

## `scripts/test_all.py`: the aggregating entry point

With LocalStack already running, `make test-all` (`python3 scripts/test_all.py`)
runs every independent gate **sequentially, even after an earlier gate fails**,
and writes per-gate logs plus a `summary.json` into a private temporary
directory whose path it prints at start and finish. It distinguishes `FAIL`
(a test, command, or prerequisite failed, or a JUnit report was missing/empty)
from `INCOMPLETE` (the LocalStack or `tests/unit/` JUnit report recorded skips
but no failures); `INCOMPLETE` does not make a normal run exit nonzero unless
invoked as `make test-all TEST_ALL_ARGS=--require-complete`.

In source order, `scripts/test_all.py` runs:

- `make test-coverage`, all three Lambda unit-test targets
  (`test-lambda-reap-tasks`, `test-lambda-reap-investigations`,
  `test-lambda-create-investigation`), `test-github-dl` (build-helper tests),
  `test-shell` (Bats), `lint`, and `staticcheck`.
- `go test -tags localstack ./internal/aws -run ^TestIntegrationEndpoint` — the
  endpoint-isolation unit tests for the `localstack`-tagged CLI build, which is
  absent from normal builds and only loopback-reachable.
- `tests/unit/` via `uv run --group localstack pytest tests/unit/ --junitxml=...`
  (offline regression tests for the test tooling itself — for example
  `test_test_all.py` regression-tests this very runner, and
  `test_content_files.py` regression-tests LocalStack test helper logic without
  starting LocalStack) — reported through the same `PASS`/`FAIL`/`INCOMPLETE`
  JUnit classification.
- `.agents/skills/boundary-live-verification/scripts`' own `unittest discover`
  suite (offline tooling tests for the live-verification skill; these do not
  run live AWS verification).
- `make -C lambda/create-investigation test-coverage`.
- `gofmt -d`, `shfmt -d`, `shellcheck`, and `terraform fmt -check -recursive`
  over tracked source files.
- `terraform_checks`: for every Terraform root under `deploy/` and
  `hcp-terraform/` (detected by locating each root's `main.tf`), it copies only
  source files into a disposable temporary snapshot, runs `terraform init
  -backend=false` and `terraform validate` with sanitized environment variables
  (stripped `TF_CLI_ARGS*`/`TF_VAR_*`/`AWS_*`/`TF_DATA_DIR`/`TF_WORKSPACE`, and
  dummy `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` plus an unreachable
  `AWS_ENDPOINT_URL`), and — if the root has a `tests/*.tftest.hcl` glob match —
  runs `terraform test`. Before running any test file, `mocked_aws_only()`
  tokenizes its HCL text and **refuses to run it** unless it has an
  unambiguous top-level `mock_provider "aws" { ... }` block with no `alias`
  attribute and no real `provider "aws" { ... }` block anywhere in the file;
  this is a structural safety guard against a future test file accidentally
  making real AWS calls during this aggregate run, not a semantic check of the
  assertions inside.
- `localstack_check`: requires LocalStack already reachable (`require_ready`),
  then runs the full `tests/localstack/integration/` pytest selection with a
  JUnit report, classified `PASS`/`FAIL`/`INCOMPLETE` the same way.
- `python-syntax` (compiles every tracked `.py` file), optional
  `validate-findings`/`findings-to-sarif.py` conversion when a root
  `adversary-findings.json` exists, both-architecture `make build` and `make
  build-lambda-image` (no image push), and finally `make pre-commit` restricted
  to tracked files.

**What `scripts/test_all.py` does not cover:** AWS deployments, investigation
creation, live identity/network/audit assertions, image publication,
coverage/SARIF uploads, and external Konflux/Prow security scanners.
`deploy/account/tests/test_replication_topology.py` is also outside this
runner — it drives `terraform console` against an HCL fragment rather than
`terraform test`, so it must be invoked separately (for example `python3 -m
pytest deploy/account/tests/test_replication_topology.py`), not via
`make test-all` or either root Makefile's `test` target. `tests/oidc-token-debug.py`
is a manual diagnostic, not an unattended suite, and is never invoked by this
runner. Nothing under `components/trusted-actions/` is covered either: that
component is a separate Go module with its own `Makefile` and its own
unit/integration/Postgres test strategy, documented in
[Trusted Actions testing and CI](trusted-actions-testing.md).

## Go unit tests

Tests for the `rosa-boundary` CLI live alongside the code in `internal/`
(`internal/aws`, `internal/cmd`, `internal/config`, `internal/credentials`,
`internal/lambda`, `internal/output`, `internal/auth`). They use the standard
library `testing` package with table-driven subtests and mock interfaces (for
example a `lambdaInvoker` interface) to isolate AWS SDK dependencies — no
external test framework and no real AWS calls.

```bash
make test-cli       # go test ./...
make test-coverage   # go test -coverprofile=coverage.out -covermode=atomic ./...
make codecov         # test-coverage, then scripts/codecov.sh uploads to Codecov
```

`internal/aws` also carries a `//go:build localstack`-tagged file
(`endpoint_localstack_test.go`) exercising the public constructors and an STS
exchange against a loopback `httptest` server to prove SDK requests reach the
correct endpoint overrides used by the `localstack`-tagged CLI build; it proves
request routing, not real STS/ECS/EFS behavior, and is absent from ordinary
builds. `scripts/test_all.py` runs it explicitly with `-run
^TestIntegrationEndpoint`.

## Lambda unit tests

Each Lambda (`create-investigation`, `reap-tasks`, `reap-investigations`) has a
`test_handler.py` co-located with its `handler.py`:

```bash
make test-lambda-create-investigation   # pytest (via uv), uses moto + unittest.mock
make test-lambda-reap-tasks             # unittest (via uv), mocked boto3 clients
make test-lambda-reap-investigations    # unittest (via uv), mocked boto3 clients
make test-lambda                        # all three
```

`create-investigation`'s suite uses pytest with `moto` for AWS mocking and
`unittest.mock` for OIDC/JWKS stubs, grouped into classes by feature area
(input validation, tagging, sidecar config). `reap-tasks` and
`reap-investigations` use `unittest` with mocked AWS clients; the latter
covers investigation garbage collection and audit cleanup.

## Terraform `.tftest.hcl` suites (`deploy/account` and `deploy/regional`)

Both Terraform roots — `deploy/account` (one state per AWS account) and
`deploy/regional` (one state per deployed Region; see
[Regional runtime infrastructure](../infrastructure/regional-runtime.md)) ship a
`tests/` directory of native [Terraform test](https://developer.hashicorp.com/terraform/language/tests)
suites. Every suite uses `mock_provider "aws"` (and, where the module needs it,
`mock_provider "archive" {}`) so `terraform test` can run `plan`/`apply`
against ephemeral test state without AWS credentials or live infrastructure.
These suites are the authoritative check on IAM identity/policy ownership,
content-bucket and replication wiring, ECR/Lambda destination behavior, and the
input-variable guards that gate Bedrock model selection — they prove Terraform
*renders* the intended configuration, never that AWS accepts or enforces it.
Several suite headers say this explicitly (for example,
`deploy/regional/tests/content-storage.tftest.hcl`'s opening comment: mocked
applies "prove nothing about AWS enforcement, real alias/aws/s3 key ARNs or
actual replication behaviour").

### Account-level suites (`deploy/account/tests`)

| Suite | What it covers |
| --- | --- |
| `baseline.tftest.hcl` | The account singleton contract: one shared identity set and `regional_iam_contract` output, Bedrock budget/notification configuration, OIDC provider create/reference/adoption modes, role-name-prefix length validation, model-agreement preservation, rejection of wildcard Bedrock service-trust Regions and of silently dropping the legacy trust Region, metrics-read identity wiring, content-identity defaults, and a source-level `fileset`/`regexall` assertion that the account root has no `aws_iam_role_policy` resources or regional-only ARNs and that `modules/shared-iam` contains **exactly five** `aws_iam_role_policy_attachment` resources (the three pre-reaper attachments plus the investigation reaper's basic and VPC-execution attachments). |
| `shared-iam.tftest.hcl` | The `modules/shared-iam` submodule directly: identity trust policies, resource tags, the five common managed-policy attachments, multi-Region Bedrock invocation-logging `SourceArn` trust (while retaining `SourceAccount`), rejection of a wildcard logging Region and of dropping the legacy Region, and the metrics-read role's opt-in behavior and fail-closed caller-allowlist validation (rejecting wildcards, account-root callers, repeated callers, and out-of-range session durations). |
| `content-publishing.tftest.hcl` | The three content-publisher GitHub Actions OIDC identities (exact-subject trust, no wildcard repository/branch/audience, no injected subjects, no pull-request refs as branches), content-replication identity independence from audit replication, custom-prefix propagation, and the stable output contract. |
| `ecr-lambda.tftest.hcl` | The account-owned source ECR repository for the create-investigation Lambda image: opt-in creation, immutability/retention, source-owned filtered replication to Regional destinations, rejection of replicating into the source Region or the wrong primary Region, and migration-input consistency checks. |

`deploy/account/tests/test_replication_topology.py` is a **different test
mechanism**: a standalone Python `unittest` module that reads
`hcp-terraform/rosa-boundary/main.tf` as text, slices out its `locals` block up
to the `module "rosa_boundary"` block, writes that slice into a temporary
module, and shells out to `terraform console` to evaluate
`jsonencode(local.replication_topology)`. It asserts the existing ECR-only
topology and inactive S3 destination are preserved, a populated
content-replication handoff keeps the same destination key, every HCP
Terraform workspace variable block receives `local.replication_topology.<stage>`
under a single `replication` key (with the old discrete keys gone from the
generator), stage/production publisher handoffs stay source-only, the
corresponding `moved` blocks exist so Terraform treats renamed variables as
renames rather than deletions, and that `deploy/account/variables.tf` and
`deploy/regional/variables.tf` declare an identical `replication` variable
type. It is invoked separately (for example `python3 -m pytest
deploy/account/tests/test_replication_topology.py`), not via either root
Makefile's `test` target.

### Regional-level suites (`deploy/regional/tests`)

All five suites mock the same core AWS data/resources
(`aws_kms_alias`, `aws_s3_bucket`, `aws_partition`, `aws_caller_identity`,
`aws_region`, `aws_iam_role`, `aws_iam_openid_connect_provider`, and, where the
module creates them, `aws_lambda_function`, `aws_cloudwatch_event_rule`,
`aws_ecs_cluster`, `aws_efs_file_system`, `aws_efs_access_point`,
`aws_kms_key`, `aws_cloudwatch_log_group`), and override `aws_s3_bucket.content`'s
ARN/ID so the shared `aws_s3_bucket` mock doesn't collide the content bucket
with the audit bucket under test.

**`iam-ownership.tftest.hcl`** asserts the **regional/account IAM ownership
separation** invariant: the regional root must create no shared `aws_iam_role`
or `aws_iam_openid_connect_provider` resources (the dedicated `content_files`
service role — see `deploy/regional/iam-content-files.tf` — is the one local-role
exception), zero `aws_iam_role_policy_attachment` resources, and no
`aws_iam_role_policies_exclusive`/`aws_iam_role_policy_attachments_exclusive`
reconciliation anywhere in its `.tf` files (checked with a source-level
`fileset`/`regexall` scan, plus confirming `account-handoff.tf` has no `from =
aws_iam_role_policy.` moved blocks) — all shared identities and managed
attachments live in the account workspace's `modules/shared-iam`, looked up via
`data.aws_iam_role`/`data.aws_iam_openid_connect_provider`. A companion
assertion (`legacy_policy_names_ownership_and_original_scopes`) confirms every
shared-role `aws_iam_role_policy` attaches to one of those looked-up data
sources (task, execution, sre_shared, lambda_invoker,
create_investigation_lambda, reap_tasks_lambda, reap_investigations_lambda,
bedrock_invocation_logging, s3_replication), that the thirteen legacy inline
policy names and their exact JSON scopes are unchanged in the legacy Region
(including the `task_bedrock`/Bedrock-endpoint wildcard scopes and the
project-scoped `InvokeDefaultProjectResponses` statement mirrored onto the VPC
endpoint policy), and that the investigation reaper's EFS
mount/write/root-access grant — in both the Lambda's inline policy and the EFS
file-system policy — is conditioned on its own dedicated
`aws_efs_access_point.reaper`, never a bare file-system-wide grant. Further
runs confirm a second Region (`us-west-2`) renders the same identities but
distinct, suffixed policy names and Region/account-scoped ARNs instead of
copying the legacy Region's grants, and that the optional account-owned
metrics-read grant is opt-in and rejected at variable-evaluation time if the
calling Region doesn't match `legacy_policy_region`. These are configuration-shape
checks under mocking — they prove Terraform renders ownership-correct,
non-colliding grants, not that a live AWS account enforces them or that
cross-workspace state lookups succeed against real account state.

**`claude_default_model.tftest.hcl`** verifies the `claude_default_model` ↔
`bedrock_model_agreements` consistency guard implemented as an input-variable
validation in `deploy/regional/variables.tf`: `claude_default_model` must be a
known Bedrock inference-profile ID (a key in
`local.claude_inference_profile_foundation_models`) that resolves to a
foundation-model ID present in `bedrock_model_agreements`; a bare
foundation-model ID is rejected even if that foundation model is itself
approved. Because this validation runs during `plan`, the suite satisfies every
other module precondition first: `mock_provider "aws"` supplies `aws_kms_alias`,
`aws_s3_bucket`, `aws_iam_role`, and `aws_iam_openid_connect_provider` mocks so
IAM ARNs read via data sources resolve; an `override_data` block gives
`data.aws_partition.current` a real `aws` partition; and two more
`override_data` pairs put both test subnets in one VPC with distinct
availability-zone IDs (satisfying the Bedrock-endpoint precondition) and give
each subnet's route table a default route (satisfying `subnet_outbound_routing`).
With those preconditions satisfied, each `run` block's `plan` succeeds or fails
purely on the `claude_default_model` validation: for example,
`default_sonnet55_profile_succeeds` pins the shared default to
`us.anthropic.claude-sonnet-5-5` and confirms it reaches the task's
`ANTHROPIC_MODEL` environment variable; `haiku55_requires_matching_agreement`
sets `claude_default_model = "us.anthropic.claude-haiku-5-5"` against an
agreement map that only approves a different model and expects
`var.claude_default_model` to fail; `approved_sonnet55_us_profile_succeeds` and
`approved_sonnet55_eu_profile_succeeds` confirm both the US and EU regional
inference-profile prefixes resolve correctly when their matching agreement is
present.

**`content-storage.tftest.hcl`** (36 `run` blocks) covers the per-Region
published-content bucket: the bucket and the task's read grant exist
unconditionally in every Region without opt-in, while publisher and
replication grants stay absent until role ARNs/destinations are supplied;
bucket protections (encryption, versioning, public-access block); minimal
publisher/runtime grants; non-legacy-Region policy names carrying the Region
suffix (mirroring `iam-ownership`'s naming contract); replication rules and
their IAM grant; multiple destinations keeping replication-rule priorities
unique across Regions; an extensive set of `content_prefixes`
input-validation rejections (empty, non-directory, overlapping, duplicate,
reserved-bootstrap, wildcard, IAM-policy-variable syntax, whitespace, and
colon-containing prefixes); rejections of path-qualified or cross-account
publisher/replication role ARNs and of grants placed on the wrong role; and a
content-replica-side block showing a replica accepts a shared, populated
topology without its own source-side grants, an unpopulated destination leaves
content inactive, and a replica still validates bucket metadata and key
Region.

**`content-files.tftest.hcl`** checks the S3 Files-backed content mount
feature end to end under mocking: each configured `content_prefixes` key gets
its own `aws_s3files_file_system`/`aws_s3files_file_system_policy` backed by
the content bucket and the dedicated `content_files` service role; ECS task
volumes/mount points are read-only and prefix-derived; the ECS
`stopTimeout` leaves at least ten seconds of slack after `entrypoint.sh`'s
`METADATA_SECONDS` + `SHUTDOWN_SECONDS` + `KILL_GRACE_SECONDS` watchdog budget;
the `content_files` service role's trust policy is scoped to
`elasticfilesystem.amazonaws.com` with `aws:SourceAccount`/`aws:SourceArn`
conditions; task clients get an allow-mount/deny-write/deny-root-access policy
plus an explicit whole-bucket S3 mutation deny; every filesystem policy denies
writes/root access to all clients and denies any principal other than the task
role, and denies insecure transport; the dedicated `content_files` security
group restricts TCP 2049 ingress to only the Fargate task security group; and
custom nested prefixes with an optional `kube-proxy` sidecar correctly
reapportion container CPU and add a `dependsOn: HEALTHY` ordering. It checks
rendered configuration and policy JSON, not a real S3 Files mount or live AWS
authorization.

**`ecr-lambda-destination.tftest.hcl`** covers the regional root's
**destination** ECR repository for the create-investigation Lambda image (the
counterpart to the account root's **source** repository tested by
`ecr-lambda.tftest.hcl`): repository and lifecycle policy are opt-in and
absent by default; when configured, the destination mirrors source
immutability, `force_delete`, `AES256` encryption, scan-on-push, and 25-image
retention. Image mode resolves the ordinary account/Region ECR URI and wires
the image Lambda to it, including when no destination repository is declared
in this workspace. Additional runs reject non-SHA or mutable image tags, keep
ZIP mode free of ECR image wiring, and reject a destination in the source
Region. The suite does **not** assert a Quay pull-through cache rule.

### Running the Terraform suites

The account Makefile exposes `make --directory=deploy/account test`
(`terraform test`). The regional root's `Makefile` defines `init`, `fmt`,
`validate`, `plan`, `apply`, `build-lambda`, `destroy`, and `lambda` targets but
**no `test` target**, so `deploy/regional/tests/*.tftest.hcl` must be run with
`terraform test` directly from `deploy/regional` — do not assume a `make test`
invocation exists there, and `make validate` does not exercise the test files.
`scripts/test_all.py`'s `terraform_checks` runs both roots' suites in a
disposable snapshot as part of `make test-all`, in addition to any direct
`terraform test` invocation. `deploy/account/tests/test_replication_topology.py`
is outside both Makefiles' `test` targets and `scripts/test_all.py` entirely, as
described above.

## LocalStack integration tests

Tests in `tests/localstack/integration/` run against
[LocalStack Pro](https://localstack.cloud/) to validate AWS service
interactions — S3 (audit WORM/Object Lock), IAM (roles, OIDC, tag-based
authorization), ECS (Fargate task lifecycle), EFS (filesystems and access
points), optional S3 Files (per-prefix filesystem APIs and ECS-mounted content
propagation), KMS, and CloudWatch Logs — against LocalStack's emulated APIs,
never a real AWS account. Some tests exercise emulated AWS APIs directly;
others inspect source/policy/task-definition contracts; close-investigation
cases execute a temporary, endpoint-restricted Go CLI build against the
emulated services. Markers: `@pytest.mark.integration` (all tests),
`@pytest.mark.slow` (ECS task launches, >30s), `@pytest.mark.e2e` (end-to-end
investigation workflows).

```bash
make localstack-up            # start LocalStack and its AWS initialization hook
make test-localstack-fast     # skip @slow ECS task launches
make test-localstack          # full selection; starts and tears down LocalStack
make localstack-down          # tear down
```

Requires a LocalStack Pro auth token (`tests/localstack/.env`,
`LOCALSTACK_AUTH_TOKEN`) and Podman with its socket enabled. All Make
integration entry points and `make test-all` assert live LocalStack health
(`make localstack-ready` / `require_ready`) before running pytest; direct
`pytest tests/localstack/integration/` runs also check readiness before
session-client setup and before each dependent test. `ECS_EXECUTOR=local`
intentionally skips task-container execution tests — a passing local run is
not proof of live AWS/Fargate behavior, and a completely unskipped run may not
be possible in that configuration.

### Local vs Prow CI

`make test-localstack-ci` runs `tests/localstack/ci-run.sh`, the entrypoint
Prow uses. Unlike the Compose-based local targets, it starts its own Podman API
socket and LocalStack container, enables Docker-backed ECS tests, and writes
JUnit results and diagnostic logs to `ARTIFACT_DIR`; it requires the prepared
Linux nested-Podman CI environment, an exported `LOCALSTACK_AUTH_TOKEN`, and an
existing writable `ARTIFACT_DIR`, and it does not load `tests/localstack/.env`.
Prow's `localstack-integration-tests` presubmit job (`run_if_changed` covering
`lambda/`, `deploy/regional/`, `tests/localstack/`, `cmd/`, `pkg/`,
`internal/`, the root Go module files, and `Makefile`) runs exactly this script
with an injected token; the script rejects an all-skipped run, but reading
individual skip reasons still requires the JUnit report. This is still
emulated AWS, never real Fargate/IAM — Prow running this suite is not evidence
of deployed-environment behavior.

## Shell / Bats suites

```bash
make test-shell
```

Runs `tests/shell/` (`agent-instructions.bats`, `credential-helper.bats`,
`entrypoint.bats`, `investigation-examples.bats`, `skill-sync.bats`) plus
`tests/localstack/ci-run.bats` and `tests/localstack/compose.bats`, including
mocked Podman socket-discovery regressions. No LocalStack license, running
containers, AWS credentials, or AWS Region are needed; Lambda unit tests mock
`boto3` client construction before handler imports/reloads. `make test-shell`
requires `bats`, and on macOS adds Homebrew's GNU coreutils/`gnu-sed` to `PATH`
only for the test process (to match the Linux container's GNU command
behavior) rather than changing the contributor's shell environment. This suite
runs locally (via `make test`, `make check`, and `scripts/test_all.py`) only —
it is not one of Prow's five generated presubmit jobs.

## LocalStack vs Prow CI: coverage summary

| Suite | Runs fully locally (LocalStack/mocks only) | Runs in Prow CI | Needs real AWS |
| --- | --- | --- | --- |
| Go unit tests | Yes (`make test-coverage`) | Yes — `coverage` presubmit (`make codecov`), marked optional, skips TA-only changes | No |
| Lambda unit tests | Yes, all three (`make test-lambda`) | Partial — `lambda-unit-tests` presubmit runs only `make test-lambda-create-investigation`; the two reaper targets are not a Prow job | No |
| Terraform `.tftest.hcl` suites | Yes (`terraform test`, or via `scripts/test_all.py`'s `terraform_checks`) | **No** — not run by any reviewed Prow presubmit or Konflux PipelineRun | No (mocked) |
| `test_replication_topology.py` | Yes, invoked manually with `pytest` | No | No |
| LocalStack integration tests | Yes (`make test-localstack*`) | Yes — `localstack-integration-tests` presubmit, path-filtered, via `tests/localstack/ci-run.sh` | No (LocalStack Pro emulation) |
| Shell/Bats suites | Yes (`make test-shell`) | No dedicated presubmit | No |
| `tests/unit/` offline tooling tests | Yes (`scripts/test_all.py`'s `python-unit` step) | No | No |

This split means a green Prow run on a PR proves only Go-coverage upload,
`create-investigation`'s Lambda suite, and the path-filtered LocalStack
integration suite — it does **not** prove the Terraform test suites pass, the
reaper Lambda suites pass, or the shell/bats suites pass; those remain
local-only gates that `make check` / `make test-all` enforce but Prow does not.

## Known test-boundary limitations

- **Mocked Terraform is not AWS.** Every `.tftest.hcl` run executes against
  Terraform's in-memory mocked state. It proves Terraform renders the intended
  resource names, IAM policy JSON, attachment targets, trust conditions, and
  input-variable rejections; it does not prove AWS accepts those policies, that
  cross-workspace `data.aws_iam_role`/`data.aws_iam_openid_connect_provider`
  lookups succeed against real account state, that S3/ECR replication actually
  copies objects, or that a live `terraform apply` succeeds end to end.
- **LocalStack is not AWS.** Even LocalStack Pro's emulated ECS/EFS/IAM/S3 do
  not prove real OIDC trust-policy enforcement, Fargate scheduling behavior, or
  production audit guarantees; `ECS_EXECUTOR=local` skips real task-container
  execution even in CI.
- **Prow coverage is partial and optional in places.** The `coverage`
  presubmit is marked optional and skips Trusted-Actions-only changes; no Prow
  job runs the reaper Lambda unit tests, the Terraform test suites, or the
  shell/bats suites. A passing PR does not certify those gates ran.
- **Separate component, separate suite.** `components/trusted-actions/` is an
  independent Go module with its own `Makefile`, Postgres/race/integration
  targets, and Codecov patch-coverage gate, not exercised by root `go test
  ./...` or any target described on this page — see
  [Trusted Actions testing and CI](trusted-actions-testing.md).
- **Manual and out-of-scope tooling.** `tests/oidc-token-debug.py` is a manual
  diagnostic, never invoked by an automated suite.
  `deploy/account/tests/test_replication_topology.py` must be run explicitly
  with a Python test runner. Neither local gates nor the reviewed Prow/Konflux
  configuration perform AWS deployments, investigation creation in a real
  account, image publication, coverage/SARIF uploads, or Enterprise Contract
  scanning; those require their own approved workflows. See the
  [investigation lifecycle](../workflows/investigation-lifecycle.md) page for
  what an actual investigation run does in a deployed environment, which none
  of these suites substitute for.

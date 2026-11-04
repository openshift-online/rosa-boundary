#!/usr/bin/env python3
"""Exhaustive local gates, not deployments, image publication, or live AWS tests."""

import argparse
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/localstack"))
from check_ready import NotReady, require_ready


def source_files(root=ROOT):
    """Include working-tree edits/new files, but never ignored secrets or state."""
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root
    ).decode().split("\0")
    return sorted({name for name in names if name and (root / name).is_file() and not (root / name).is_symlink()})


def junit_status(path):
    """Distinguish test failures from incomplete execution, independently of policy."""
    cases = ET.parse(path).getroot().findall(".//testcase")
    skipped = sum(case.find("skipped") is not None for case in cases)
    failed = sum(case.find("failure") is not None or case.find("error") is not None for case in cases)
    if not cases:
        return "FAIL", "no tests recorded"
    if failed:
        return "FAIL", f"{failed}/{len(cases)} tests failed or errored (see JUnit report)"
    if skipped:
        return "INCOMPLETE", f"{skipped}/{len(cases)} tests skipped; not verified (see JUnit report)"
    return "PASS", f"{len(cases)} tests recorded, none skipped"


class Runner:
    def __init__(self, artifacts):
        self.artifacts = artifacts
        self.results = []

    def run(self, name, command, cwd=ROOT, env=None):
        log = self.artifacts / f"{len(self.results):02d}-{name.replace('/', '-')}.log"
        print(f"Running {name} ...", flush=True)
        try:
            with log.open("w") as stream:
                result = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, check=False)
            ok = result.returncode == 0
        except OSError as error:
            log.write_text(str(error) + "\n")
            ok = False
        self.results.append({"name": name, "status": "PASS" if ok else "FAIL", "passed": ok, "log": str(log)})
        print(f"  {'PASS' if ok else 'FAIL'}: {log}", flush=True)
        return ok

    def report(self, name, status, message):
        self.results.append({"name": name, "status": status, "passed": status == "PASS", "detail": message})
        print(f"{status} {name}: {message}", flush=True)

    def problem(self, name, message):
        self.report(name, "FAIL", message)


def mocked_aws_only(source):
    """Conservative HCL scan: require a default mock and reject AWS overrides.

    Tokenize comments and quoted strings atomically, so neither can impersonate
    a block. Unsupported heredocs fail closed rather than risk template content
    being mistaken for configuration. Terraform validate/test checks HCL syntax.
    Named-only mocks do not protect the default provider; real provider blocks
    (including named overrides or escaped labels) are conservatively rejected.
    """
    pattern = re.compile(r'\s+|\#[^\n]*|//[^\n]*|/\*.*?\*/|"(?:[^"\\]|\\.)*"|[A-Za-z_][A-Za-z_0-9-]*|.', re.S)
    tokens = []
    for match in pattern.finditer(source):
        token = match.group()
        if token.isspace() or token.startswith(("#", "//", "/*")):
            continue
        tokens.append(token)
    depth = 0
    default_mock = False
    for index, token in enumerate(tokens):
        # Reject unterminated comments/strings and heredocs conservatively.
        if token in ('"', '/') or tokens[index:index + 2] == ['<', '<']:
            return False
        if token == 'provider' and tokens[index + 2:index + 3] == ['{']:
            return False
        if token == 'mock_provider' and tokens[index + 1:index + 3] in (['"aws"', '{'], ['aws', '{']):
            if depth != 0:
                return False
            # Any alias attribute is rejected: named mocks alone are unsafe,
            # and accepting mappings would require full HCL evaluation.
            end = index + 3
            level = 1
            while end < len(tokens) and level:
                level += (tokens[end] == '{') - (tokens[end] == '}')
                if tokens[end] == 'alias':
                    return False
                end += 1
            if level:
                return False
            default_mock = True
        depth += (token == '{') - (token == '}')
        if depth < 0:
            return False
    return default_mock and depth == 0


def terraform_checks(runner, files):
    """Initialize/validate in a disposable source-only copy; never use live state."""
    with tempfile.TemporaryDirectory(prefix="rosa-terraform-check-") as temp:
        snapshot = Path(temp)
        for name in files:
            path = Path(name)
            if path.parts[0] in ("deploy", "hcp-terraform", "lambda") and path.suffix in (".tf", ".hcl", ".py", ".json") and not name.endswith(".tfvars.json"):
                dest = snapshot / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / name, dest)
        # Root modules and the independently reusable shared-IAM module.
        roots = sorted({str(Path(name).parent) for name in files if name.endswith("/main.tf") and name.startswith(("deploy/", "hcp-terraform/"))})
        env = dict(os.environ, TF_IN_AUTOMATION="1", TF_INPUT="0", AWS_EC2_METADATA_DISABLED="true")
        # Never let an inherited CLI option redirect an isolated validation/test.
        for key in list(env):
            if key.startswith(("TF_CLI_ARGS", "TF_VAR_", "AWS_")) or key in ("TF_DATA_DIR", "TF_WORKSPACE"):
                del env[key]
        env.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_EC2_METADATA_DISABLED="true", AWS_ENDPOINT_URL="http://127.0.0.1:9")
        for module in roots:
            directory = snapshot / module
            if not runner.run(f"terraform-init-{module}", ["terraform", "init", "-backend=false", "-input=false", "-no-color"], cwd=directory, env=env):
                runner.problem(f"terraform-checks-{module}", "blocked by initialization failure; validation/tests did not run")
                continue
            runner.run(f"terraform-validate-{module}", ["terraform", "validate", "-no-color"], cwd=directory, env=env)
            tests = list((directory / "tests").glob("*.tftest.hcl"))
            if tests:
                # Every existing test uses mocked AWS. Reject future real-provider
                # tests rather than accidentally creating AWS resources here.
                if any(not mocked_aws_only(test.read_text()) for test in tests):
                    runner.problem(f"terraform-test-{module}", "refusing test file without an unambiguous default AWS mock or with AWS provider overrides")
                    continue
                runner.run(f"terraform-test-{module}", ["terraform", "test", "-no-color"], cwd=directory, env=env)


def localstack_check(runner):
    endpoint = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
    try:
        require_ready(endpoint)
    except NotReady as error:
        runner.problem("localstack", f"{error}; start it with make localstack-up")
        return
    report = runner.artifacts / "localstack.xml"
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_DEFAULT_REGION="us-east-2", AWS_EC2_METADATA_DISABLED="true", AWS_ENDPOINT_URL=endpoint, LOCALSTACK_ENDPOINT=endpoint)
    runner.run("localstack", ["uv", "run", "--group", "localstack", "pytest", "tests/localstack/integration/", "-v", "-ra", f"--junitxml={report}"], env=env)
    try:
        status, message = junit_status(report)
        runner.report("localstack-coverage", status, message)
    except (OSError, ET.ParseError):
        runner.problem("localstack-coverage", "missing or invalid JUnit report")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-complete", action="store_true", help="exit nonzero for incomplete coverage as well as failures")
    args = parser.parse_args()
    artifacts = Path(tempfile.mkdtemp(prefix="rosa-test-all-"))
    print(f"Private logs and summary: {artifacts}", flush=True)
    runner = Runner(artifacts)
    files = source_files()
    make = os.environ.get("MAKE", "make")
    for target in ("test-coverage", "test-lambda-reap-tasks", "test-lambda-reap-investigations", "test-lambda-create-investigation", "test-github-dl", "test-shell", "lint", "staticcheck"):
        runner.run(target, [make, target])
    runner.run("localstack-endpoint-unit", ["go", "test", "-tags", "localstack", "./internal/aws", "-run", "^TestIntegrationEndpoint", "-count=1"])
    unit_report = artifacts / "python-unit.xml"
    runner.run("python-unit", ["uv", "run", "--group", "localstack", "pytest", "tests/unit/", "-v", "-ra", f"--junitxml={unit_report}"])
    try:
        status, message = junit_status(unit_report)
        runner.report("python-unit-coverage", status, message)
    except (OSError, ET.ParseError):
        runner.problem("python-unit-coverage", "missing or invalid JUnit report")
    runner.run("live-tooling-unit", [sys.executable, "-m", "unittest", "discover", "-s", ".agents/skills/boundary-live-verification/scripts", "-p", "test_*.py", "-v"])
    runner.run("lambda-coverage", [make, "-C", "lambda/create-investigation", "test-coverage"])
    if runner.run("go-format", ["gofmt", "-d", *[name for name in files if name.endswith(".go")]]):
        # gofmt -d exits zero for differences, so inspect its captured output.
        if Path(runner.results[-1]["log"]).stat().st_size:
            runner.problem("go-format-differences", "unformatted Go files; see go-format log")
    shell_files = [name for name in files if name.endswith(".sh") or name == "utils/rosa-boundary-credential-helper"]
    runner.run("shell-format", ["shfmt", "-d", "-i", "4", *shell_files])
    runner.run("shellcheck-all", ["shellcheck", *shell_files])
    runner.run("terraform-format", ["terraform", "fmt", "-check", "-recursive", "deploy", "hcp-terraform", "tests/localstack/terraform"])
    terraform_checks(runner, files)
    localstack_check(runner)
    runner.run("python-syntax", [sys.executable, "-c", "import pathlib, sys; [compile(pathlib.Path(p).read_bytes(), p, 'exec') for p in sys.argv[1:]]", *[name for name in files if name.endswith(".py")]])
    if (ROOT / "adversary-findings.json").is_file():
        runner.run("validate-findings", [make, "validate-findings"])
        runner.run("convert-findings", [sys.executable, "scripts/findings-to-sarif.py", "--input", "adversary-findings.json", "--output", str(artifacts / "findings.sarif")])
    else:
        print("No root adversary-findings.json: findings validation/conversion not applicable.", flush=True)
    runner.run("container-build-both-architectures", [make, "build"])
    runner.run("lambda-container-build", [make, "build-lambda-image"])
    if files:
        runner.run("pre-commit", ["uv", "run", "--group", "localstack", "pre-commit", "run", "--files", *files])
    (artifacts / "summary.json").write_text(json.dumps(runner.results, indent=2) + "\n")
    print("\nSummary:")
    for result in runner.results:
        detail = f": {result['detail']}" if "detail" in result else ""
        print(f"  {result['status']} {result['name']}{detail}")
    if any(result["status"] == "INCOMPLETE" for result in runner.results):
        print("Coverage is incomplete: skipped tests are NOT verified.")
        if args.require_complete:
            print("--require-complete: incomplete coverage makes this run nonzero.")
    print(f"Full logs: {artifacts}")
    print("Not included: deployments/publication, coverage/SARIF uploads, external CI scanners, or live AWS verification.")
    return int(any(result["status"] == "FAIL" or (args.require_complete and result["status"] == "INCOMPLETE") for result in runner.results))


if __name__ == "__main__":
    raise SystemExit(main())

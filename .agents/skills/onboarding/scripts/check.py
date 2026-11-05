#!/usr/bin/env python3
"""Non-mutating onboarding assertions. Never authenticate or display secrets."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[4]
TOOLS = ("git", "make", "uv", "python3", "go", "podman", "terraform",
         "bats", "shellcheck", "shfmt", "jq", "staticcheck", "golangci-lint")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def commands(names):
    for name in names:
        require(shutil.which(name), f"Missing {name}; follow local setup, then resume this step")


def succeeds(command, message):
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, check=False)
    require(result.returncode == 0, message)


def token_configured():
    """Check presence only, without sourcing arbitrary shell or printing a token."""
    path = ROOT / "tests/localstack/.env"
    require(path.is_file(), "Missing tests/localstack/.env (required by make localstack-up)")
    value = os.environ.get("LOCALSTACK_AUTH_TOKEN")
    if not value:
        match = re.search(r"^\s*LOCALSTACK_AUTH_TOKEN\s*=\s*(.*?)\s*$", path.read_text(), re.M)
        value = match[1].strip("\"'") if match else ""
    require(value and value.lower() not in ("your-token-here", "your-auth-token-here", "your-token", "changeme"),
            "Set the LocalStack token privately; activation is verified at startup")


def summary_ok(path):
    data = json.loads(Path(path).read_text())
    require(isinstance(data, list) and data, "Missing aggregate results")
    results = data
    require(all(isinstance(item, dict) and item.get("status") in ("PASS", "INCOMPLETE") for item in results),
            "Aggregate contains failed/unknown gates; resolve and rerun make test-all")
    print("Summary contains no failed gates; review INCOMPLETE coverage and confirm full run provenance")


def check(step, summary=None):
    require(Path.cwd().resolve() == ROOT, "Run from the repository root")
    require((ROOT / "Makefile").is_file(), "Missing repository Makefile")
    commands(("git", "make"))
    if step == 1:
        return
    if step == 2:
        commands(("terraform", "podman", "uv"))
    if step in (3, 4, 5):
        commands(TOOLS)
    if step in (4, 5):
        token_configured()
        succeeds(["podman", "info"], "Podman engine is not ready; resume step 3")
        succeeds(["uv", "run", "--no-sync", "--group", "localstack", "python", "-c",
                  "import boto3, pytest; import importlib.metadata as m; "
                  "[m.version(n) for n in ('podman-compose', 'pre-commit')]"],
                 "Python dependency environment is not ready; resume step 3")
    if step == 5:
        succeeds(["uv", "run", "--no-sync", "--group", "localstack", "make", "localstack-ready"],
                 "LocalStack required services are not ready; resume step 4")
    if step in (6, 7):
        commands(("aws", "session-manager-plugin", "gh"))
        require(summary, "Supply --summary /private/path/summary.json from the completed step 5 run")
        summary_ok(summary)
    if step == 7:
        succeeds(["aws", "sts", "get-caller-identity"], "AWS session unavailable; authenticate yourself and resume")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("step", type=int, choices=range(1, 8))
    parser.add_argument("--summary")
    args = parser.parse_args()
    try:
        check(args.step, args.summary)
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        # Avoid rendering file contents or command output, which may contain secrets.
        print(f"BLOCKED step {args.step}: " + (str(error) if isinstance(error, RuntimeError) else "prerequisite could not be checked"))
        return 1
    print(f"PASS step {args.step} machine prerequisites; human assertions in the reference still apply")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

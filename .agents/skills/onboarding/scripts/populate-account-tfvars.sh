#!/usr/bin/env bash
# Prepare a new personal-dev configuration; does not apply infrastructure.
main() {
	set -euo pipefail
	if [[ ! -f deploy/account/terraform.tfvars.example || ! -f mise.toml ]]; then
		printf '%s\n' 'Run from the repository root' >&2
		return 1
	fi
	REGION="${REGION:-$(aws configure get region || true)}"
	: "${REGION:?Set REGION to your approved personal-dev AWS region}"
	ACCOUNT="$(aws sts get-caller-identity --region "$REGION" --query Account --output text)"
	export REGION ACCOUNT

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
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	main "$@"
fi

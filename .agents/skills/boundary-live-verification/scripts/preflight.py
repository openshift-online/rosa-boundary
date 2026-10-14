#!/usr/bin/env python3
"""Read-only AWS metadata check for one contributor's dev artifact expectations.

No Terraform, task creation, IAM changes, credentials, or audit log reads.
Exit 0 only when every requested artifact matches and is image-digest-pinned.
"""

import argparse
import base64
import binascii
import json
import os
import subprocess
import sys

from dev_state import DIGEST, check, profile


def aws(*args):
    cmd = ["aws", *args, "--no-cli-pager", "--output", "json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False,
                          env={**os.environ, "AWS_PAGER": ""})
    if proc.returncode:
        # AWS stderr can include sensitive request context: do not relay it.
        raise RuntimeError(f"AWS read failed: {args[0]} {args[1]} (exit {proc.returncode})")
    return json.loads(proc.stdout)


def check_deployment(p, image_digest=None, lambda_sha=None, architecture=None):
    region = p["region"]
    stage = p["stage"]
    family = f"{p['project']}-{stage}"
    result = {"account_id": p["account_id"], "region": region, "stage": stage,
              "checks": {}, "matched": False}
    identity = aws("sts", "get-caller-identity")
    if identity.get("Account") != p["account_id"]:
        result["checks"]["aws_identity"] = "MISMATCH"
        return result
    result["checks"]["aws_identity"] = "matched"

    cluster = aws("ecs", "describe-clusters", "--clusters", family, "--region", region)
    if len(cluster.get("clusters", [])) != 1 or cluster["clusters"][0].get("status") != "ACTIVE":
        result["checks"]["ecs_cluster"] = "MISMATCH"
        return result
    result["checks"]["ecs_cluster"] = "active"
    if image_digest or architecture:
        task = aws("ecs", "describe-task-definition", "--task-definition", family, "--region", region)["taskDefinition"]
        result["task_definition_arn"] = task["taskDefinitionArn"]
        containers = [c for c in task.get("containerDefinitions", []) if c.get("name") == "rosa-boundary"]
        if len(containers) != 1 or task.get("status") != "ACTIVE":
            result["checks"]["base_task_definition"] = "MISMATCH"
            return result
        result["checks"]["base_task_definition"] = "active"
        platform = (task.get("runtimePlatform") or {}).get("cpuArchitecture") or "X86_64"
        if architecture:
            result["checks"]["task_architecture"] = "matched" if platform == architecture else "MISMATCH"
        if image_digest:
            image = containers[0]["image"]
            # Avoid claiming mutable :latest is bound to a source digest.
            if image.endswith("@" + image_digest):
                result["checks"]["task_image_digest"] = "matched (pinned)"
            else:
                result["checks"]["task_image_digest"] = "UNVERIFIED (not pinned to expected digest)"
    if lambda_sha:
        info = aws("lambda", "get-function-configuration", "--function-name",
                   f"{family}-create-investigation", "--region", region)
        result["lambda_package_type"] = info.get("PackageType")
        result["checks"]["lambda_state"] = (
            "matched" if info.get("State") == "Active" and info.get("LastUpdateStatus") == "Successful"
            else "MISMATCH")
        if info.get("PackageType") == "Zip":
            result["checks"]["lambda_code_sha256"] = (
                "matched" if info.get("CodeSha256") == lambda_sha else "MISMATCH")
        else:
            result["checks"]["lambda_code_sha256"] = "UNVERIFIED (Image Lambda needs resolved image digest check)"
    result["matched"] = all(v in ("matched", "matched (pinned)", "active")
                            for v in result["checks"].values())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--expect-image-digest")
    parser.add_argument("--expect-lambda-code-sha256")
    parser.add_argument("--expect-architecture", choices=("X86_64", "ARM64"))
    args = parser.parse_args()
    if not (args.expect_image_digest or args.expect_lambda_code_sha256 or args.expect_architecture):
        parser.error("supply at least one expected artifact/platform; unchecked surfaces are not verified")
    try:
        if args.expect_image_digest:
            check(args.expect_image_digest, DIGEST, "expected image digest")
        if args.expect_lambda_code_sha256 and len(base64.b64decode(args.expect_lambda_code_sha256, validate=True)) != 32:
            raise ValueError("invalid expected Lambda CodeSha256")
        result = check_deployment(profile(args.profile), args.expect_image_digest,
                                  args.expect_lambda_code_sha256, args.expect_architecture)
        print(json.dumps(result, indent=2))
        return 0 if result["matched"] else 2
    except (OSError, ValueError, KeyError, RuntimeError, binascii.Error, json.JSONDecodeError) as exc:
        print(f"preflight blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

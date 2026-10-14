#!/usr/bin/env python3
"""Store non-secret per-contributor dev coordinates and live-test run metadata.

No AWS calls, deployment, credentials, arbitrary evidence text or audit data.
"""

import argparse
import base64
import binascii
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import urlsplit
import uuid


NAME = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{0,39}\Z")
REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
TEST = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
TASK_DEF = re.compile(r"arn:aws[a-z-]*:ecs:([^:]+):([0-9]{12}):task-definition/[^\s]+\Z")
TASK_ARN = re.compile(r"arn:aws[a-z-]*:ecs:([^:]+):([0-9]{12}):task/[^\s]+\Z")
INVESTIGATION = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\Z")
RESULTS = ("passed", "failed", "blocked")
EVIDENCE = ("verified", "missing", "unverified", "not-required")
CLEANUP = ("completed", "pending", "not-required")


def check(value, pattern, label):
    if not pattern.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def now():
    return datetime.now(timezone.utc).isoformat()


def directory(base, *parts, create=False):
    path = base
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f"symlink directory refused: {path}")
        if create:
            path.mkdir(mode=0o700, exist_ok=True)
        if path.exists() and not path.is_dir():
            raise ValueError(f"not a directory: {path}")
    return path


def roots():
    home = Path.home()
    config = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config").expanduser()
    state = Path(os.environ.get("XDG_STATE_HOME") or home / ".local/state").expanduser()
    if not config.is_absolute() or not state.is_absolute():
        raise ValueError("XDG roots must be absolute paths")
    if config.is_symlink() or state.is_symlink():
        raise ValueError("XDG root symlinks are not supported")
    return config, state


def profile_path(name, create=False):
    check(name, NAME, "profile name")
    config, _ = roots()
    return directory(config, "rosa-boundary-live-verification", "profiles", create=create) / (name + ".json")


def runs_path(name, create=False):
    check(name, NAME, "profile name")
    _, state = roots()
    return directory(state, "rosa-boundary-live-verification", name, "runs", create=create)


def read_json(path):
    if path.is_symlink():
        raise ValueError(f"symlink file refused: {path}")
    if path.stat().st_mode & 0o077:
        raise ValueError(f"file must have mode 0600: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, data, *, exclusive=False):
    if path.is_symlink():
        raise ValueError(f"symlink file refused: {path}")
    content = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()
    if exclusive:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        return
    # Refuse replacing insecure or user-supplied files; writes are atomic.
    read_json(path)
    fd, temp = tempfile.mkstemp(prefix=".run-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def profile(name):
    data = read_json(profile_path(name))
    if data.get("name") != name or data.get("stage") != "dev":
        raise ValueError("invalid dev profile")
    return data


def add_profile(args):
    check(args.account_id, re.compile(r"[0-9]{12}\Z"), "account ID")
    check(args.region, REGION, "region")
    check(args.realm, TEST, "realm")
    check(args.client_id, re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z"), "client ID")
    url = urlsplit(args.oidc_base_url)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("OIDC base URL must be HTTPS with no credentials/query/fragment")
    if args.oidc_base_url.rstrip("/").endswith("/realms/" + args.realm):
        raise ValueError("supply the OIDC base URL, not the realm issuer URL")
    data = {
        "schema": 1, "name": args.name, "stage": "dev", "project": "rosa-boundary",
        "account_id": args.account_id, "region": args.region,
        "oidc_base_url": args.oidc_base_url.rstrip("/"),
        "realm": args.realm, "client_id": args.client_id, "created_at": now(),
    }
    write_json(profile_path(args.name, create=True), data, exclusive=True)
    print(f"Created private dev profile {args.name}; live account and OIDC settings still need verification")


def show_profile(args):
    p = profile(args.name)
    print(json.dumps({k: p[k] for k in ("name", "stage", "project", "account_id", "region", "created_at")}, indent=2))
    print("OIDC base URL/realm/client ID configured (values omitted)")


def validate_arn(value, pattern, p, label):
    match = pattern.fullmatch(value)
    if not match or (match.group(1), match.group(2)) != (p["region"], p["account_id"]):
        raise ValueError(f"{label} must match profile account/region")


def start_run(args):
    p = profile(args.profile)
    check(args.revision, REVISION, "full Git revision")
    check(args.source_sha256, HEX64, "source SHA-256")
    check(args.test, TEST, "test name")
    if args.image_digest:
        check(args.image_digest, DIGEST, "image digest")
    if args.cli_sha256:
        check(args.cli_sha256, HEX64, "CLI SHA-256")
    if args.lambda_code_sha256:
        raw = base64.b64decode(args.lambda_code_sha256, validate=True)
        if len(raw) != 32:
            raise ValueError("invalid Lambda CodeSha256")
    if args.task_definition_arn:
        validate_arn(args.task_definition_arn, TASK_DEF, p, "task definition ARN")
    run_id = str(uuid.uuid4())
    data = {
        "schema": 1, "run_id": run_id, "profile": args.profile, "stage": "dev",
        "account_id": p["account_id"], "region": p["region"], "created_at": now(),
        "revision": args.revision, "source_sha256": args.source_sha256,
        "test": args.test, "result": "in-progress",
        "artifacts": {k: v for k, v in {
            "image_digest": args.image_digest,
            "lambda_code_sha256": args.lambda_code_sha256,
            "task_definition_arn": args.task_definition_arn,
            "cli_sha256": args.cli_sha256,
        }.items() if v},
    }
    write_json(runs_path(args.profile, create=True) / (run_id + ".json"), data, exclusive=True)
    print(run_id)


def run_path(name, run_id):
    try:
        canonical = str(uuid.UUID(run_id))
    except ValueError as exc:
        raise ValueError("invalid run ID") from exc
    if canonical != run_id:
        raise ValueError("run ID must be canonical UUID")
    return runs_path(name) / (run_id + ".json")


def update_run(args):
    p = profile(args.profile)
    path = run_path(args.profile, args.run_id)
    data = read_json(path)
    if data.get("result") != "in-progress" or data.get("account_id") != p["account_id"] or data.get("region") != p["region"]:
        raise ValueError("run finished already or profile does not match")
    if not args.task_arn and not args.investigation_id:
        raise ValueError("provide task ARN or investigation ID")
    if args.task_arn:
        validate_arn(args.task_arn, TASK_ARN, p, "task ARN")
        if data.get("task_arn") and data["task_arn"] != args.task_arn:
            raise ValueError("cannot replace an existing task ARN")
        data["task_arn"] = args.task_arn
    if args.investigation_id:
        check(args.investigation_id, INVESTIGATION, "investigation ID")
        if data.get("investigation_id") and data["investigation_id"] != args.investigation_id:
            raise ValueError("cannot replace an existing investigation ID")
        data["investigation_id"] = args.investigation_id
    write_json(path, data)
    print("Recorded cleanup identifiers")


def finish_run(args):
    p = profile(args.profile)
    path = run_path(args.profile, args.run_id)
    data = read_json(path)
    if data.get("result") != "in-progress" or data.get("account_id") != p["account_id"] or data.get("region") != p["region"]:
        raise ValueError("run finished already or profile does not match")
    if args.task_arn:
        validate_arn(args.task_arn, TASK_ARN, p, "task ARN")
        if data.get("task_arn") and data["task_arn"] != args.task_arn:
            raise ValueError("task ARN differs from previously recorded cleanup identifier")
    if args.investigation_id:
        check(args.investigation_id, INVESTIGATION, "investigation ID")
        if data.get("investigation_id") and data["investigation_id"] != args.investigation_id:
            raise ValueError("investigation ID differs from previously recorded cleanup identifier")
    if args.result == "passed" and ("missing" in (args.session_evidence, args.s3_evidence) or args.cleanup == "pending"):
        raise ValueError("cannot pass with missing evidence or pending cleanup")
    if args.result == "passed" and data["test"] in ("smoke", "lifecycle-smoke") and (
        args.session_evidence != "verified" or args.s3_evidence != "verified" or args.cleanup != "completed"
    ):
        raise ValueError("lifecycle smoke requires verified session/S3 evidence and completed cleanup")
    data.update({"result": args.result, "finished_at": now(), "cleanup": args.cleanup,
                 "session_evidence": args.session_evidence, "s3_evidence": args.s3_evidence})
    if args.task_arn:
        data["task_arn"] = args.task_arn
    if args.investigation_id:
        data["investigation_id"] = args.investigation_id
    write_json(path, data)
    print(f"Recorded {args.result}; cleanup {args.cleanup}")


def show_run(args):
    profile(args.profile)
    print(json.dumps(read_json(run_path(args.profile, args.run_id)), indent=2))


def list_runs(args):
    profile(args.profile)
    path = runs_path(args.profile)
    if not path.exists():
        return
    for file in sorted(path.glob("*.json")):
        data = read_json(file)
        print(f"{data['run_id']} {data['created_at']} {data['test']} {data['result']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="kind", required=True)
    profiles = sub.add_parser("profile").add_subparsers(dest="action", required=True)
    add = profiles.add_parser("add", help="Create an immutable dev-only profile (0600)")
    add.add_argument("--name", required=True)
    add.add_argument("--account-id", required=True)
    add.add_argument("--region", required=True)
    add.add_argument("--oidc-base-url", required=True)
    add.add_argument("--realm", required=True)
    add.add_argument("--client-id", required=True)
    add.set_defaults(func=add_profile)
    show = profiles.add_parser("show", help="Show non-OIDC profile coordinates")
    show.add_argument("--name", required=True)
    show.set_defaults(func=show_profile)
    runs = sub.add_parser("run").add_subparsers(dest="action", required=True)
    start = runs.add_parser("start", help="Record a planned/started live run (no AWS calls)")
    start.add_argument("--profile", required=True)
    start.add_argument("--revision", required=True)
    start.add_argument("--source-sha256", required=True)
    start.add_argument("--test", required=True)
    start.add_argument("--image-digest")
    start.add_argument("--lambda-code-sha256")
    start.add_argument("--task-definition-arn")
    start.add_argument("--cli-sha256")
    start.set_defaults(func=start_run)
    update = runs.add_parser("update", help="Save task/investigation IDs as soon as they are created")
    update.add_argument("--profile", required=True)
    update.add_argument("--run-id", required=True)
    update.add_argument("--task-arn")
    update.add_argument("--investigation-id")
    update.set_defaults(func=update_run)
    finish = runs.add_parser("finish", help="Record final outcome and cleanup")
    finish.add_argument("--profile", required=True)
    finish.add_argument("--run-id", required=True)
    finish.add_argument("--result", choices=RESULTS, required=True)
    finish.add_argument("--cleanup", choices=CLEANUP, required=True)
    finish.add_argument("--session-evidence", choices=EVIDENCE, required=True)
    finish.add_argument("--s3-evidence", choices=EVIDENCE, required=True)
    finish.add_argument("--task-arn")
    finish.add_argument("--investigation-id")
    finish.set_defaults(func=finish_run)
    for name, func in (("show", show_run), ("list", list_runs)):
        item = runs.add_parser(name)
        item.add_argument("--profile", required=True)
        if name == "show":
            item.add_argument("--run-id", required=True)
        item.set_defaults(func=func)
    args = parser.parse_args()
    try:
        args.func(args)
    except (OSError, ValueError, KeyError, binascii.Error, json.JSONDecodeError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()

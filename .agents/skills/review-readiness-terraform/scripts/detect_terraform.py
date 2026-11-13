#!/usr/bin/env python3
"""Cheap, fail-closed Terraform-related change gate for rosa-boundary.

Print one compact JSON object. Never read Terraform variable values, state, or plans.
Only a positive classification should lead to the full review workflow.
"""

import argparse
import json
import re
import shlex
import subprocess
import sys
from pathlib import PurePosixPath

REPO = "openshift-online/rosa-boundary"
ROOTS = (
    "deploy/account/",
    "deploy/network/",
    "deploy/regional/",
    "hcp-terraform/",
    "components/trusted-actions/terraform/",
    "tests/localstack/terraform/",
)
AUTOMATION = re.compile(r"(?:^|/)(?:Makefile|[^/]+\.mk)$|^\.tekton/|^\.github/workflows/|^scripts/")
RELATED = re.compile(r"terraform|tfvars|TF_VAR_|hcp-terraform|app\.terraform\.io|tfe_workspace|deploy/(?:account|network|regional)", re.I)
TF_SUFFIX = re.compile(r"\.(?:tf|tf\.json|tfvars|tfvars\.json|tftest\.hcl|tfvars\.example|hcl)$")


def run(*args):
    proc = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode:
        raise ValueError(f"{' '.join(args[:3])} failed: {proc.stderr.strip()[:240]}")
    return proc.stdout


def git_paths(*args):
    # Git -z output must not be decoded by line; filenames may contain newlines.
    proc = subprocess.run(("git", *args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode:
        raise ValueError(f"git {args[0]} failed: {proc.stderr.decode(errors='replace')[:240]}")
    return [p.decode("utf-8", errors="surrogateescape") for p in proc.stdout.split(b"\0") if p]


def parse_patch(text):
    """Return paths and patch hunks; reject non-Git or ambiguous patch input."""
    result = {}
    path = None
    for line in text.splitlines():
        if line.startswith("diff --git "):
            try:
                tokens = shlex.split(line)
                if len(tokens) != 4 or not tokens[2].startswith("a/") or not tokens[3].startswith("b/"):
                    raise ValueError("unexpected diff --git header")
            except ValueError as exc:
                raise ValueError(f"unreadable Git patch header: {exc}") from exc
            path = tokens[3][2:]
            result.setdefault(path, [])
            result.setdefault(tokens[2][2:], [])  # renamed/deleted old path matters too
        elif path and line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
            result[path].append(line[1:])
    if not result:
        raise ValueError("no Git diff headers found; supply a Git-format patch or --paths-file")
    return {p: "\n".join(lines) for p, lines in result.items()}


def related(path, changed_lines=None):
    path = path.removeprefix("./")
    if path.startswith("/") or ".." in PurePosixPath(path).parts:
        raise ValueError("diff contains an unsafe path")
    if TF_SUFFIX.search(path):
        return "Terraform/HCL input"
    if path.startswith(ROOTS):
        if path.endswith((".md", ".txt", ".png", ".svg")):
            return None
        if PurePosixPath(path).name in {"OWNERS", ".gitignore"}:
            return None
        return "Terraform root input/automation"
    if path.startswith(("tests/", "scripts/")) and "terraform" in PurePosixPath(path).name.lower():
        return "Terraform test/automation"
    if AUTOMATION.search(path):
        if "terraform" in path.lower() or "tfvars" in path.lower():
            return "Terraform automation"
        if changed_lines is None:  # missing PR patch/binary/manual path list: never claim absent
            return "possible Terraform automation (patch unavailable)"
        if RELATED.search(changed_lines):
            return "Terraform automation changed lines"
    return None


def classify(files):
    matches = [{"path": path, "reason": reason} for path, patch in sorted(files.items())
               if (reason := related(path, patch))]
    return {"terraform": bool(matches), "uncertain": False,
            "changed_paths": len(files), "matches": matches}


def inputs(args):
    if args.pr is not None:
        if args.repo != REPO:
            raise ValueError(f"this skill reviews {REPO} only")
        lines = run("gh", "api", f"repos/{REPO}/pulls/{args.pr}/files", "--paginate",
                    "--jq", ".[] | {filename, previous_filename, patch} | @json")
        files = {}
        for line in lines.splitlines():
            item = json.loads(line)
            files[item["filename"]] = item.get("patch")
            if item.get("previous_filename"):
                files[item["previous_filename"]] = item.get("patch")
        if not files:
            raise ValueError("PR returned no changed files; cannot classify")
        return files
    if args.patch:
        patches = []
        for name in args.patch:
            with open(name, encoding="utf-8") as stream:
                patches.append(stream.read())
        return parse_patch("\n".join(patches))
    if args.paths_file:
        with open(args.paths_file, encoding="utf-8") as stream:
            paths = [line.rstrip("\n") for line in stream if line.strip()]
        if not paths:
            raise ValueError("empty paths file cannot prove absence of Terraform changes")
        return dict.fromkeys(paths)
    if args.working_tree:
        paths = set(git_paths("diff", "--no-ext-diff", "--name-only", "-z", "HEAD", "--"))
        untracked = set(git_paths("ls-files", "--others", "--exclude-standard", "-z", "--"))
        files = {p: None if p in untracked else
                 run("git", "diff", "--no-ext-diff", "--unified=0", "HEAD", "--", p) if AUTOMATION.search(p) else ""
                 for p in paths | untracked}
        return files
    if args.branch:
        base = run("git", "merge-base", args.base, args.branch).strip()
        diff = (base, args.branch)
    elif args.commit:
        parents = run("git", "rev-list", "--parents", "-n", "1", args.commit).split()
        if len(parents) > 2:
            raise ValueError("merge commit: specify an explicit --range and base")
        if len(parents) < 2:
            raise ValueError("root commit: supply a Git-format patch or an explicit --range")
        diff = (parents[1], parents[0])
    else:
        diff = (args.range,)
    paths = git_paths("diff", "--no-ext-diff", "--name-only", "-z", *diff, "--")
    return {p: run("git", "diff", "--no-ext-diff", "--unified=0", *diff, "--", p) if AUTOMATION.search(p) else ""
            for p in paths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pr", type=int)
    source.add_argument("--branch")
    source.add_argument("--commit")
    source.add_argument("--range")
    source.add_argument("--working-tree", action="store_true")
    source.add_argument("--patch", nargs="+", metavar="PATH")
    source.add_argument("--paths-file")
    parser.add_argument("--base", help="required for --branch")
    parser.add_argument("--repo", default=REPO)
    args = parser.parse_args()
    if args.branch and not args.base:
        parser.error("--branch requires --base")
    try:
        print(json.dumps(classify(inputs(args)), separators=(",", ":")))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"terraform": None, "uncertain": True, "error": str(exc)}))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

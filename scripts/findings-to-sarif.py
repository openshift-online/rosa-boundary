#!/usr/bin/env python3
"""Convert adversary-findings.json to SARIF 2.1.0 for GitHub code scanning.

Supports three modes:
  - Default: convert adversary-findings.json → adversary-findings.sarif
  - --from-markdown: migrate adversary-findings/{medium,low}/*.md → adversary-findings.json
  - --validate: check adversary-findings.json schema without producing SARIF
"""

import argparse
import json
import re
import sys
from pathlib import Path

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
TOOL_NAME = "rosa-boundary-adversary"
TOOL_URI = "https://github.com/openshift/rosa-boundary"
TOOL_VERSION = "1.0.0"

SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

SEVERITY_TO_SCORE = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
}

REQUIRED_FINDING_FIELDS = {"id", "title", "severity", "category", "file", "line",
                           "issue", "impact", "recommendation"}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_findings(data: dict) -> list[str]:
    """Return a list of validation errors (empty = valid)."""
    errors = []
    if not isinstance(data, dict):
        return ["Root element must be a JSON object"]
    if "findings" not in data:
        errors.append("Missing required field: 'findings'")
        return errors
    if not isinstance(data["findings"], list):
        errors.append("'findings' must be an array")
        return errors
    for i, f in enumerate(data["findings"]):
        prefix = f"findings[{i}]"
        if not isinstance(f, dict):
            errors.append(f"{prefix}: must be an object")
            continue
        for field in REQUIRED_FINDING_FIELDS:
            if field not in f or f[field] is None:
                errors.append(f"{prefix}: missing required field '{field}'")
        if "severity" in f and f["severity"] not in SEVERITY_TO_LEVEL:
            errors.append(
                f"{prefix}: invalid severity '{f['severity']}' "
                f"(must be one of {', '.join(SEVERITY_TO_LEVEL)})"
            )
        if "line" in f and not isinstance(f["line"], int):
            errors.append(f"{prefix}: 'line' must be an integer")
    return errors


# ---------------------------------------------------------------------------
# SARIF generation
# ---------------------------------------------------------------------------

def derive_tags(category: str) -> list[str]:
    """Derive SARIF tags from a category string like 'Infrastructure - Overly Permissive IAM Policy'."""
    tags = ["security"]
    parts = re.split(r"\s*[—–-]\s*", category)
    for part in parts:
        words = part.strip().lower().split()
        if words:
            tags.append(words[0])
    return list(dict.fromkeys(tags))  # dedupe preserving order


def build_sarif(findings: list[dict]) -> dict:
    """Build a SARIF 2.1.0 document from a list of finding dicts."""
    # Deduplicate rules by finding id
    seen_rules: dict[str, int] = {}
    rules = []
    results = []

    for finding in findings:
        fid = finding["id"]
        severity = finding["severity"].lower()
        level = SEVERITY_TO_LEVEL.get(severity, "note")
        score = SEVERITY_TO_SCORE.get(severity, "1.0")

        # Build or reuse rule
        if fid not in seen_rules:
            rule = {
                "id": fid,
                "name": re.sub(r"[^a-zA-Z0-9]", "", finding["title"].title().replace(" ", "")),
                "shortDescription": {"text": finding["title"]},
                "fullDescription": {"text": finding["issue"]},
                "help": {
                    "text": finding["recommendation"],
                    "markdown": finding["recommendation"],
                },
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": derive_tags(finding["category"]),
                    "security-severity": score,
                },
            }
            seen_rules[fid] = len(rules)
            rules.append(rule)

        # Build result
        region = {"startLine": finding["line"]}
        if finding.get("end_line"):
            region["endLine"] = finding["end_line"]

        result = {
            "ruleId": fid,
            "ruleIndex": seen_rules[fid],
            "level": level,
            "message": {"text": f"{finding['issue']}\n\n**Impact**: {finding['impact']}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding["file"],
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": region,
                    }
                }
            ],
        }
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URI,
                        "version": TOOL_VERSION,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


# ---------------------------------------------------------------------------
# Markdown migration
# ---------------------------------------------------------------------------

def parse_file_refs(ref_line: str) -> list[dict]:
    """Parse file references from a markdown **File**/**Files** line.

    Handles:
      `path:line`        → line=N
      `path:start-end`   → line=start, end_line=end
      `path`             → line=1
    Multiple refs separated by `, ` are returned as separate entries.
    """
    refs = re.findall(r"`([^`]+)`", ref_line)
    entries = []
    for ref in refs:
        match = re.match(r"^(.+?):(\d+)(?:-(\d+))?$", ref)
        if match:
            path, start, end = match.group(1), int(match.group(2)), match.group(3)
            entries.append({
                "file": path,
                "line": start,
                "end_line": int(end) if end else None,
            })
        else:
            entries.append({"file": ref, "line": 1, "end_line": None})
    return entries


def parse_markdown_finding(filepath: Path) -> list[dict]:
    """Parse a single markdown finding file into one or more finding dicts.

    Returns multiple dicts when the finding references multiple files.
    """
    text = filepath.read_text()

    # ID and title: # M1: Title  or  # L3: Title
    m = re.search(r"^#\s+((?:M|L|H|C|I)\d+):\s+(.+)$", text, re.MULTILINE)
    if not m:
        print(f"  WARNING: could not parse id/title from {filepath}", file=sys.stderr)
        return []
    fid, title = m.group(1), m.group(2).strip()

    # Severity
    m = re.search(r"\*\*Severity\*\*:\s*(\w+)", text)
    severity = m.group(1).lower() if m else "info"

    # Category
    m = re.search(r"\*\*Category\*\*:\s*(.+?)$", text, re.MULTILINE)
    category = m.group(1).strip() if m else "Uncategorized"

    # File references (handles **File** and **Files**)
    m = re.search(r"\*\*Files?\*\*:\s*(.+?)$", text, re.MULTILINE)
    file_refs = parse_file_refs(m.group(1)) if m else [{"file": "unknown", "line": 1, "end_line": None}]

    # Sections: Issue, Impact, Recommendation
    def extract_section(name: str) -> str:
        pattern = rf"## {name}\s*\n(.*?)(?=\n## |\Z)"
        m = re.search(pattern, text, re.DOTALL)
        return m.group(1).strip() if m else ""

    issue = extract_section("Issue")
    impact = extract_section("Impact")
    recommendation = extract_section("Recommendation")

    # Produce one finding dict per file reference
    findings = []
    for ref in file_refs:
        findings.append({
            "id": fid,
            "title": title,
            "severity": severity,
            "category": category,
            "file": ref["file"],
            "line": ref["line"],
            "end_line": ref["end_line"],
            "issue": issue,
            "impact": impact,
            "recommendation": recommendation,
        })
    return findings


def migrate_from_markdown(findings_dir: Path) -> dict:
    """Parse all markdown findings and return the findings JSON structure."""
    findings = []
    md_files = sorted(findings_dir.glob("**/*.md"))
    md_files = [f for f in md_files if f.name != "README.md"]

    if not md_files:
        print(f"ERROR: no markdown files found in {findings_dir}", file=sys.stderr)
        sys.exit(1)

    for md_file in md_files:
        parsed = parse_markdown_finding(md_file)
        findings.extend(parsed)
        for p in parsed:
            print(f"  Parsed: {p['id']} — {p['title']} ({p['file']}:{p['line']})")

    # Sort by id for stable output
    findings.sort(key=lambda f: (f["id"][0], int(re.search(r"\d+", f["id"]).group())))

    return {
        "scan_date": "2026-04-15",
        "commit": "bacef1e",
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Convert adversary findings to SARIF 2.1.0"
    )
    parser.add_argument(
        "--input", "-i",
        default="adversary-findings.json",
        help="Input findings JSON file (default: adversary-findings.json)",
    )
    parser.add_argument(
        "--output", "-o",
        default="adversary-findings.sarif",
        help="Output SARIF file (default: adversary-findings.sarif)",
    )
    parser.add_argument(
        "--from-markdown",
        metavar="DIR",
        help="Migrate markdown findings from DIR to JSON (e.g., adversary-findings/)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate the input JSON schema without producing SARIF",
    )
    args = parser.parse_args()

    # Migration mode: markdown → JSON
    if args.from_markdown:
        findings_dir = Path(args.from_markdown)
        if not findings_dir.is_dir():
            print(f"ERROR: {findings_dir} is not a directory", file=sys.stderr)
            sys.exit(1)
        print(f"Migrating markdown findings from {findings_dir}...")
        data = migrate_from_markdown(findings_dir)
        output_path = Path(args.input)
        output_path.write_text(json.dumps(data, indent=2) + "\n")
        print(f"Wrote {len(data['findings'])} findings to {output_path}")
        return

    # Load JSON
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: {input_path} not found", file=sys.stderr)
        sys.exit(1)

    data = json.loads(input_path.read_text())

    # Validate mode
    errors = validate_findings(data)
    if errors:
        print("Validation errors:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)

    if args.validate:
        print(f"OK: {len(data['findings'])} findings, all valid")
        return

    # Convert to SARIF
    sarif = build_sarif(data["findings"])
    output_path = Path(args.output)
    output_path.write_text(json.dumps(sarif, indent=2) + "\n")
    print(f"Wrote SARIF with {len(sarif['runs'][0]['results'])} results to {output_path}")


if __name__ == "__main__":
    main()

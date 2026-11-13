"""Claude Code's native download pin and Mintmaker update contract."""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "renovate.json").read_text())
DEP = "anthropics/claude-code"


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_claude_extraction(newline):
    manager, = [m for m in CONFIG["customManagers"] if m["depNameTemplate"] == DEP]
    assert manager["managerFilePatterns"] == ["/^Containerfile$/"]
    assert manager["datasourceTemplate"] == "github-releases"
    assert manager["versioningTemplate"] == "semver-coerced"
    pattern, = manager["matchStrings"]
    pattern = pattern.replace("(?<currentValue>", "(?P<currentValue>")
    content = ('# renovate: datasource=github-releases depName=anthropics/claude-code\n'
               'ENV CLAUDE_CODE_VERSION="2.1.323"\n').replace("\n", newline)
    assert re.search(pattern, content)["currentValue"] == "2.1.323"
    checked_in = (ROOT / "Containerfile").read_text()
    assert len(re.findall(pattern, checked_in)) == 1
    for mutation in [
        content.replace(DEP, "untrusted/claude-code"),
        content.replace("CLAUDE_CODE_VERSION", "OTHER_VERSION"),
        content.replace("2.1.323", "2.1.323-rc.1"),
        content.replace("ENV ", "ARG "),
        'ENV CLAUDE_CODE_VERSION="2.1.323"\n',
    ]:
        assert re.search(pattern, mutation) is None


def test_claude_review_policy():
    policy, = [r for r in CONFIG["packageRules"] if r.get("matchPackageNames") == [DEP]]
    assert policy["matchManagers"] == ["custom.regex"]
    assert policy["automerge"] is False
    assert policy["groupName"] is None
    assert policy["ignoreUnstable"] is True
    assert policy["minimumReleaseAgeBehaviour"] == "timestamp-required"
    assert "minimumReleaseAge" not in policy


def test_claude_verified_native_install():
    content = (ROOT / "Containerfile").read_text()
    stage = content.split("FROM tools-base AS claude-builder\n", 1)[1].split("\nFROM ", 1)[0]
    assert 'releases/tags/v${CLAUDE_CODE_VERSION}' in stage
    assert 'ENV CLAUDE_CODE_CHECKSUM_FILE="SHASUMS256.txt"' in stage
    assert 'ENV CLAUDE_CODE_CHECKSUM_ALGORITHM="sha256"' in stage
    assert '--checksum_file "${CLAUDE_CODE_CHECKSUM_FILE}"' in stage
    assert '--checksum_algorithm "${CLAUDE_CODE_CHECKSUM_ALGORITHM}"' in stage
    assert 'COPY --from=claude-builder /opt/claude /usr/local/lib/claude-code' in content
    assert 'ln --symbolic /usr/local/lib/claude-code/claude /usr/local/bin/claude' in content

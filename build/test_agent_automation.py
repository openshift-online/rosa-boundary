"""Coding agents' native download pins and Mintmaker update contract.

Claude Code, OpenCode, the OpenAI Codex CLI and pi all ship as exact upstream
release archives verified against a published SHA256 manifest, each with one
annotated ENV pin and one dedicated custom manager. This is deliberately
separate from the six-tool SRE exact-pin contract.
"""
import json
import os
import re
import shlex
import subprocess
from pathlib import Path

import pytest
from verify_sre_tools import AGENTS, AGENT_DEPS, agent_pins

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "renovate.json").read_text())
CONTAINERFILE = (ROOT / "Containerfile").read_text()
PINS = agent_pins(ROOT / "Containerfile")

# Per agent: builder stage, upstream release tag form, published checksum
# manifest, asset selector flag, installed payload and PATH entry, plus the
# architecture-specific asset names the upstream release actually publishes.
INSTALLS = {
    "claude": dict(
        stage="claude-builder",
        tag="v${CLAUDE_CODE_VERSION}",
        checksum_file="SHASUMS256.txt",
        selector="--platform",
        copy="COPY --from=claude-builder /opt/claude /usr/local/lib/claude-code",
        link="ln --symbolic /usr/local/lib/claude-code/claude /usr/local/bin/claude",
        assets={"amd64": "claude-linux-x64.tar.gz",
                "arm64": "claude-linux-arm64.tar.gz"},
    ),
    "opencode": dict(
        stage="opencode-builder",
        tag="v${OPENCODE_VERSION}",
        checksum_file="SHA256SUMS",
        selector="--exact_asset",
        copy="COPY --from=opencode-builder /opt/opencode /usr/local/lib/opencode",
        link="ln --symbolic /usr/local/lib/opencode/opencode /usr/local/bin/opencode",
        assets={"amd64": "opencode-linux-x64.tar.gz",
                "arm64": "opencode-linux-arm64.tar.gz"},
    ),
    "codex": dict(
        stage="codex-builder",
        tag="rust-v${CODEX_VERSION}",
        checksum_file="codex-package_SHA256SUMS",
        selector="--exact_asset",
        copy="COPY --from=codex-builder    /opt/codex    /usr/local/lib/codex",
        link="ln --symbolic /usr/local/lib/codex/bin/codex /usr/local/bin/codex",
        assets={"amd64": "codex-package-x86_64-unknown-linux-musl.tar.gz",
                "arm64": "codex-package-aarch64-unknown-linux-musl.tar.gz"},
    ),
    "pi": dict(
        stage="pi-builder",
        tag="v${PI_VERSION}",
        checksum_file="SHA256SUMS",
        selector="--exact_asset",
        copy="COPY --from=pi-builder       /opt/pi       /usr/local/lib/pi",
        link="ln --symbolic /usr/local/lib/pi/pi /usr/local/bin/pi",
        assets={"amd64": "pi-linux-x64.tar.gz", "arm64": "pi-linux-arm64.tar.gz"},
    ),
}

# Tags from the same upstream repository that must never become a pin. Entries
# are templated on the live pin so a routine version bump needs no test edit:
# OpenCode publishes unrelated process-daemon releases and Codex publishes
# frequent rust-v*-alpha prereleases.
REJECTED_TAGS = {
    "claude": [],
    "opencode": ["process-daemon-v0.5.2", "v{version}-rc.1", "opencode-v{version}"],
    "codex": ["rust-v0.171.0-alpha.5", "v{version}", "rust-v{major}.{minor}"],
    "pi": ["pi-v{version}", "v{version}-beta.1"],
}

PLATFORM_CALL = re.compile(r'\$\(platform_convert "@@PLATFORM@@"\s+([^)]*)\)')
PLATFORM_FLAGS = {"--amd64": ("amd64", "amd64"), "--x86_64": ("amd64", "x86_64"),
                  "--arm64": ("arm64", "arm64"), "--aarch64": ("arm64", "aarch64")}


def prefix(agent):
    return AGENTS[agent].removesuffix("_VERSION")


def upstream_tag(agent):
    """The release tag the builder stage resolves to for the checked-in pin."""
    return INSTALLS[agent]["tag"].replace("${" + AGENTS[agent] + "}", PINS[agent])


def rejected_tags(agent):
    major, minor, _ = PINS[agent].split(".")
    return [tag.format(version=PINS[agent], major=major, minor=minor)
            for tag in REJECTED_TAGS[agent]]


def stage_text(agent):
    stage = INSTALLS[agent]["stage"]
    return CONTAINERFILE.split(f"FROM tools-base AS {stage}\n", 1)[1].split("\nFROM ", 1)[0]


def manager(agent):
    found, = [m for m in CONFIG["customManagers"]
              if m["depNameTemplate"] == AGENT_DEPS[agent]]
    return found


def python_pattern(pattern):
    """Python spelling of RE2 named capture; actual Renovate tested separately."""
    return pattern.replace("(?<currentValue>", "(?P<currentValue>").replace(
        "(?<version>", "(?P<version>")


def architecture_values(expression):
    """Resolve both arms of a platform_convert invocation without running uname."""
    tokens = shlex.split(expression)
    values = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in ("--custom-amd64", "--custom-arm64"):
            values["amd64" if token.endswith("-amd64") else "arm64"] = tokens[index + 1]
            index += 2
            continue
        if token in PLATFORM_FLAGS:
            architecture, value = PLATFORM_FLAGS[token]
            values[architecture] = value
        index += 1
    return values


def test_agent_set_matches_managers():
    """Every agent has one manager, and agents never absorb an SRE tool pin."""
    assert set(AGENTS) == set(AGENT_DEPS) == set(INSTALLS) == set(REJECTED_TAGS)
    declared = {m["depNameTemplate"] for m in CONFIG["customManagers"]}
    assert set(AGENT_DEPS.values()) <= declared
    assert not set(AGENT_DEPS.values()) & {
        "openshift-online/ocm-cli", "openshift/backplane-cli", "openshift/osdctl",
        "mikefarah/yq", "aws/aws-cli", "openshift/oc"}


@pytest.mark.parametrize("agent", sorted(AGENTS))
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_pin_extraction(agent, newline):
    config = manager(agent)
    assert config["managerFilePatterns"] == ["/^Containerfile$/"]
    assert config["datasourceTemplate"] == "github-releases"
    assert config["versioningTemplate"] == "semver-coerced"
    pattern, = [python_pattern(p) for p in config["matchStrings"]]
    version = PINS[agent]
    content = (f'# renovate: datasource=github-releases depName={AGENT_DEPS[agent]}\n'
               f'ENV {AGENTS[agent]}="{version}"\n').replace("\n", newline)
    assert re.search(pattern, content)["currentValue"] == version
    assert len(re.findall(pattern, CONTAINERFILE)) == 1
    for mutation in [
        content.replace(AGENT_DEPS[agent], "untrusted/" + AGENT_DEPS[agent].split("/")[-1]),
        content.replace(AGENTS[agent], "OTHER_VERSION"),
        content.replace(version, version + "-rc.1"),
        content.replace("ENV ", "ARG "),
        f'ENV {AGENTS[agent]}="{version}"\n',
    ]:
        assert re.search(pattern, mutation) is None


@pytest.mark.parametrize("agent", sorted(AGENTS))
def test_release_tag_transform(agent):
    """The stage's tag form and the manager's extraction agree on the pin."""
    version = PINS[agent]
    assert f'releases/tags/{INSTALLS[agent]["tag"]}' in stage_text(agent)
    accepted = upstream_tag(agent)
    extract = manager(agent).get("extractVersionTemplate")
    if extract is None:
        # Without a template the datasource must already yield the pin, which
        # only holds for a bare 'v<semver>' tag in a single-product repository.
        assert accepted == "v" + version
        return
    pattern = re.compile(python_pattern(extract))
    assert pattern.fullmatch(accepted)["version"] == version
    for tag in rejected_tags(agent):
        assert pattern.fullmatch(tag) is None, tag


@pytest.mark.parametrize("agent", sorted(AGENTS))
def test_supported_architecture_assets(agent):
    """Both build architectures resolve to assets the upstream release publishes."""
    stage = stage_text(agent)
    selector = INSTALLS[agent]["selector"]
    # The selector value embeds a quoted platform_convert call, so match the
    # whole line rather than the first inner quote.
    expression, = re.findall(rf'^\s*{selector} "(.+)"\s*$', stage, re.MULTILINE)
    call = PLATFORM_CALL.search(expression)
    assert call, "architecture-specific assets must go through platform_convert"
    values = architecture_values(call[1])
    assert set(values) == {"amd64", "arm64"}
    resolved = {architecture: PLATFORM_CALL.sub(value, expression)
                for architecture, value in values.items()}
    assert resolved == INSTALLS[agent]["assets"]


@pytest.mark.parametrize("agent", sorted(AGENTS))
def test_verified_native_install(agent):
    spec = INSTALLS[agent]
    stage = stage_text(agent)
    name = prefix(agent)
    assert f'releases/tags/{spec["tag"]}' in stage
    assert f'ENV {name}_CHECKSUM_FILE="{spec["checksum_file"]}"' in stage
    assert f'ENV {name}_CHECKSUM_ALGORITHM="sha256"' in stage
    assert f'--checksum_file "${{{name}_CHECKSUM_FILE}}"' in stage
    assert f'--checksum_algorithm "${{{name}_CHECKSUM_ALGORITHM}}"' in stage
    assert spec["copy"] in CONTAINERFILE
    assert spec["link"] in CONTAINERFILE
    # No floating release, no unverified fetch, and no package-manager install.
    assert "releases/latest" not in stage
    for forbidden in ("curl", "wget", "npm ", "npx ", "pip install"):
        assert forbidden not in stage


@pytest.mark.parametrize("agent", sorted(AGENTS))
def test_builder_stage_isolation(agent):
    """Agents build from tools-base and ship only their /opt payload."""
    stage = INSTALLS[agent]["stage"]
    assert f"FROM tools-base AS {stage}\n" in CONTAINERFILE
    copies = re.findall(rf"^COPY --from={stage}\s+(\S+)\s+(\S+)$", CONTAINERFILE, re.MULTILINE)
    assert len(copies) == 1
    source, _ = copies[0]
    assert source.startswith("/opt/")


def test_agent_review_policy():
    policy, = [r for r in CONFIG["packageRules"]
               if set(r.get("matchPackageNames", [])) == set(AGENT_DEPS.values())]
    assert policy["matchManagers"] == ["custom.regex"]
    assert policy["automerge"] is False
    assert policy["groupName"] is None
    assert policy["ignoreUnstable"] is True
    assert policy["minimumReleaseAgeBehaviour"] == "timestamp-required"
    # Do not replace the inherited service release-age interval with a guess.
    assert "minimumReleaseAge" not in policy


def test_renovate_agent_tag_transforms(tmp_path):
    """Opt-in actual Renovate tag extraction; no writes or network.

    Set RENOVATE_RUNTIME_DIR to an installed renovate package directory. This
    proves the configured extractVersion both maps an upstream tag onto the pin
    and drops releases that are not that product's stable releases.
    """
    runtime = os.environ.get("RENOVATE_RUNTIME_DIR")
    if not runtime:
        pytest.skip("set RENOVATE_RUNTIME_DIR for actual Renovate runtime contracts")
    cases = []
    for agent in sorted(AGENTS):
        extract = manager(agent).get("extractVersionTemplate")
        if extract is None:
            continue
        cases.append(dict(extractVersion=extract, accepted=upstream_tag(agent),
                          version=PINS[agent], rejected=rejected_tags(agent)))
    assert cases, "agents with prefixed or shared release tags need extractVersion"
    script = tmp_path / "tags.mjs"
    script.write_text(r'''
import assert from 'node:assert/strict';
import fs from 'node:fs';
const { cases, base } = JSON.parse(fs.readFileSync(0, 'utf8'));
const { applyExtractVersion } = await import(base + '/dist/modules/datasource/common.js');
for (const { extractVersion, accepted, version, rejected } of cases) {
  const releases = [{ version: accepted }, ...rejected.map((version) => ({ version }))];
  const result = applyExtractVersion({ releases }, extractVersion);
  assert.deepEqual(result.releases.map((release) => release.version), [version]);
  assert.equal(result.releases[0].versionOrig, accepted);
}
''')
    subprocess.run(["node", str(script)],
                   input=json.dumps({"base": Path(runtime).resolve().as_uri(), "cases": cases}),
                   text=True, check=True, capture_output=True)

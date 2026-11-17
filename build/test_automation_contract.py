"""Offline SRE-tool and coding-agent pin extraction and review-policy contracts."""
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
from verify_sre_tools import AGENTS, AGENT_DEPS

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "renovate.json").read_text())
# Coding agents keep their own managers and contract tests; the six-tool
# assertions below must never silently absorb one of them.
SRE_MANAGERS = [m for m in CONFIG["customManagers"]
                if m["depNameTemplate"] not in set(AGENT_DEPS.values())]
TOOLS = {
    "OCM_VERSION": "openshift-online/ocm-cli",
    "BACKPLANE_CLI_VERSION": "openshift/backplane-cli",
    "OSDCTL_VERSION": "openshift/osdctl",
    "YQ_VERSION": "mikefarah/yq",
    "AWSCLI_VERSION": "aws/aws-cli",
    "OC_VERSION": "openshift/oc",
}


def extract(content):
    for arg in TOOLS:
        assert len(re.findall(rf'^ARG {arg}=', content, re.MULTILINE)) == 1
    found = []
    for manager in SRE_MANAGERS:
        assert manager["managerFilePatterns"] == ["/^Containerfile$/"]
        for pattern in manager["matchStrings"]:
            # Python spelling of RE2 named capture; actual Renovate tested separately.
            pattern = pattern.replace("(?<currentValue>", "(?P<currentValue>")
            found.extend((manager["depNameTemplate"], m["currentValue"])
                         for m in re.finditer(pattern, content))
    assert len(found) == 6, "missing or duplicated annotated tool ARG"
    assert {dep for dep, _ in found} == set(TOOLS.values())
    return found


def fixture():
    lines = []
    for manager in SRE_MANAGERS:
        dep = manager["depNameTemplate"]
        arg = next(arg for arg, name in TOOLS.items() if name == dep)
        version = "4.8.7" if arg == "OC_VERSION" else "2.8.7" if arg == "AWSCLI_VERSION" else "v4.8.7"
        lines.append(f'# renovate: datasource={manager["datasourceTemplate"]} depName={dep}\nARG {arg}="{version}"\n')
    return "".join(lines)


AGENT_VERSION = "9.8.7"


def agent_fixture():
    """Annotated agent ENV pins, which use a different directive than the tools."""
    return "".join(f'# renovate: datasource=github-releases depName={AGENT_DEPS[agent]}\n'
                   f'ENV {name}="{AGENT_VERSION}"\n' for agent, name in AGENTS.items())


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_extraction(newline):
    assert len(extract(fixture().replace("\n", newline))) == 6


AGENT_MANAGERS = [m for m in CONFIG["customManagers"]
                  if m["depNameTemplate"] in set(AGENT_DEPS.values())]


def matches(managers, content):
    found = []
    for manager in managers:
        for pattern in manager["matchStrings"]:
            pattern = pattern.replace("(?<currentValue>", "(?P<currentValue>")
            found.extend(re.findall(pattern, content))
    return found


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_agent_pins_never_match_tool_managers(newline):
    """Agent ENV pins stay invisible to the six-tool managers, and vice versa."""
    tools = fixture().replace("\n", newline)
    agents = agent_fixture().replace("\n", newline)
    assert len(extract(tools + agents)) == 6
    assert len(AGENT_MANAGERS) == len(AGENTS)
    assert matches(SRE_MANAGERS, agents) == []
    assert matches(AGENT_MANAGERS, tools) == []
    assert len(matches(AGENT_MANAGERS, agents)) == len(AGENTS)


def test_checked_in_pins():
    extract((ROOT / "Containerfile").read_text())


@pytest.mark.parametrize("mutation", [
    lambda s: s + s,
    lambda s: s + 'ARG OCM_VERSION="v9.8.7"\n',
    lambda s: s.replace("ARG OCM_VERSION", "ARG UNRELATED_VERSION"),
    lambda s: s.replace("openshift-online/ocm-cli", "untrusted/ocm-cli"),
    lambda s: s.replace('ARG OCM_VERSION="v4.8.7"', 'ARG OCM_VERSION="4.8.7"'),
])
def test_missing_duplicate_or_unrelated_rejected(mutation):
    with pytest.raises(AssertionError):
        extract(mutation(fixture()))


def test_renovate_runtime(tmp_path):
    """Opt-in actual Renovate extraction/JSONata/age policy; no writes or network.

    Set RENOVATE_RUNTIME_DIR to an installed renovate package directory.
    """
    runtime = os.environ.get("RENOVATE_RUNTIME_DIR")
    if not runtime:
        pytest.skip("set RENOVATE_RUNTIME_DIR for actual Renovate runtime contracts")
    module = Path(runtime).resolve().as_uri()
    script = tmp_path / "runtime.mjs"
    script.write_text(r'''
import assert from 'node:assert/strict';
import fs from 'node:fs';
const { config, content, base, agents, agentVersion, expected } = JSON.parse(fs.readFileSync(0, 'utf8'));
const { extractPackageFile } = await import(base + '/dist/modules/manager/custom/regex/index.js');
const { getExpression } = await import(base + '/dist/util/jsonata.js');
const { applyPackageRules } = await import(base + '/dist/util/package-rules/index.js');
const { checkMinimumReleaseAge } = await import(base + '/dist/util/minimum-release-age.js');
const { validateConfig } = await import(base + '/dist/config/validation.js');
const { massageConfig } = await import(base + '/dist/config/massage.js');
assert.equal(config.customManagers.length, expected);
for (const text of [content, content.replaceAll('\n', '\r\n')]) {
  const deps = config.customManagers.flatMap(m => extractPackageFile(text, 'Containerfile', m)?.deps ?? []);
  assert.equal(deps.length, expected);
  assert.equal(new Set(deps.map(d => d.depName)).size, expected);
  for (const agent of agents) {
    assert.equal(deps.find(d => d.depName === agent).currentValue, agentVersion);
  }
}
// The checked-in configuration must be schema-valid for the deployed service.
const validation = await validateConfig('repo', massageConfig(config));
assert.deepEqual(validation.errors, []);
assert.deepEqual(validation.warnings, []);
const transform = getExpression(config.customDatasources['openshift-stable'].transformTemplates[0]);
for (const [lines, expected] of [
  [['Version:  4.8.7'], ['4.8.7']],
  [['Name: 4.8.7', 'Version:  4.8.7'], ['4.8.7']],
  [['Version:  4.8.7', 'Version:  4.8.8'], []],
  [['Version:  4.8.7-rc.1'], []],
  [['Version: invalid'], []],
  [['Name: 4.8.7'], []],
]) {
  const result = await transform.evaluate({ releases: lines.map(version => ({version})) });
  assert.deepEqual(result.releases.map(r => r.version), expected);
}
// Exercise effective matching and Renovate's real age gate, not just JSON.
// Only oc may pass without a timestamp; known timestamps still honor the delay.
const inherited = { ...config, minimumReleaseAge: '3 days',
  minimumReleaseAgeBehaviour: 'timestamp-required',
  manager: 'custom.regex', packageFile: 'Containerfile' };
const fresh = new Date().toISOString();
const old = new Date(Date.now() - 4 * 86400000).toISOString();
const ocRelease = (await transform.evaluate({
  releases: [{ version: 'Version:  4.8.8' }],
})).releases[0];
assert.equal(ocRelease.releaseTimestamp, undefined);
for (const manager of config.customManagers) {
  const effective = await applyPackageRules({ ...inherited,
    depName: manager.depNameTemplate, packageName: manager.depNameTemplate,
    datasource: manager.datasourceTemplate });
  const isOc = manager.depNameTemplate === 'openshift/oc';
  assert.equal(effective.automerge, false);
  assert.equal(effective.ignoreUnstable, true);
  assert.equal(effective.groupName, null);
  assert.equal(effective.minimumReleaseAge, '3 days');
  assert.equal(effective.minimumReleaseAgeBehaviour, isOc ? 'timestamp-optional' : 'timestamp-required');
  assert.equal(checkMinimumReleaseAge(effective, ocRelease.releaseTimestamp).isPending, !isOc);
  assert.equal(checkMinimumReleaseAge(effective, fresh).isPending, true);
  assert.equal(checkMinimumReleaseAge(effective, old).isPending, false);
}
const oc = { ...inherited, depName: 'openshift/oc', packageName: 'openshift/oc',
  datasource: 'custom.openshift-stable' };
for (const mismatch of [
  { manager: 'dockerfile' },
  { datasource: 'github-releases' },
  { packageFile: 'other/Containerfile' },
  { depName: 'other/oc', packageName: 'other/oc' },
]) {
  const effective = await applyPackageRules({ ...oc, ...mismatch });
  assert.equal(effective.minimumReleaseAgeBehaviour, 'timestamp-required');
  assert.equal(checkMinimumReleaseAge(effective, undefined).isPending, true);
}
''')
    subprocess.run(["node", str(script)], input=json.dumps({
        "base": module, "config": CONFIG, "content": fixture() + agent_fixture(),
        "agents": sorted(AGENT_DEPS.values()), "agentVersion": AGENT_VERSION,
        "expected": len(TOOLS) + len(AGENTS),
    }), text=True, check=True, capture_output=True)


def test_image_arg_contract():
    text = (ROOT / "Containerfile").read_text()
    stage = text.split("FROM tools-base AS sre-tools\n", 1)[1].split("\nFROM ", 1)[0]
    assert 'ARG TARGETARCH\nRUN test "$(platform_convert "@@PLATFORM@@" --amd64 --arm64)" = "${TARGETARCH}"' in text
    assert "BACKPLANE_TOOLS_VERSION" not in text
    assert "backplane-tools install" not in text
    assert "OMC_VERSION" not in text
    assert "/opt/omc" not in text
    assert "/etc/bash_completion.d/omc" not in text
    for arg in TOOLS:
        block = stage.split(f"ARG {arg}=", 1)[1].split("\nARG ", 1)[0]
        assert f'--version "${{{arg}}}"' in block
        assert "--arch" in block
    assert "releases/latest" not in stage
    copies = re.findall(r'^COPY --from=sre-tools (.+)$', text, re.MULTILINE)
    assert len(copies) == 7  # six tools and generated inventory
    for copy in copies:
        assert not any(forbidden in copy for forbidden in ["/keys", "sre_tools.py", "verify_sre_tools.py"])
    assert "/usr/local/share/rosa-boundary/tool-versions.json" in text


def test_review_and_age_policy():
    rules = CONFIG["packageRules"]
    policy = next(r for r in rules if r.get("matchPackageNames") == list(TOOLS.values()))
    assert policy["automerge"] is False
    assert policy["groupName"] is None
    assert policy["ignoreUnstable"] is True
    assert policy["minimumReleaseAgeBehaviour"] == "timestamp-required"
    # Do not replace the inherited service release-age interval with a guessed value.
    assert "minimumReleaseAge" not in CONFIG
    assert all("minimumReleaseAge" not in rule for rule in rules)
    exceptions = [r for r in rules if r.get("minimumReleaseAgeBehaviour") == "timestamp-optional"]
    assert len(exceptions) == 1
    exception = exceptions[0]
    assert exception["matchManagers"] == ["custom.regex"]
    assert exception["matchPackageNames"] == ["openshift/oc"]
    assert exception["matchDatasources"] == ["custom.openshift-stable"]
    assert exception["matchFileNames"] == ["/^Containerfile$/"]
    assert rules.index(exception) > rules.index(policy)
    for dep, constraint in [("mikefarah/yq", ">=4.0.0 <5.0.0"),
                            ("aws/aws-cli", ">=2.0.0 <3.0.0"),
                            ("openshift/oc", ">=4.0.0 <5.0.0")]:
        assert any(r.get("matchPackageNames") == [dep] and r.get("allowedVersions") == constraint for r in rules)

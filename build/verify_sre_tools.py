#!/usr/bin/env python3
"""Offline acceptance helper; mount build/ and Containerfile read-only, run as sre.

Runtime: python3 /verify/verify_sre_tools.py runtime --containerfile /pins/Containerfile
Reconcile: python3 build/verify_sre_tools.py compare amd64.json arm64.json --containerfile Containerfile
Inventory ships at /usr/local/share/rosa-boundary/tool-versions.json.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile

from sre_tools import TOOLS, SIGNERS, actual_version, pin_version, require_version, single_version

ARGS = dict(zip(TOOLS, ('OCM_VERSION', 'BACKPLANE_CLI_VERSION', 'OSDCTL_VERSION',
                       'YQ_VERSION', 'OC_VERSION', 'AWSCLI_VERSION')))
INVENTORY = Path('/usr/local/share/rosa-boundary/tool-versions.json')

# Coding agents are pinned native upstream archives, not members of the six-tool
# exact-pin contract: they carry no signer, no inventory entry and no installer
# adapter. Each declares one annotated ENV pin in the Containerfile, and the
# final image is accepted by an offline '--version' probe against that pin.
AGENTS = {'claude': 'CLAUDE_CODE_VERSION', 'opencode': 'OPENCODE_VERSION',
          'codex': 'CODEX_VERSION', 'pi': 'PI_VERSION'}
# Upstream provenance of each pin, shared with the update-contract tests.
AGENT_DEPS = {'claude': 'anthropics/claude-code', 'opencode': 'anomalyco/opencode',
              'codex': 'openai/codex', 'pi': 'earendil-works/pi'}
# Installed payload directory per agent; the PATH entry is /usr/local/bin/<agent>.
AGENT_PAYLOADS = {'claude': Path('/usr/local/lib/claude-code'),
                  'opencode': Path('/usr/local/lib/opencode'),
                  'codex': Path('/usr/local/lib/codex'),
                  'pi': Path('/usr/local/lib/pi')}
AGENT_PATHS = {agent: Path('/usr/local/bin') / agent for agent in AGENTS}
SEARCH_TOOLS = {'fd': 'FD_VERSION', 'rg': 'RIPGREP_VERSION'}


def declared_pins(source, directive, names, value):
    """One exact, annotated pin per name, or fail closed."""
    result = {}
    for key, name in names.items():
        declarations = re.findall(rf'^{directive}\s+{name}\b[^\r\n]*', source, re.MULTILINE)
        if len(declarations) != 1:
            raise ValueError('missing or duplicate pin: ' + name)
        match = re.fullmatch(rf'{directive} {name}="({value})"', declarations[0])
        if not match:
            raise ValueError('malformed pin: ' + name)
        result[key] = match[1]
    return result


def pins(path):
    result = declared_pins(path.read_text(), 'ARG', ARGS, '[^"]+')
    for tool, pin in result.items():
        pin_version(tool, pin)
    return result


def agent_pins(path):
    """Coding agent pins are always a bare, exact three-part version."""
    return declared_pins(path.read_text(), 'ENV', AGENTS, r'\d+\.\d+\.\d+')


def agent_version(agent, executable):
    """Offline '--version' probe reading stdout only.

    Agents may warn on stderr about an unwritable config home; such notices must
    never be able to supply the version that acceptance compares against the pin.
    """
    with tempfile.TemporaryDirectory() as home:
        result = subprocess.run([str(executable), '--version'], check=True, capture_output=True,
                                text=True, timeout=120, stdin=subprocess.DEVNULL,
                                env={'HOME': home, 'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C',
                                     'HTTP_PROXY': 'http://127.0.0.1:9', 'HTTPS_PROXY': 'http://127.0.0.1:9'})
    return single_version(agent, result.stdout)


def accept_agents(agents, arch):
    """Each shipped agent is this architecture, carries no elevated mode bit,
    and reports exactly its pinned version offline."""
    for agent, executable in AGENT_PATHS.items():
        elf_arch(executable, arch)
        for path in AGENT_PAYLOADS[agent].rglob('*'):
            if path.is_file() and not path.is_symlink() and path.stat().st_mode & (stat.S_ISUID | stat.S_ISGID):
                raise ValueError('setuid or setgid agent file: ' + str(path))
        actual = agent_version(agent, executable)
        if actual != agents[agent]:
            raise ValueError(f'{agent}: expected {agents[agent]}, got {actual}')


def accept_search_tools(expected, arch):
    """Pi's PATH search dependencies must be runnable, pinned native binaries."""
    for tool, version in expected.items():
        executable = Path('/usr/local/bin') / tool
        elf_arch(executable, arch)
        if executable.stat().st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise ValueError('elevated search tool: ' + tool)
        result = subprocess.run([str(executable), '--version'], check=True,
                                capture_output=True, text=True, timeout=30,
                                env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C'})
        # rg also prints optional PCRE2 library versions on later lines.
        first = result.stdout.splitlines()[0] if result.stdout else ''
        label = 'ripgrep' if tool == 'rg' else tool
        if not re.fullmatch(re.escape(f'{label} {version}') + r'(?: \(rev [0-9a-f]+\))?', first):
            raise ValueError(f'{tool}: expected {version}, got {first}')


def accept_process_tools():
    """Agent app-server lifecycle tracking needs ps, not just version probes."""
    pid = str(os.getpid())
    result = subprocess.run(['ps', '-p', pid, '-o', 'pid=,args='], check=True,
                            capture_output=True, text=True, timeout=30,
                            env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C'})
    fields = result.stdout.split()
    if not fields or fields[0] != pid:
        raise ValueError('ps could not inspect the current unprivileged process')


def validate(entries, expected, arch):
    if len(entries) != 6 or {entry['tool'] for entry in entries} != set(TOOLS):
        raise ValueError('inventory must contain exactly six unique tools')
    for entry in entries:
        tool = entry['tool']
        if entry['architecture'] != arch or entry['expected_pin'] != expected[tool]:
            raise ValueError('architecture or effective pin differs from checked-in defaults')
        require_version(tool, expected[tool], entry['actual_version'])
        if not re.fullmatch('[0-9a-f]{64}', entry['sha256']):
            raise ValueError('invalid artifact hash')
        if entry.get('signature_identity') != SIGNERS.get(tool):
            raise ValueError('invalid signature identity')


def combine(directory, destination):
    entries = [json.loads(path.read_text()) for path in sorted(directory.glob('*.json'))]
    if len(entries) != 6 or {entry['tool'] for entry in entries} != set(TOOLS):
        raise ValueError('incomplete inventory')
    destination.write_text(json.dumps(entries, indent=2) + '\n')


def elf_arch(path, arch):
    with path.open('rb') as binary:
        header = binary.read(20)
    machine = {'amd64': 62, 'arm64': 183}[arch]
    if len(header) != 20 or header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != machine:
        raise ValueError('wrong executable architecture: ' + str(path))


def runtime(entries, expected, agents, search):
    if os.getuid() == 0:
        raise ValueError('runtime validation must run unprivileged')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    if arch is None:
        raise ValueError('unsupported runtime architecture')
    validate(entries, expected, arch)
    for removed in ('ocm-addons', 'backplane-tools', 'omc'):
        if shutil.which(removed) or Path('/etc/bash_completion.d', removed).exists():
            raise ValueError('removed tool remains: ' + removed)
    if Path('/usr/local/share/licenses/sre-tools').exists():
        raise ValueError('bespoke vendored licenses remain')
    if Path('/usr/local/bin/aws').resolve() != Path('/usr/local/aws-cli/v2/current/aws'):
        raise ValueError('AWS alternative does not preserve distribution layout')
    for tool in TOOLS:
        executable = Path('/usr/local/bin') / tool
        elf_arch(executable, arch)
        require_version(tool, expected[tool], actual_version(tool, executable))
    commands = [['ocm', '--help'], ['ocm', 'backplane', '--help'],
                ['ocm', 'completion', 'bash'], ['ocm', 'backplane', 'completion', 'bash'],
                ['oc', 'completion', 'bash'],
                ['osdctl', 'completion', 'bash', '--skip-version-check']]
    with tempfile.TemporaryDirectory() as home:
        for command in commands:
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30,
                           env={'HOME': home, 'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C'})
    accept_agents(agents, arch)
    accept_search_tools(search, arch)
    accept_process_tools()


def compare(left, right, expected):
    validate(left, expected, 'amd64')
    validate(right, expected, 'arm64')
    a = {e['tool']: (e['expected_pin'], e['actual_version']) for e in left}
    b = {e['tool']: (e['expected_pin'], e['actual_version']) for e in right}
    if a != b:
        raise ValueError('cross-architecture versions differ')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    merge = sub.add_parser('combine')
    merge.add_argument('directory', type=Path)
    merge.add_argument('destination', type=Path)
    run = sub.add_parser('runtime')
    run.add_argument('--inventory', type=Path, default=INVENTORY)
    run.add_argument('--containerfile', type=Path, required=True)
    pair = sub.add_parser('compare')
    pair.add_argument('amd64', type=Path)
    pair.add_argument('arm64', type=Path)
    pair.add_argument('--containerfile', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'combine':
        combine(args.directory, args.destination)
    elif args.command == 'runtime':
        runtime(json.loads(args.inventory.read_text()), pins(args.containerfile),
                agent_pins(args.containerfile),
                declared_pins(args.containerfile.read_text(), 'ENV', SEARCH_TOOLS, r'\d+\.\d+\.\d+'))
    else:
        compare(json.loads(args.amd64.read_text()), json.loads(args.arm64.read_text()), pins(args.containerfile))


if __name__ == '__main__':
    main()

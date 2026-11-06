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
import subprocess
import tempfile

from sre_tools import TOOLS, SIGNERS, actual_version, pin_version, require_version

ARGS = dict(zip(TOOLS, ('OCM_VERSION', 'BACKPLANE_CLI_VERSION', 'OSDCTL_VERSION',
                       'YQ_VERSION', 'OC_VERSION', 'AWSCLI_VERSION')))
INVENTORY = Path('/usr/local/share/rosa-boundary/tool-versions.json')


def pins(path):
    source = path.read_text()
    result = {}
    for tool, arg in ARGS.items():
        declarations = re.findall(r'^ARG\s+' + arg + r'\b[^\r\n]*', source, re.MULTILINE)
        if len(declarations) != 1:
            raise ValueError('missing or duplicate pin: ' + arg)
        match = re.fullmatch(r'ARG ' + arg + r'="([^"]+)"', declarations[0])
        if not match:
            raise ValueError('malformed pin: ' + arg)
        pin_version(tool, match[1])
        result[tool] = match[1]
    return result


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


def runtime(entries, expected):
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
        runtime(json.loads(args.inventory.read_text()), pins(args.containerfile))
    else:
        compare(json.loads(args.amd64.read_text()), json.loads(args.arm64.read_text()), pins(args.containerfile))


if __name__ == '__main__':
    main()

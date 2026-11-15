#!/usr/bin/env python3
"""Package the pinned APPA binary and its restricted Claude hook profile."""
import argparse
import json
import os
from pathlib import Path
import re
import tempfile

BINARY = '/usr/local/bin/appa'
CONFIG = '/etc/rosa-boundary/openappa'
STATE = '/var/lib/rosa-boundary/openappa'
RUNTIME_URL = 'http://127.0.0.1:8787'


def asset_name(version, arch):
    """Select an exact stable release asset, never a platform substring."""
    if not re.fullmatch(r'v\d+\.\d+\.\d+', version):
        raise ValueError('OpenAPPA requires an exact stable version')
    triples = {'amd64': 'x86_64', 'arm64': 'aarch64'}
    if arch not in triples:
        raise ValueError('unsupported OpenAPPA architecture')
    return f'appa-{triples[arch]}-unknown-linux-gnu.tar.gz'


def download(version, arch, output):
    """Reuse authenticated SHA256 downloads and validated binary-only extraction."""
    import github_dl as github
    from sre_tools import extract_binary

    name = asset_name(version, arch)
    token = github.resolve_token()
    if os.environ.get('REQUIRE_GITHUB_TOKEN', 'false').lower() == 'true' and not token:
        raise ValueError('GitHub build credentials are required')
    if token and not github.validate_token(token):
        raise ValueError('GitHub build authentication failed')
    assets = github.list_assets(
        f'https://api.github.com/repos/archestra-ai/OpenAPPA/releases/tags/{version}', token)
    checksum = github.get_checksum(assets, 'SHA256SUMS', token=token, asset_name=name)
    if not checksum:
        raise ValueError('missing or ambiguous OpenAPPA checksum')
    archive = github.get_binary(assets, checksum, token)
    if not archive or not github.validate_binary(archive, checksum):
        raise ValueError('OpenAPPA archive failed SHA256 verification')
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / name
        path.write_bytes(archive)
        extract_binary(path, 'appa', output)


def hook_settings(binary=BINARY, config=CONFIG, state=STATE, url=RUNTIME_URL):
    """APPA v0.40.1's Claude hook protocol and deadlines, without an installer.

    Keep aligned with appa-runtime/src/init/settings.rs when changing the pin.
    The harness timeout must exceed APPA's own deadline, not kill the hook early.
    No record-launch/resume hints: this small profile exposes fresh sessions only.
    """
    def entry(args, timeout=130):
        return {'type': 'command', 'command': binary, 'args': args, 'timeout': timeout}

    post = ['hook', '--deployment-url', url]
    hooks = {'SessionStart': [{'hooks': [
        entry(post + ['--ensure-runtime', '--config', f'{config}/appa.toml',
                      '--data-dir', state], 160),
        entry(['session-context']),
    ]}]}
    for event in ('UserPromptSubmit', 'PreToolUse', 'PostToolUse',
                  'PostToolUseFailure', 'PermissionDenied', 'SubagentStart', 'SubagentStop'):
        group = {'hooks': [entry(post)]}
        if event in ('PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'PermissionDenied'):
            group['matcher'] = '*'
        if event == 'SubagentStart':
            group['hooks'].append(entry(['session-context', '--subagent']))
        hooks[event] = [group]
    for event in ('Stop', 'StopFailure'):
        hooks[event] = [{'hooks': [entry(post + ['--turn-end'], 40)]}]
    return {'hooks': hooks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    install = commands.add_parser('download')
    install.add_argument('--version', required=True)
    install.add_argument('--arch', required=True, choices=('amd64', 'arm64'))
    install.add_argument('--output', type=Path, required=True)
    settings = commands.add_parser('settings')
    settings.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'download':
        download(args.version, args.arch, args.output)
    else:
        args.output.write_text(json.dumps(hook_settings(), indent=2) + '\n')


if __name__ == '__main__':
    main()

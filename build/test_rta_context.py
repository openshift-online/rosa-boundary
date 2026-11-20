"""Opt-in real Podman ignore matching using only synthetic source/secret files.

Run through make verify-image-context TOOL_IMAGE=<local Boundary image>.
"""
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
INCLUDED = [
    'build/helper.py',
    'components/trusted-actions/go.mod',
    'components/trusted-actions/go.sum',
    'components/trusted-actions/VERSION',
    'components/trusted-actions/cmd/rta/main.go',
    'components/trusted-actions/internal/rta/command.go',
    'components/trusted-actions/internal/openapi/api.go',
]
EXCLUDED = [
    '.git/config', '.env', 'cmd/rosa-boundary/main.go', 'internal/cmd/root.go',
    'components/other/main.go',
    'components/trusted-actions/.env',
    'components/trusted-actions/.env.example',
    'components/trusted-actions/configs/config.yaml',
    'components/trusted-actions/terraform/regional/main.tf',
    'components/trusted-actions/deploy/private.yaml',
    'components/trusted-actions/cmd/server/main.go',
    'components/trusted-actions/cmd/rta/credentials.json',
    'components/trusted-actions/bin/rta',
    'components/trusted-actions/node_modules/tool/index.js',
]


@pytest.mark.parametrize('loose_directory_exception', [False, True],
                         ids=['allowlist', 'reject-loose-directory-exception'])
def test_podman_filters_nested_cli_context(tmp_path, loose_directory_exception):
    image = os.environ.get('RTA_CONTEXT_IMAGE')
    if not image:
        pytest.skip('run make verify-image-context TOOL_IMAGE=<local Boundary image>')
    image_id = subprocess.check_output(
        ['podman', 'image', 'inspect', '--format', '{{.Id}}', image], text=True).strip()
    print('Testing context against local image:', image_id)
    for name in INCLUDED + EXCLUDED:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('synthetic build-context fixture, never a real secret\n')
    shutil.copyfile(ROOT / '.containerignore', tmp_path / '.containerignore')
    if loose_directory_exception:
        # A parent-directory exception also admits its descendants. Prove the
        # check catches that regression, using only the fake files above.
        ignore = tmp_path / '.containerignore'
        ignore.write_text(ignore.read_text()
                          .replace('\ncomponents/trusted-actions/**\n', '\n')
                          .replace('\ncomponents/trusted-actions/cmd/**\n', '\n')
                          .replace('\ncomponents/trusted-actions/cmd/rta/**\n', '\n'))
    checks = [f'test -f /context/{name}' for name in INCLUDED]
    checks += [f'test ! -e /context/{name} || {{ echo "UNEXPECTED_CONTEXT_PATH:{name}"; exit 1; }}'
               for name in EXCLUDED]
    (tmp_path / 'Containerfile').write_text(
        'ARG TEST_IMAGE\nFROM ${TEST_IMAGE}\nCOPY . /context/\nRUN ' +
        ' \\\n    && '.join('(' + check + ')' for check in checks) + '\n')
    # No tag or push: leave the existing shipping-image reference untouched.
    # Capture full output; pytest includes it on failure.
    result = subprocess.run(
        ['podman', 'build', '--network=none', '--pull=never',
         '--build-arg', 'TEST_IMAGE=' + image_id,
         '--file', str(tmp_path / 'Containerfile'), str(tmp_path)],
        capture_output=True, text=True, timeout=120)
    output = result.stdout + result.stderr
    if loose_directory_exception:
        assert result.returncode != 0, output
        assert '\nUNEXPECTED_CONTEXT_PATH:components/trusted-actions/.env\n' in output, output
    else:
        assert result.returncode == 0, output

"""Every module a Lambda imports must survive packaging.

Both delivery paths for `lambda/create-investigation` drop files on the floor
by default, and each does it silently in a different way:

* the container build uses a **whitelist** `.containerignore` (`*` then
  `!file`), so a module the Containerfile `COPY`s but the whitelist omits
  fails the build with "no items matching glob";
* the ZIP path archives the whole source directory and relies on an
  **exclude** list in Terraform, so a test file nobody excluded ships to
  production.

Adding `close_requests.py` to the Containerfile without adding it to
`.containerignore` broke the Konflux image build, which is where this suite
comes from. These tests read the three files that actually decide packaging
rather than restating what they should say.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CREATE = ROOT / 'lambda' / 'create-investigation'
CONTAINERFILE = CREATE / 'Containerfile'
CONTAINERIGNORE = CREATE / '.containerignore'
REGIONAL = ROOT / 'deploy' / 'regional'

# COPY [--flag ...] src... dest — with no --from, the sources are build-context
# paths, which is what .containerignore filters.
COPY_LINE = re.compile(r'^\s*COPY\s+(?P<rest>.+)$', re.MULTILINE)


def copied_context_files(containerfile_text):
    """Source paths a COPY takes from the build context, not another stage."""
    sources = []
    for match in COPY_LINE.finditer(containerfile_text):
        tokens = match.group('rest').split()
        flags = [token for token in tokens if token.startswith('--')]
        if any(flag.startswith('--from=') for flag in flags):
            continue
        operands = [token for token in tokens if not token.startswith('--')]
        # The last operand is the destination.
        sources.extend(operands[:-1])
    return sources


def whitelisted(containerignore_text):
    return {line[1:].strip() for line in containerignore_text.splitlines()
            if line.startswith('!')}


def test_every_file_the_containerfile_copies_is_whitelisted():
    copied = copied_context_files(CONTAINERFILE.read_text(encoding='utf-8'))
    assert copied, 'no context COPY found; the Containerfile layout changed'
    allowed = whitelisted(CONTAINERIGNORE.read_text(encoding='utf-8'))
    missing = [source for source in copied if source not in allowed]
    assert not missing, (
        f'{missing} are COPYed by the Containerfile but filtered out by '
        f'.containerignore; the image build fails with "no items matching glob"')


def test_the_whitelist_does_not_carry_files_the_build_no_longer_copies():
    """A stale whitelist entry is harmless but hides what the image contains."""
    copied = set(copied_context_files(CONTAINERFILE.read_text(encoding='utf-8')))
    allowed = whitelisted(CONTAINERIGNORE.read_text(encoding='utf-8'))
    assert allowed == copied, (
        'the .containerignore whitelist and the Containerfile COPY sources have '
        'drifted apart')


def test_close_requests_reaches_both_delivery_paths():
    """The module the close service dispatches to is not optional."""
    assert (CREATE / 'close_requests.py').is_file()
    assert 'close_requests.py' in CONTAINERFILE.read_text(encoding='utf-8')
    assert '!close_requests.py' in CONTAINERIGNORE.read_text(encoding='utf-8')
    assert 'close_requests.py' not in zip_excludes('lambda-create-investigation.tf'), \
        'close_requests.py must not be excluded from the Lambda ZIP'


def zip_excludes(terraform_file):
    terraform = (REGIONAL / terraform_file).read_text(encoding='utf-8')
    excludes = re.search(r'excludes\s*=\s*\[(.*?)\]', terraform, re.DOTALL)
    assert excludes is not None, f'{terraform_file} no longer declares ZIP excludes'
    return set(re.findall(r'"([^"]+)"', excludes.group(1)))


# Each Lambda's source directory and the Terraform root that archives it.
BUNDLES = [
    ('lambda-create-investigation.tf', 'create-investigation'),
    ('lambda-reap-investigations.tf', 'reap-investigations'),
]


@pytest.mark.parametrize('terraform_file,source_dir', BUNDLES)
def test_the_zip_excludes_every_test_file_and_keeps_every_runtime_module(terraform_file,
                                                                         source_dir):
    """Derived from the directory, not a hardcoded list.

    `archive_file` takes `source_dir` wholesale, so a new module ships
    automatically and a new test file ships to production unless somebody
    remembers the exclude list. Reading the directory is what makes this test
    notice a file nobody told it about.
    """
    excluded = zip_excludes(terraform_file)
    present = sorted(path.name for path in (ROOT / 'lambda' / source_dir).glob('*.py'))
    assert present, f'no Python modules found for {source_dir}'
    for name in present:
        if name.startswith('test_') or name == 'conftest.py':
            assert name in excluded, f'{name} must not ship to production in the Lambda ZIP'
        else:
            assert name not in excluded, f'{name} is a runtime module and must ship'


@pytest.mark.parametrize('module', [
    'close_requests.py',
    'close_finalization.py',
    'investigation_sessions.py',
    'boundary_close_records.py',
    'workspace_verification.py',
])
def test_close_modules_import_only_what_the_lambda_bundles(module):
    """Third-party imports must already be declared dependencies.

    Lambda modules import each other by plain module name because they sit
    side by side in the task root. The only third-party packages available
    are the declared ones; boto3/botocore are supplied by every bundle.
    """
    path = next(parent / module for parent in (CREATE, ROOT / 'lambda' / 'reap-investigations')
                if (parent / module).exists())
    imported = set()
    for line in path.read_text(encoding='utf-8').splitlines():
        match = re.match(r'(?:from|import)\s+([A-Za-z_][\w.]*)', line.strip())
        if match:
            imported.add(match.group(1).split('.')[0])
    allowed_third_party = {'boto3', 'botocore'}
    local = {'boundary_close_records', 'investigation_sessions', 'close_finalization',
             'workspace_verification', 'close_requests', 'handler'}
    stdlib = {'json', 'logging', 're', 'uuid', 'os', 'sys', 'time', 'stat', 'hashlib',
              'datetime', 'contextlib', 'collections', 'itertools', 'typing', 'base64',
              'urllib', 'functools', 'posixpath', 'errno', 'shutil', 'tempfile', 'random',
              'math', 'string', 'io', 'pathlib', 'dataclasses', 'enum', 'traceback'}
    unexpected = imported - allowed_third_party - local - stdlib
    assert not unexpected, (
        f'{module} imports {sorted(unexpected)}, which the Lambda bundle does not install')

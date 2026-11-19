"""Same-checkout RTA build/provenance and pipeline wiring contracts."""
import json
from pathlib import Path
import re
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'Containerfile').read_text()
PIPELINES = [
    ROOT / '.tekton/rosa-boundary-pull-request.yaml',
    ROOT / '.tekton/rosa-boundary-push.yaml',
]


def test_cli_is_built_from_nested_source_and_only_binary_ships():
    image = re.search(r'^FROM (\S+) AS rta-builder$', SOURCE, re.MULTILINE)
    assert image
    assert re.fullmatch(r'registry\.access\.redhat\.com/hi/go:\d+\.\d+\.\d+@sha256:[0-9a-f]{64}',
                        image[1])
    stage = SOURCE.split(' AS rta-builder\n', 1)[1].split('\nFROM ', 1)[0]
    for expected in [
        'ENV GOTOOLCHAIN=local CGO_ENABLED=0',
        'test "$(go env GOARCH)" = "${TARGETARCH}"',
        'COPY components/trusted-actions/go.mod components/trusted-actions/go.sum ./',
        'COPY components/trusted-actions/cmd/rta/ ./cmd/rta/',
        'COPY components/trusted-actions/internal/ ./internal/',
        'COPY components/trusted-actions/VERSION ./',
        'go build -mod=readonly -trimpath', '-ldflags="-s -w ',
        'internal/rta.Version=${version}', 'internal/rta.Commit=${RTA_COMMIT}',
        '-o /out/rta ./cmd/rta',
    ]:
        assert expected in stage
    assert stage.index('RUN go mod download') < stage.index('COPY components/trusted-actions/cmd/rta/')
    for forbidden in ['git clone', 'go install', 'goreleaser', 'releases/latest', 'type=secret']:
        assert forbidden not in stage
    copies = re.findall(r'^COPY .*--from=rta-builder .+$', SOURCE, re.MULTILINE)
    assert copies == ['COPY --chmod=0755 --from=rta-builder /out/rta /usr/local/bin/rta']
    final = SOURCE.split('FROM ${BASE_IMAGE} AS final\n', 1)[1]
    assert 'org.opencontainers.image.revision="${RTA_COMMIT}"' in final
    assert '--rta-commit "${RTA_COMMIT}"' in final
    assert '--rta-version-file /verify-src/components/trusted-actions/VERSION' in final


@pytest.mark.parametrize('pipeline', PIPELINES, ids=lambda p: p.stem)
def test_resolved_clone_commit_is_forwarded(pipeline):
    text = pipeline.read_text()
    build = text.split('      - name: BUILD_ARGS\n', 1)[1].split('      - name:', 1)[0]
    assert '- $(params.build-args[*])' in build
    assert '- RTA_COMMIT=$(tasks.clone-repository.results.commit)' in build
    # Keep the same source artifact and shipping-image context; no TA-image
    # pull, separate checkout, platform expansion or server build dependency.
    assert 'value: $(tasks.prefetch-dependencies.results.SOURCE_ARTIFACT)' in text
    assert '  - name: path-context\n    value: .\n' in text
    assert '    - linux/x86_64\n' in text
    assert '    - linux/arm64\n' not in text


@pytest.mark.parametrize('pipeline', PIPELINES, ids=lambda p: p.stem)
@pytest.mark.parametrize('path,expected', [
    ('components/trusted-actions/cmd/rta/main.go', True),
    ('components/trusted-actions/internal/rta/auth.go', True),
    ('components/trusted-actions/internal/openapi/api.go', True),
    ('components/trusted-actions/go.mod', True),
    ('components/trusted-actions/go.sum', True),
    ('components/trusted-actions/VERSION', True),
    ('components/trusted-actions/terraform/regional/ecs.tf', False),
    ('components/trusted-actions/docs/deployment.md', False),
    ('components/trusted-actions/cmd/server/main.go', False),
    ('components/trusted-actions/go.mod.backup', False),
    ('docs/testing.md', False),
    ('Containerfile', True),
])
def test_boundary_trigger_includes_cli_build_inputs(pipeline, path, expected):
    # files.all is PaC's changed-path list; exists(x, ...) matches ANY path.
    # Exercise the checked-in RE2-compatible regexes, not a second allowlist.
    text = pipeline.read_text()
    patterns = [p.replace('\\\\', '\\') for p in re.findall(r"x\.matches\('([^']+)'\)", text)]
    assert patterns
    assert any(re.search(pattern, path) for pattern in patterns) == expected


def test_make_stamps_both_platforms_and_checks_image_revision():
    text = (ROOT / 'Makefile').read_text()
    for platform in ['amd64', 'arm64']:
        recipe = text.split(f'build-{platform}:\n', 1)[1].split('\n# ', 1)[0]
        assert '--build-arg RTA_COMMIT="$(RTA_COMMIT)"' in recipe
        assert '--build-arg RTA_BUILD_DATE="$(RTA_BUILD_DATE)"' in recipe
    assert 'git status --porcelain --untracked-files=normal' in text
    assert "'-dirty'" in text
    assert '/pins/RTA_VERSION --rta-commit "$$commit"' in text


def test_builder_updates_are_reviewed_without_enabling_runtime_base_updates():
    config = json.loads((ROOT / 'renovate.json').read_text())
    assert '/^Containerfile$/' in config['dockerfile']['managerFilePatterns']
    rules = [r for r in config['packageRules'] if r.get('matchFileNames') == ['Containerfile']]
    builder = next(r for r in rules if r.get('matchPackageNames') == ['registry.access.redhat.com/hi/go'])
    assert builder['automerge'] is False
    assert builder['platformAutomerge'] is False
    base = next(r for r in rules if r.get('matchPackageNames') == ['registry.access.redhat.com/ubi9/ubi'])
    assert base['enabled'] is False


def test_make_uses_checkout_commit_and_marks_modified_inputs(tmp_path):
    """Exercise Make's real metadata expressions in a disposable Git repo."""
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    (tmp_path / 'Makefile').write_text(
        (ROOT / 'Makefile').read_text() +
        '\nprint-rta-metadata:\n\t@echo "$(RTA_COMMIT) $(RTA_BUILD_DATE)"\n')
    subprocess.run(['git', '-C', str(tmp_path), 'add', 'Makefile'], check=True)
    subprocess.run(['git', '-C', str(tmp_path), '-c', 'user.name=Test',
                    '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture'], check=True)
    commit = subprocess.check_output(['git', '-C', str(tmp_path), 'rev-parse', 'HEAD'], text=True).strip()
    def metadata():
        return subprocess.check_output(['make', '--no-print-directory', 'print-rta-metadata'],
                                       cwd=tmp_path, text=True).strip().split()
    clean = metadata()
    assert clean[0] == commit
    assert re.fullmatch(r'\d{4}-\d{2}-\d{2}T\S+', clean[1])
    (tmp_path / 'untracked-build-input').write_text('modified checkout')
    assert metadata() == [commit + '-dirty', clean[1]]

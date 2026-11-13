"""Offline skill projection, ownership, and failure-isolation contracts."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "utils/rosa-boundary-skill-reconciler.py"
SPEC = importlib.util.spec_from_file_location("reconciler", HELPER)
reconciler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reconciler)


@pytest.fixture
def paths(tmp_path):
    home = tmp_path / "home"
    source = tmp_path / "content"
    home.mkdir()
    source.mkdir()
    return home, source, home / ".claude/skills"


def skill(source, collection="collection", name="example"):
    path = source / collection / "skills" / name
    path.mkdir(parents=True)
    (path / "SKILL.md").write_text("---\nname: example\n---\nInstructions")
    (path / "asset.txt").write_text("asset")
    return path


def test_add_update_remove_and_new_collections(paths):
    home, source, destination = paths
    original = skill(source)
    reconciler.reconcile(home, source)
    link = destination / "boundary--collection--example"
    assert link.is_symlink()
    assert (link / "asset.txt").read_text() == "asset"
    (original / "asset.txt").write_text("updated")
    assert (link / "asset.txt").read_text() == "updated"
    (original / "SKILL.md").unlink()
    reconciler.reconcile(home, source)
    assert link.is_symlink()  # first successful absence is not a deletion
    skill(source, "new", "another")
    reconciler.reconcile(home, source)
    assert not link.is_symlink()
    assert (destination / "boundary--new--another").is_symlink()


def test_unavailable_source_does_not_count_as_absence(paths):
    home, source, destination = paths
    original = skill(source)
    reconciler.reconcile(home, source)
    (original / "SKILL.md").unlink()
    with pytest.raises(OSError):
        reconciler.reconcile(home, source / "missing")
    reconciler.reconcile(home, source)
    assert (destination / "boundary--collection--example").is_symlink()


def test_user_files_links_settings_preserved(paths):
    home, source, destination = paths
    skill(source)
    destination.mkdir(parents=True)
    conflict = destination / "boundary--collection--example"
    conflict.write_text("user owned")
    settings = home / ".claude/settings.json"
    settings.write_text('{"theme":"dark"}')
    reconciler.reconcile(home, source)
    assert conflict.read_text() == "user owned"
    assert settings.read_text() == '{"theme":"dark"}'
    conflict.unlink()
    conflict.symlink_to(home / "user-target")
    reconciler.reconcile(home, source)
    assert os.readlink(conflict) == str(home / "user-target")


def test_modified_managed_link_is_not_removed(paths):
    home, source, destination = paths
    original = skill(source)
    reconciler.reconcile(home, source)
    link = destination / "boundary--collection--example"
    link.unlink()
    link.symlink_to(home / "user-target")
    (original / "SKILL.md").unlink()
    reconciler.reconcile(home, source)
    reconciler.reconcile(home, source)
    assert os.readlink(link) == str(home / "user-target")


def test_reappearance_resets_absence_counter(paths):
    home, source, destination = paths
    original = skill(source)
    reconciler.reconcile(home, source)
    definition = original / "SKILL.md"
    definition.unlink()
    reconciler.reconcile(home, source)
    definition.write_text("returned")
    reconciler.reconcile(home, source)
    definition.unlink()
    reconciler.reconcile(home, source)
    assert (destination / "boundary--collection--example").is_symlink()


def test_escaped_targets_definitions_and_plugin_payload_rejected(paths):
    home, source, destination = paths
    outside = skill(home, "outside")
    (source / "escape").symlink_to(home / "outside", target_is_directory=True)
    original = skill(source)
    (original / "SKILL.md").unlink()
    (original / "SKILL.md").symlink_to(outside / "SKILL.md")
    plugin = skill(source, "plugin")
    (plugin / ".claude-plugin").mkdir()
    reconciler.reconcile(home, source)
    assert list(destination.iterdir()) == []


def test_symlinked_home_subdirectories_rejected(paths):
    home, source, _ = paths
    skill(source)
    (home / ".claude").symlink_to(source, target_is_directory=True)
    with pytest.raises(ValueError):
        reconciler.reconcile(home, source)
    assert not (source / "skills").exists()


def test_corrupt_or_traversing_state_fails_without_writes(paths):
    home, source, destination = paths
    skill(source)
    reconciler.reconcile(home, source)
    state = home / ".claude/.boundary-skills/state.json"
    state.write_text(json.dumps({"../../victim": {"target": "anything", "missing": 1}}))
    with pytest.raises(ValueError):
        reconciler.reconcile(home, source)
    assert (destination / "boundary--collection--example").is_symlink()


def test_lock_serializes_overlapping_tasks(paths):
    home, source, destination = paths
    reconciler.reconcile(home, source)
    skill(source)
    with (home / ".claude/.boundary-skills/lock").open("r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        reconciler.reconcile(home, source)
        assert list(destination.iterdir()) == []
    reconciler.reconcile(home, source)
    assert len(list(destination.iterdir())) == 1


def test_read_error_aborts_before_mutation(paths, monkeypatch):
    home, source, destination = paths
    skill(source)
    reconciler.reconcile(home, source)
    state = home / ".claude/.boundary-skills/state.json"
    before = state.read_bytes()
    def fail(_):
        raise PermissionError("unreadable source")
    monkeypatch.setattr(reconciler, "discover", fail)
    with pytest.raises(PermissionError):
        reconciler.reconcile(home, source)
    assert state.read_bytes() == before
    assert (destination / "boundary--collection--example").is_symlink()


def test_invalid_interval_exits_without_tight_retry(tmp_path):
    result = subprocess.run([sys.executable, str(HELPER)], env={
        **os.environ, "HOME": str(tmp_path), "BOUNDARY_SKILL_RECONCILE_INTERVAL": "0",
    }, capture_output=True, text=True, timeout=5)
    assert result.returncode == 1
    assert "invalid reconciliation interval" in result.stderr


def test_loop_exits_promptly_on_sigterm(tmp_path):
    process = subprocess.Popen([sys.executable, str(HELPER)], env={
        **os.environ, "HOME": str(tmp_path), "BOUNDARY_SKILL_RECONCILE_INTERVAL": "60",
    }, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        readable, _, _ = select.select([process.stderr], [], [], 5)
        assert readable, "helper did not start"
        assert "reconciler started" in process.stderr.readline()
        process.terminate()
        process.communicate(timeout=5)
        assert process.returncode == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


def test_collection_deletion_and_ambiguous_names(paths):
    home, source, destination = paths
    skill(source)
    reconciler.reconcile(home, source)
    (source / "collection").rename(home / "removed")
    reconciler.reconcile(home, source)
    reconciler.reconcile(home, source)
    assert list(destination.iterdir()) == []
    skill(source, "a--b", "c")
    skill(source, "a", "b--c")
    reconciler.reconcile(home, source)
    assert list(destination.iterdir()) == []


def test_image_installs_python_and_reconciler():
    content = (ROOT / "Containerfile").read_text()
    runtime = content.split('LABEL org.opencontainers.image.title="rosa-boundary"', 1)[1]
    assert "        python3 \\\n" in runtime
    assert "        python3-pip \\\n" in runtime
    assert "COPY --chmod=644 utils/rosa-boundary-skill-reconciler.py /usr/local/libexec/" in runtime
    settings = json.loads((ROOT / "skel/sre/.claude/settings.json").read_text())
    assert settings == {"env": {"CLAUDE_CODE_USE_BEDROCK": "1", "DISABLE_AUTOUPDATER": "1"},
                        "theme": "auto"}

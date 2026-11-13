#!/usr/bin/python3
"""Project read-only Boundary skill directories into Claude's user-global skills.

Only this integration's recorded symlinks may be removed. A failed scan never
counts as an absence. Shared EFS homes serialize passes with a file lock.
"""
import fcntl
import json
import logging
import os
from pathlib import Path
import re
import signal
import threading

LOG = logging.getLogger("boundary-skills")
SOURCE = Path("/opt/rosa-content/rosa-claude-plugins")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\Z")


def local_directory(path):
    """Create a local directory without following a pre-existing symlink."""
    path.mkdir(mode=0o700, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise ValueError("refusing symlink or non-directory: %s" % path)


def discover(source):
    """Build a complete snapshot; propagate I/O errors before changing links."""
    if source.is_symlink():
        raise ValueError("content root must not be a symlink")
    root = source.resolve(strict=True)
    desired = {}
    collisions = set()
    for collection in sorted(source.iterdir()):
        if not SAFE_NAME.fullmatch(collection.name) or not collection.is_dir():
            continue
        skills = collection / "skills"
        if not skills.exists():
            continue
        if not skills.resolve(strict=True).is_relative_to(root):
            LOG.warning("ignoring escaped collection: %s", collection.name)
            continue
        for skill in sorted(skills.iterdir()):
            if not SAFE_NAME.fullmatch(skill.name) or not skill.is_dir():
                continue
            target = skill.resolve(strict=True)
            definition = skill / "SKILL.md"
            if not target.is_relative_to(root):
                LOG.warning("ignoring escaped skill: %s", skill.name)
                continue
            if not definition.exists():
                continue
            if not definition.resolve(strict=True).is_relative_to(root) or not definition.is_file():
                LOG.warning("ignoring unsafe definition: %s", skill.name)
                continue
            # Newer Claude versions can treat a personal skill as a full plugin.
            # This integration must not implicitly register hooks/MCP/agents.
            if (skill / ".claude-plugin").exists():
                LOG.warning("ignoring plugin-bearing skill: %s", skill.name)
                continue
            name = "boundary--%s--%s" % (collection.name, skill.name)
            if len(name.encode()) > 240:
                LOG.warning("ignoring oversized skill name")
                continue
            if name in desired:
                collisions.add(name)
            desired[name] = str(target)
    for name in collisions:
        LOG.warning("ambiguous managed name: %s", name)
        del desired[name]
    return desired


def owned_link(path, target):
    """Ownership requires both a recorded target and an unchanged symlink."""
    return path.is_symlink() and os.readlink(path) == target


def reconcile(home, source=SOURCE):
    """Reconcile once under an EFS-compatible lock; never overwrite user files."""
    claude = home / ".claude"
    local_directory(claude)
    destination = claude / "skills"
    local_directory(destination)
    state_dir = claude / ".boundary-skills"
    local_directory(state_dir)
    lock_fd = os.open(state_dir / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "r+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        state_file = state_dir / "state.json"
        try:
            fd = os.open(state_file, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            state = {}
        else:
            with os.fdopen(fd) as handle:
                state = json.load(handle)
        # Validate bookkeeping before using any name for filesystem operations.
        if not isinstance(state, dict):
            raise ValueError("invalid reconciler state")
        for name, record in state.items():
            if (not SAFE_NAME.fullmatch(name) or not name.startswith("boundary--")
                    or not isinstance(record, dict)
                    or not isinstance(record.get("target"), str)
                    or not isinstance(record.get("missing"), int)):
                raise ValueError("invalid reconciler record")
        desired = discover(source)
        for name in list(state):
            record = state[name]
            link = destination / name
            if not owned_link(link, record["target"]):
                del state[name]
                continue
            if desired.get(name) == record["target"]:
                record["missing"] = 0
                continue
            record["missing"] += 1
            if record["missing"] >= 2:
                link.unlink()
                del state[name]
                LOG.info("removed %s", name)
        for name, target in desired.items():
            link = destination / name
            if name in state:
                continue
            if os.path.lexists(link):
                LOG.warning("preserving unowned destination: %s", name)
                continue
            # Record ownership before creation: interruption cannot leave an
            # unrecorded link. No existing file is replaced by symlink().
            state[name] = {"target": target, "missing": 0}
        temporary = state_dir / "state.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(state, handle)
        os.replace(temporary, state_file)
        for name, target in desired.items():
            if name not in state or state[name]["target"] != target:
                continue
            try:
                (destination / name).symlink_to(target, target_is_directory=True)
                LOG.info("added %s", name)
            except FileExistsError:
                pass


def main():
    """Run bounded-frequency passes until shutdown; failures never stop sessions."""
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    try:
        interval = int(os.environ.get("BOUNDARY_SKILL_RECONCILE_INTERVAL", "60"))
        if interval < 5 or interval > 86400:
            raise ValueError("interval must be between 5 and 86400 seconds")
    except ValueError as error:
        LOG.error("invalid reconciliation interval: %s", error)
        return 1
    stopped = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda *_: stopped.set())
    home = Path(os.environ.get("HOME", "/home/sre"))
    LOG.info("reconciler started (interval=%ss)", interval)
    while not stopped.is_set():
        try:
            reconcile(home)
        except (OSError, ValueError, TypeError, RuntimeError) as error:
            LOG.warning("reconciliation deferred: %s", error)
        stopped.wait(interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

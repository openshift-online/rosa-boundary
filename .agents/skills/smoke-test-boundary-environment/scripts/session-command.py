#!/usr/bin/env python3
"""Run one readiness command through Boundary's CLI and a local controlling PTY.

Linux, Python standard library only. Authenticate/configure OCM separately.
Never create, stop or close tasks/investigations; never retry remote commands.
"""

import argparse
import errno
import fcntl
import json
import math
import os
import pty
import re
import secrets
import selectors
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import termios
import time


# Keep the helper within this skill's read-only discovery scope.
COMMANDS = (
    ("rta", "version", "-o", "json"),
    ("rta", "--timeout", "15s", "action", "list", "-o", "json"),
    ("rta", "--timeout", "15s", "action", "describe", "get", "-o", "json"),
)
# Catalog output should be small; cap all streams together to bound memory.
OUTPUT_LIMIT = 1024 * 1024
# Give graceful local shutdown two seconds, then a one-second reap after SIGKILL.
TERM_GRACE = 2
KILL_GRACE = 1
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")


class Cancelled(Exception):
    """Do not use InterruptedError: selectors may swallow it and resume waiting."""


def arguments():
    """Reject unsupported commands/inputs before opening a terminal or network."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--session", required=True, help="existing Boundary task ID")
    parser.add_argument(
        "--timeout", type=float, default=60,
        help="whole-operation seconds, excluding at most 3s local shutdown (default 60)",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- rta ...")
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if tuple(args.command) not in COMMANDS:
        parser.error("command must be exactly one of: " + "; ".join(map(shlex.join, COMMANDS)))
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 300:
        parser.error("--timeout must be finite, greater than 0 and at most 300 seconds")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.profile) or args.profile.startswith("-"):
        parser.error("invalid profile name")
    if not re.fullmatch(r"[0-9a-f]{32}", args.session):
        parser.error("--session must be the 32-character task ID returned by Boundary")
    if not sys.platform.startswith("linux"):
        parser.error("this controlling-terminal helper supports Linux only")
    return args


def remote_command(command, marker):
    """Keep the normal sre interactive login environment, but exit after one command."""
    # No terminal input is injected: authentication cannot consume the command,
    # and terminal echo cannot masquerade as a completion marker.
    body = (
        'set +e; test "$(id -un)" = sre || exit 1; '
        f"printf '\\n%s\\n' {shlex.quote(marker + '_START')}; "
        f"( {shlex.join(command)} ); result=$?; "
        f"printf '\\n%s:%d\\n' {shlex.quote(marker + '_DONE')} \"$result\"; exit 0"
    )
    login = "cd ~ && exec bash --login -i -c " + shlex.quote(body)
    return "runuser -u sre -- sh -c " + shlex.quote(login)


def controlling_terminal():
    """Claim stdin's slave PTY after Popen's setsid; this process is single-threaded."""
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def child_exited(pid):
    """Observe without reaping, keeping the PID reserved until group cleanup."""
    return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def stop_group(process):
    """Bound local CLI/plugin cleanup; never signal a remote task."""
    for sig, grace in ((signal.SIGTERM, TERM_GRACE), (signal.SIGKILL, KILL_GRACE)):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + grace
        while not child_exited(process.pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        if child_exited(process.pid):
            # Kill lingering same-group plugin children before releasing the PID.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            return process.wait(timeout=KILL_GRACE)
    return None


def run(args):
    """Supervise three bounded streams: remote PTY, CLI JSON, and CLI diagnostics."""
    result = {
        "profile": args.profile, "session_id": args.session, "command": args.command,
        "outcome": "helper_error", "command_exit_status": None, "join_exit_status": None,
        "output": "", "diagnostics": "", "task_cleanup_performed": False,
        "remote_command_outcome_unknown": True,
        "note": "Disconnect is not task cleanup. Stop this run's task separately.",
    }
    cli = shutil.which("rosa-boundary")
    if cli is None:
        result["diagnostics"] = "Boundary CLI not found; run make install-cli separately."
        return result, 125
    marker = "__BOUNDARY_" + secrets.token_hex(16)
    argv = [
        cli, "--profile", args.profile, "--timeout", f"{args.timeout:.9f}s",
        "session", "join", args.session, "-o", "json",
        "--command", remote_command(args.command, marker),
    ]
    buffers = {key: bytearray() for key in ("terminal", "stdout", "stderr")}
    process = None
    master = slave = None
    selector = selectors.DefaultSelector()

    def interrupted(signum, _frame):
        raise Cancelled(f"received signal {signum}")

    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    code = 125
    try:
        deadline = time.monotonic() + args.timeout
        master, slave = pty.openpty()
        # Avoid wrapping long JSON lines at an artificially narrow terminal width.
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 240, 0, 0))
        process = subprocess.Popen(
            argv, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, preexec_fn=controlling_terminal,
        )
        os.close(slave)
        slave = None
        for stream, key in ((master, "terminal"), (process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream if isinstance(stream, int) else stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, key)
        total = 0
        while selector.get_map() or not child_exited(process.pid):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result["outcome"], code = "timeout", 124
                break
            for event, _ in selector.select(min(remaining, 0.1)):
                try:
                    chunk = os.read(event.fd, 65536)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    if exc.errno != errno.EIO or event.data != "terminal":
                        raise
                    chunk = b""  # Linux PTY EOF.
                if not chunk:
                    selector.unregister(event.fileobj)
                    continue
                available = OUTPUT_LIMIT - total
                buffers[event.data].extend(chunk[:available])
                total += len(chunk)
                if total > OUTPUT_LIMIT:
                    raise OverflowError("combined terminal/CLI output exceeded 1 MiB")
        else:
            result["outcome"], code = "disconnected", 0
    except Cancelled as exc:
        result["outcome"], result["diagnostics"], code = "interrupted", str(exc), 130
    except OverflowError as exc:
        result["outcome"], result["diagnostics"] = "output_limit", str(exc)
    except (OSError, subprocess.SubprocessError) as exc:
        result["diagnostics"] = str(exc)
    finally:
        # A second interrupt must not prevent bounded cleanup of the local group.
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        try:
            if process is not None:
                result["join_exit_status"] = stop_group(process)
                process.stdout.close()
                process.stderr.close()
            for fd in (master, slave):
                if fd is not None:
                    os.close(fd)
            selector.close()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)

    terminal = ANSI.sub("", buffers["terminal"].decode("utf-8", "replace")).replace("\r", "")
    start = re.search(r"(?m)^" + re.escape(marker) + r"_START\n", terminal)
    done = re.search(r"(?m)^" + re.escape(marker) + r"_DONE:([0-9]{1,3})\n", terminal)
    result["output"] = terminal[start.end():done.start()] if start and done else terminal
    if start and done and done.start() >= start.end() and int(done[1]) <= 255:
        result["command_exit_status"] = int(done[1])
        result["remote_command_outcome_unknown"] = False
    result["diagnostics"] += buffers["stderr"].decode("utf-8", "replace")
    if code == 0:
        try:
            summary = json.loads(buffers["stdout"])
        except (ValueError, UnicodeError):
            summary = None
        valid = isinstance(summary, dict) and all(
            key in summary and type(summary[key]) is type(value) and summary[key] == value
            for key, value in {
                "profile": args.profile, "session_id": args.session, "status": "disconnected",
                "task_closed": False, "close_requested": False, "investigation_closed": False,
            }.items()
        )
        if result["join_exit_status"] != 0:
            result["outcome"], code = "join_failed", 125
        elif not valid or result["remote_command_outcome_unknown"]:
            result["outcome"], code = "unverified", 125
        elif result["command_exit_status"] != 0:
            result["outcome"], code = "command_failed", 1
        else:
            result["outcome"] = "completed"
    return result, code


if __name__ == "__main__":
    report, exit_code = run(arguments())
    print(json.dumps(report, ensure_ascii=True))
    sys.exit(exit_code)

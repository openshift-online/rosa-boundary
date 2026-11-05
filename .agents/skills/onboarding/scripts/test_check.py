"""Offline regression tests; no credentials, engine, downloads or live calls."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("onboarding_check", Path(__file__).with_name("check.py"))
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class PrerequisiteTests(unittest.TestCase):
    def test_summary_accepts_actual_runner_list_and_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.json"
            path.write_text(json.dumps([{"status": "PASS"}, {"status": "INCOMPLETE"}]))
            check.summary_ok(path)

    def test_summary_rejects_empty_unknown_and_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "summary.json"
            for data in ([], {}, [{"status": "FAIL"}], [{"status": "UNKNOWN"}], [None]):
                with self.subTest(data=data):
                    path.write_text(json.dumps(data))
                    with self.assertRaises(RuntimeError):
                        check.summary_ok(path)

    def test_missing_tool_blocks(self):
        with patch.object(check.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Missing"):
                check.commands(["uv"])

    def test_private_token_presence_and_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(check, "ROOT", root), patch.dict(check.os.environ, {}, clear=True):
                with self.assertRaises(RuntimeError):
                    check.token_configured()
                path = root / "tests/localstack/.env"
                path.parent.mkdir(parents=True)
                for value in ("", "your-token-here"):
                    path.write_text(f"LOCALSTACK_AUTH_TOKEN={value}\n")
                    with self.assertRaises(RuntimeError):
                        check.token_configured()
                path.write_text("LOCALSTACK_AUTH_TOKEN=synthetic-test-value\n")
                check.token_configured()

    def test_failed_command_blocks_without_output(self):
        with patch.object(check.subprocess, "run") as run:
            run.return_value.returncode = 1
            with self.assertRaisesRegex(RuntimeError, "not ready"):
                check.succeeds(["podman", "info"], "not ready")
            self.assertEqual(run.call_args.kwargs["stdout"], check.subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()

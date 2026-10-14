"""Offline tests for the private dev profile and non-secret run ledger."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("dev_state.py")
SHA = "a" * 40
DIGEST = "b" * 64


class DevStateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.config = base / "config"
        self.state = base / "state"
        self.config.mkdir()
        self.state.mkdir()
        self.env = {**os.environ, "XDG_CONFIG_HOME": str(self.config), "XDG_STATE_HOME": str(self.state)}

    def run_cli(self, *args, ok=True):
        result = subprocess.run([sys.executable, str(SCRIPT), *args], env=self.env,
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode == 0, ok, result.stderr)
        return result

    def profile(self):
        self.run_cli("profile", "add", "--name", "mine", "--account-id", "123456789012",
                     "--region", "us-east-1", "--oidc-base-url", "https://id.example.net/auth",
                     "--realm", "devrealm", "--client-id", "sre-client")

    def start(self):
        return self.run_cli("run", "start", "--profile", "mine", "--revision", SHA,
                            "--source-sha256", DIGEST, "--test", "smoke").stdout.strip()

    def test_private_profile_no_overwrite_and_redacted_display(self):
        self.profile()
        path = self.config / "rosa-boundary-live-verification/profiles/mine.json"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(path.read_text())["stage"], "dev")
        result = self.run_cli("profile", "show", "--name", "mine")
        self.assertNotIn("id.example.net", result.stdout)
        self.run_cli("profile", "add", "--name", "mine", "--account-id", "123456789012",
                     "--region", "us-east-1", "--oidc-base-url", "https://id.example.net/auth",
                     "--realm", "devrealm", "--client-id", "sre-client", ok=False)

    def test_reject_credentials_in_url_and_traversal(self):
        self.run_cli("profile", "add", "--name", "../other", "--account-id", "123456789012",
                     "--region", "us-east-1", "--oidc-base-url", "https://id.example.net",
                     "--realm", "devrealm", "--client-id", "sre-client", ok=False)
        self.run_cli("profile", "add", "--name", "mine", "--account-id", "123456789012",
                     "--region", "us-east-1", "--oidc-base-url", "https://me:password@id.example.net",
                     "--realm", "devrealm", "--client-id", "sre-client", ok=False)

    def test_run_lifecycle_and_cleanup_id_integrity(self):
        self.profile()
        run_id = self.start()
        path = self.state / f"rosa-boundary-live-verification/mine/runs/{run_id}.json"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.run_cli("run", "update", "--profile", "mine", "--run-id", run_id,
                     "--task-arn", "arn:aws:ecs:us-east-1:123456789012:task/cluster/id",
                     "--investigation-id", "smoke-123")
        self.run_cli("run", "update", "--profile", "mine", "--run-id", run_id,
                     "--task-arn", "arn:aws:ecs:us-west-2:123456789012:task/cluster/id", ok=False)
        args = ("run", "finish", "--profile", "mine", "--run-id", run_id,
                "--result", "passed", "--cleanup", "completed")
        self.run_cli(*args, "--session-evidence", "missing", "--s3-evidence", "verified", ok=False)
        self.run_cli(*args, "--session-evidence", "verified", "--s3-evidence", "verified")
        self.assertEqual(json.loads(path.read_text())["result"], "passed")
        self.run_cli(*args, "--session-evidence", "verified", "--s3-evidence", "verified", ok=False)
        self.run_cli("run", "update", "--profile", "mine", "--run-id", run_id,
                     "--investigation-id", "another", ok=False)

    def test_refuse_symlink_or_insecure_ledger(self):
        self.profile()
        run_id = self.start()
        path = self.state / f"rosa-boundary-live-verification/mine/runs/{run_id}.json"
        path.chmod(0o644)
        self.run_cli("run", "show", "--profile", "mine", "--run-id", run_id, ok=False)
        path.chmod(0o600)
        target = path.with_suffix(".bak")
        path.rename(target)
        path.symlink_to(target)
        self.run_cli("run", "show", "--profile", "mine", "--run-id", run_id, ok=False)


if __name__ == "__main__":
    unittest.main()

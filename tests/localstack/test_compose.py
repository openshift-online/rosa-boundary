"""Socket discovery regression tests; no Podman or LocalStack required.

Run: python3 -m unittest discover -s tests/localstack -p test_compose.py -v
"""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


DIRECTORY = Path(__file__).resolve().parent


class ComposeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bin = Path(self.temp.name)
        self.env = dict(os.environ)
        self.env.pop("LOCALSTACK_PODMAN_SOCKET", None)
        self.env.pop("XDG_RUNTIME_DIR", None)
        self.env.update(
            PATH=f"{self.bin}:{self.env['PATH']}",
            SOCKET_RESULT="unix:///run/user/501/podman/podman.sock",
            PODMAN_STATUS="0",
        )
        self.stub("podman", 'printf "%s\\n" "$*" > "$CALL_LOG"\nprintf "%s\\n" "$SOCKET_RESULT"\nexit "$PODMAN_STATUS"\n')
        self.env["CALL_LOG"] = str(self.bin / "podman-call")
        self.stub("podman-compose", "exec python3 -c 'import json, os, sys; print(json.dumps([os.environ[\"LOCALSTACK_PODMAN_SOCKET\"], os.getcwd(), sys.argv[1:]]))' \"$@\"\n")

    def stub(self, name, body):
        path = self.bin / name
        path.write_text("#!/usr/bin/env bash\n" + body)
        path.chmod(0o755)

    def run_wrapper(self, *args):
        return subprocess.run(
            ["bash", str(DIRECTORY / "compose.sh"), *args],
            cwd=self.temp.name,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_mac_vm_socket_without_xdg(self):
        result = self.run_wrapper("up", "-d")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), ["/run/user/501/podman/podman.sock", str(DIRECTORY), ["up", "-d"]])
        self.assertEqual((self.bin / "podman-call").read_text().strip(), "info --format {{.Host.RemoteSocket.Path}}")

    def test_rootful_and_linux_rootless_paths(self):
        for socket in ("/run/podman/podman.sock", "/run/user/1000/podman/podman.sock"):
            with self.subTest(socket=socket):
                self.env["SOCKET_RESULT"] = socket
                result = self.run_wrapper("down", "-v")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)[0], socket)

    def test_override_skips_discovery_and_preserves_arguments(self):
        self.env.update(LOCALSTACK_PODMAN_SOCKET="/custom path/podman.sock", PODMAN_STATUS="1")
        result = self.run_wrapper("-f", "compose.ci.yml", "logs", "-f", "localstack")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), ["/custom path/podman.sock", str(DIRECTORY), ["-f", "compose.ci.yml", "logs", "-f", "localstack"]])
        self.assertFalse((self.bin / "podman-call").exists())

    def test_discovery_failure_does_not_invoke_compose(self):
        self.env["PODMAN_STATUS"] = "1"
        result = self.run_wrapper("up", "-d")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot query Podman", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_invalid_discovery_paths_fail_closed(self):
        for socket in ("", "<no value>", "relative.sock", "tcp://localhost:1234", "/one\n/two"):
            with self.subTest(socket=socket):
                self.env["SOCKET_RESULT"] = socket
                result = self.run_wrapper("up", "-d")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("absolute socket path", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_compose_failure_is_propagated(self):
        self.stub("podman-compose", "exit 42\n")
        self.assertEqual(self.run_wrapper("up", "-d").returncode, 42)


if __name__ == "__main__":
    unittest.main()

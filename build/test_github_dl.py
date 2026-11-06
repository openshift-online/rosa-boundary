"""
Unit tests for github_dl GitHub App token support and token resolution.

Tests the authentication priority logic:
  1. GitHub App token (all three GITHUB_APP_* vars present)
  2. GITHUB_TOKEN / build secret mounts
  3. Partial app vars + no PAT = failure
  4. No credentials = unauthenticated (None)
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import jwt
import requests

import github_dl


class TestBuildSecretMounts(unittest.TestCase):
    """Keep local build secret IDs aligned with the Containerfile mounts."""

    def test_github_app_mount_ids_match_makefile(self):
        root = Path(__file__).resolve().parent.parent
        makefile = (root / "Makefile").read_text()
        containerfile = (root / "Containerfile").read_text()
        for name in github_dl.GITHUB_APP_VARS:
            secret_id = f"rosa-boundary-github-app/{name}"
            assert makefile.count(f"--secret id={secret_id},env={name}") == 2
            assert f"--mount=type=secret,id={secret_id}" in containerfile


class TestResolveSecret(unittest.TestCase):
    """Test resolve_secret() path pattern and env var lookup."""

    def test_reads_from_secret_path_pattern(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("  secret-from-file  \n")
            f.flush()
            with patch.object(github_dl, "SECRET_PATH_PATTERNS", [f.name.replace("MY_VAR", "{name}")]):
                with patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("MY_VAR", None)
                    # Use a pattern that resolves to the temp file
                    with patch.object(github_dl, "SECRET_PATH_PATTERNS", [f.name]):
                        result = github_dl.resolve_secret("MY_VAR")
        os.unlink(f.name)
        assert result == "secret-from-file"

    def test_uses_pattern_substitution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_file = os.path.join(tmpdir, "MY_SECRET")
            with open(secret_file, "w") as f:
                f.write("pattern-value\n")
            pattern = os.path.join(tmpdir, "{name}")
            with patch.object(github_dl, "SECRET_PATH_PATTERNS", [pattern]):
                result = github_dl.resolve_secret("MY_SECRET")
        assert result == "pattern-value"

    def test_falls_back_to_env_var(self):
        with patch.object(github_dl, "SECRET_PATH_PATTERNS", ["/nonexistent/{name}"]):
            with patch.dict(os.environ, {"MY_SECRET": "env-val"}, clear=False):
                result = github_dl.resolve_secret("MY_SECRET")
        assert result == "env-val"

    def test_returns_none_when_nothing_found(self):
        with patch.object(github_dl, "SECRET_PATH_PATTERNS", ["/nonexistent/{name}"]):
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("MISSING_VAR", None)
                result = github_dl.resolve_secret("MISSING_VAR")
        assert result is None

    def test_prefers_first_matching_pattern(self):
        with tempfile.TemporaryDirectory() as dir1, \
             tempfile.TemporaryDirectory() as dir2:
            with open(os.path.join(dir1, "MY_VAR"), "w") as f:
                f.write("first")
            with open(os.path.join(dir2, "MY_VAR"), "w") as f:
                f.write("second")
            patterns = [
                os.path.join(dir1, "{name}"),
                os.path.join(dir2, "{name}"),
            ]
            with patch.object(github_dl, "SECRET_PATH_PATTERNS", patterns):
                result = github_dl.resolve_secret("MY_VAR")
        assert result == "first"

    def test_skips_missing_pattern_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "MY_VAR"), "w") as f:
                f.write("found-it")
            patterns = [
                "/nonexistent/{name}",
                os.path.join(tmpdir, "{name}"),
            ]
            with patch.object(github_dl, "SECRET_PATH_PATTERNS", patterns):
                result = github_dl.resolve_secret("MY_VAR")
        assert result == "found-it"

    def test_literal_path_pattern_matches_any_name(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("konflux-pat-value\n")
            f.flush()
            literal_path = f.name
        patterns = ["/nonexistent/{name}", literal_path]
        with patch.object(github_dl, "SECRET_PATH_PATTERNS", patterns):
            result = github_dl.resolve_secret("GITHUB_TOKEN")
        os.unlink(literal_path)
        assert result == "konflux-pat-value"

    def test_file_preferred_over_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "MY_VAR"), "w") as f:
                f.write("from-file")
            pattern = os.path.join(tmpdir, "{name}")
            with patch.object(github_dl, "SECRET_PATH_PATTERNS", [pattern]):
                with patch.dict(os.environ, {"MY_VAR": "from-env"}, clear=False):
                    result = github_dl.resolve_secret("MY_VAR")
        assert result == "from-file"

    def test_default_patterns_include_additional_secret_mount(self):
        """Regression guard: the default SECRET_PATH_PATTERNS must resolve the
        GitHub App creds at the location the Konflux buildah task actually mounts
        them. ADDITIONAL_SECRET=rosa-boundary-github-app expands to
        'buildah build --secret id=rosa-boundary-github-app/<key>', which lands
        each key at /run/secrets/rosa-boundary-github-app/<key> (verified against
        buildah 1.43). Do not remove this pattern without updating the pipeline."""
        assert "/run/secrets/rosa-boundary-github-app/{name}" in github_dl.SECRET_PATH_PATTERNS

    def test_resolves_app_cred_at_buildah_mount_path(self):
        """Simulate the real buildah mount: keys under
        /run/secrets/rosa-boundary-github-app/ resolve via the default patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_dir = os.path.join(tmpdir, "run", "secrets", "rosa-boundary-github-app")
            os.makedirs(secret_dir)
            with open(os.path.join(secret_dir, "GITHUB_APP_ID"), "w") as f:
                f.write("app-id-123")
            # Rewrite the absolute /run/secrets prefix under the temp root so the
            # test does not require writing to the real filesystem root.
            patterns = [
                p.replace("/run/secrets", os.path.join(tmpdir, "run", "secrets"))
                if p.startswith("/run/secrets") else p
                for p in github_dl.SECRET_PATH_PATTERNS
            ]
            with patch.object(github_dl, "SECRET_PATH_PATTERNS", patterns):
                with patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("GITHUB_APP_ID", None)
                    result = github_dl.resolve_secret("GITHUB_APP_ID")
        assert result == "app-id-123"

    def test_local_dev_github_token_still_resolves(self):
        """Local development must keep working: a bare GITHUB_TOKEN mounted at
        /run/secrets/GITHUB_TOKEN (or the env var) resolves via the generic
        /run/secrets/{name} pattern even after the CI PAT paths are removed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_dir = os.path.join(tmpdir, "run", "secrets")
            os.makedirs(secret_dir)
            with open(os.path.join(secret_dir, "GITHUB_TOKEN"), "w") as f:
                f.write("ghp_local_dev")
            patterns = [
                p.replace("/run/secrets", os.path.join(tmpdir, "run", "secrets"))
                if p.startswith("/run/secrets") else p
                for p in github_dl.SECRET_PATH_PATTERNS
            ]
            with patch.object(github_dl, "SECRET_PATH_PATTERNS", patterns):
                with patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("GITHUB_TOKEN", None)
                    result = github_dl.resolve_secret("GITHUB_TOKEN")
        assert result == "ghp_local_dev"


class TestGenerateGithubAppToken(unittest.TestCase):
    """Test generate_github_app_token() JWT creation and API exchange."""

    @patch("github_dl.requests.post")
    @patch("github_dl.jwt.encode", return_value="fake.jwt.token")
    def test_successful_token_generation(self, mock_jwt, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"token": "ghs_installation_token"}
        mock_post.return_value = mock_response

        result = github_dl.generate_github_app_token("123", "fake-pem", "456")

        assert result == "ghs_installation_token"
        mock_jwt.assert_called_once()
        call_kwargs = mock_jwt.call_args
        assert call_kwargs[0][1] == "fake-pem"
        assert call_kwargs[1]["algorithm"] == "RS256"

    @patch("github_dl.requests.post")
    @patch("github_dl.jwt.encode", return_value="fake.jwt.token")
    def test_api_failure_returns_none(self, mock_jwt, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Bad credentials"
        mock_post.return_value = mock_response

        result = github_dl.generate_github_app_token("123", "fake-pem", "456")
        assert result is None

    @patch("github_dl.requests.post", side_effect=requests.RequestException("connection refused"))
    @patch("github_dl.jwt.encode", return_value="fake.jwt.token")
    def test_network_error_returns_none(self, mock_jwt, mock_post):
        result = github_dl.generate_github_app_token("123", "fake-pem", "456")
        assert result is None

    @patch("github_dl.requests.post")
    @patch("github_dl.jwt.encode", return_value="fake.jwt.token")
    def test_missing_token_in_response_returns_none(self, mock_jwt, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"expires_at": "2026-01-01T00:00:00Z"}
        mock_post.return_value = mock_response

        result = github_dl.generate_github_app_token("123", "fake-pem", "456")
        assert result is None

    @patch("github_dl.requests.post")
    @patch("github_dl.jwt.encode", return_value="fake.jwt.token")
    def test_jwt_payload_structure(self, mock_jwt, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"token": "ghs_test"}
        mock_post.return_value = mock_response

        github_dl.generate_github_app_token("999", "pem-data", "555")

        payload = mock_jwt.call_args[0][0]
        assert payload["iss"] == "999"
        assert "iat" in payload
        assert "exp" in payload
        assert payload["exp"] - payload["iat"] == 11 * 60

    @patch("github_dl.requests.post")
    @patch("github_dl.jwt.encode", return_value="fake.jwt.token")
    def test_api_url_uses_install_id(self, mock_jwt, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"token": "ghs_test"}
        mock_post.return_value = mock_response

        github_dl.generate_github_app_token("123", "pem", "789")

        call_args = mock_post.call_args
        assert "789" in call_args[1].get("url", call_args[0][0])

    @patch("github_dl.jwt.encode", side_effect=jwt.exceptions.InvalidKeyError("Could not deserialize key data"))
    def test_malformed_pem_returns_none(self, mock_jwt):
        result = github_dl.generate_github_app_token("123", "not-a-real-pem", "456")
        assert result is None

    @patch("github_dl.jwt.encode", side_effect=ValueError("Could not deserialize key data"))
    def test_malformed_pem_valueerror_returns_none(self, mock_jwt):
        result = github_dl.generate_github_app_token("123", "not-a-real-pem", "456")
        assert result is None


class TestResolveToken(unittest.TestCase):
    """Test resolve_token() priority and fallback logic."""

    @patch("github_dl.generate_github_app_token", return_value="ghs_app_token")
    @patch("github_dl.resolve_secret")
    def test_prefers_app_token_when_all_vars_present(self, mock_resolve, mock_gen):
        def side_effect(name):
            return {
                "GITHUB_APP_ID": "123",
                "GITHUB_APP_PEM": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
                "GITHUB_APP_INSTALL_ID": "456",
            }.get(name)
        mock_resolve.side_effect = side_effect

        result = github_dl.resolve_token()
        assert result == "ghs_app_token"

    @patch("github_dl.generate_github_app_token", return_value=None)
    @patch("github_dl.resolve_secret")
    def test_falls_back_to_pat_when_app_token_gen_fails(self, mock_resolve, mock_gen):
        def side_effect(name):
            return {
                "GITHUB_APP_ID": "123",
                "GITHUB_APP_PEM": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
                "GITHUB_APP_INSTALL_ID": "456",
                "GITHUB_TOKEN": "ghp_pat_token",
            }.get(name)
        mock_resolve.side_effect = side_effect

        result = github_dl.resolve_token()
        assert result == "ghp_pat_token"

    @patch("github_dl.resolve_secret")
    def test_partial_app_vars_uses_pat_fallback(self, mock_resolve):
        def side_effect(name):
            return {
                "GITHUB_APP_ID": "123",
                "GITHUB_APP_INSTALL_ID": "456",
                "GITHUB_TOKEN": "ghp_pat_token",
            }.get(name)
        mock_resolve.side_effect = side_effect

        result = github_dl.resolve_token()
        assert result == "ghp_pat_token"

    @patch("github_dl.resolve_secret")
    def test_partial_app_vars_no_pat_exits(self, mock_resolve):
        def side_effect(name):
            return {
                "GITHUB_APP_ID": "123",
                "GITHUB_APP_INSTALL_ID": "456",
            }.get(name)
        mock_resolve.side_effect = side_effect

        with self.assertRaises(SystemExit) as ctx:
            github_dl.resolve_token()
        assert ctx.exception.code == 1

    @patch("github_dl.resolve_secret", return_value=None)
    def test_no_credentials_returns_none(self, mock_resolve):
        result = github_dl.resolve_token()
        assert result is None

    @patch("github_dl.resolve_secret")
    def test_pat_only_when_no_app_vars(self, mock_resolve):
        def side_effect(name):
            return {"GITHUB_TOKEN": "ghp_only_pat"}.get(name)
        mock_resolve.side_effect = side_effect

        result = github_dl.resolve_token()
        assert result == "ghp_only_pat"

    @patch("github_dl.resolve_secret")
    def test_pem_as_file_path(self, mock_resolve):
        pem_content = "-----BEGIN RSA PRIVATE KEY-----\nfromfile\n-----END RSA PRIVATE KEY-----"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write(pem_content)
            f.flush()
            pem_path = f.name

        def side_effect(name):
            return {
                "GITHUB_APP_ID": "111",
                "GITHUB_APP_PEM": pem_path,
                "GITHUB_APP_INSTALL_ID": "222",
            }.get(name)
        mock_resolve.side_effect = side_effect

        with patch("github_dl.generate_github_app_token", return_value="ghs_test") as mock_gen:
            result = github_dl.resolve_token()

        os.unlink(pem_path)
        assert result == "ghs_test"
        # Verify the PEM file content was read and passed to generate
        mock_gen.assert_called_once_with("111", pem_content, "222")

    @patch("github_dl.resolve_secret")
    def test_pem_as_bad_path_falls_back_to_pat(self, mock_resolve):
        def side_effect(name):
            return {
                "GITHUB_APP_ID": "111",
                "GITHUB_APP_PEM": "/nonexistent/bad-path.pem",
                "GITHUB_APP_INSTALL_ID": "222",
                "GITHUB_TOKEN": "ghp_fallback",
            }.get(name)
        mock_resolve.side_effect = side_effect

        result = github_dl.resolve_token()
        assert result == "ghp_fallback"


class TestDownloadVerification(unittest.TestCase):
    digest = "a" * 64
    name = "tool_linux_amd64.tar.gz"

    def checksum(self, content, **kwargs):
        assets = [{"name": "checksums", "browser_download_url": "https://github.com/checksums"}]
        response = MagicMock(content=content)
        with patch("github_dl.get_url_with_authentication", return_value=response):
            return github_dl.get_checksum(assets, "checksums", **kwargs)

    def test_gnu_and_bsd_exact_name(self):
        for line in [f"{self.digest}  {self.name}", f"{self.digest} *{self.name}",
                     f"SHA256 ({self.name}) = {self.digest.upper()}"]:
            with self.subTest(line=line):
                self.assertEqual(self.checksum(line.encode(), asset_name=self.name),
                                 f"{self.digest}  {self.name}")

    def test_exact_name_not_substring(self):
        content = f"{self.digest}  {self.name}.sig\n{self.digest}  {self.name}\n"
        self.assertEqual(self.checksum(content.encode(), asset_name=self.name),
                         f"{self.digest}  {self.name}")
        self.assertEqual(self.checksum(content.encode(), asset_name="tool"), "")

    def test_legacy_claude_platform(self):
        content = f"{self.digest}  claude-code-linux-x64.tar.gz\n"
        self.assertEqual(self.checksum(content.encode(), platform="linux-x64"), content.strip())

    def test_legacy_platform_ambiguous(self):
        content = f"{self.digest}  tool-linux-x64\n{self.digest}  other-linux-x64"
        self.assertEqual(self.checksum(content.encode(), platform="linux-x64"), "")

    def test_duplicates_even_identical_or_mixed_format(self):
        for second in [f"{self.digest}  {self.name}", f"SHA256 ({self.name}) = {self.digest}"]:
            content = f"{self.digest}  {self.name}\n{second}"
            self.assertEqual(self.checksum(content.encode(), asset_name=self.name), "")

    def test_malformed_records_fail_closed(self):
        lines = [f"{'a' * 63}  {self.name}", f"{'z' * 64}  {self.name}",
                 f"{self.digest}  ../{self.name}", f"{self.digest}  /{self.name}",
                 f"{self.digest}  sub/{self.name}", f"{self.digest}  sub\\{self.name}",
                 f"{self.digest}  {self.name} extra", f"{self.digest} {self.name}",
                 f"SHA256 ({self.name}) = bad", f"SHA256 ({self.name}) = {self.digest} trailing",
                 f"{self.digest}  .", f"{self.digest}  ..", f"{self.digest}  -option",
                 f"\\{self.digest}  {self.name}"]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(self.checksum(line.encode(), asset_name=self.name), "")
                # A valid requested entry must not mask a malformed record.
                content = f"{self.digest}  {self.name}\n{line}"
                self.assertEqual(self.checksum(content.encode(), asset_name=self.name), "")

    def test_bsd_other_algorithms_not_used_as_sha256(self):
        # yq's rhash output pads short algorithm names and uses base32 for TTH.
        content = (f"MD5   ({self.name}) = {'b' * 32}\n"
                   f"TTH   ({self.name}) = vzro2kfsphsx75pjehbuxo5sfugxyfmuqnfipqi\n"
                   f"SHA3-256 ({self.name}) = {self.digest}\n")
        self.assertEqual(self.checksum(content.encode(), asset_name=self.name), "")
        content += f"SHA256 ({self.name}) = {self.digest}"
        self.assertEqual(self.checksum(content.encode(), asset_name=self.name),
                         f"{self.digest}  {self.name}")

    def test_missing_empty_or_non_utf8_response(self):
        assets = [{"name": "checksums", "browser_download_url": "https://github.com/checksums"}]
        with patch("github_dl.get_url_with_authentication", return_value=None):
            self.assertEqual(github_dl.get_checksum(assets, "checksums", "linux"), "")
        for content in [b"", b"\xff", b"\n"]:
            self.assertEqual(self.checksum(content, asset_name=self.name), "")

    def test_exact_release_asset_unique(self):
        asset = {"name": self.name, "browser_download_url": "https://github.com/tool"}
        self.assertEqual(github_dl.extract_browser_download_url([asset], self.name), asset["browser_download_url"])
        for assets in [[], [asset, asset], [None], [{"name": self.name}]]:
            self.assertEqual(github_dl.extract_browser_download_url(assets, self.name), "")

    def test_get_binary_rejects_paths_and_handles_no_response(self):
        with patch("github_dl.get_url_with_authentication", return_value=None) as get:
            self.assertEqual(github_dl.get_binary([], f"{self.digest}  ../tool"), b"")
            get.assert_not_called()
            assets = [{"name": self.name, "browser_download_url": "https://github.com/tool"}]
            self.assertEqual(github_dl.get_binary(assets, f"{self.digest}  {self.name}"), b"")

    def test_validate_binary_sha256(self):
        import hashlib
        digest = hashlib.sha256(b"binary").hexdigest()
        for line in [f"{digest}  tool", f"SHA256 (tool) = {digest}"]:
            self.assertTrue(github_dl.validate_binary(b"binary", line))
            self.assertFalse(github_dl.validate_binary(b"different", line))
        self.assertFalse(github_dl.validate_binary(b"binary", "malformed"))

    @patch("github_dl.requests.get")
    def test_rate_limit_threshold_and_no_auth_redirect(self, get):
        for remaining, expected in [(49, False), (50, True)]:
            get.return_value = MagicMock(status_code=200, json=lambda: {"rate": {"remaining": remaining}})
            self.assertEqual(github_dl.validate_token("secret"), expected)
            self.assertFalse(get.call_args.kwargs["allow_redirects"])

    def test_malformed_release_json(self):
        for payload in [None, [], {"assets": {}}, {"assets": None}]:
            with patch("github_dl.get_url_with_authentication", return_value=MagicMock(json=lambda: payload)):
                self.assertEqual(github_dl.list_assets("https://api.github.com/release"), [])
        with patch("github_dl.get_url_with_authentication", return_value=MagicMock(json=MagicMock(side_effect=ValueError))):
            self.assertEqual(github_dl.list_assets("https://api.github.com/release"), [])


class TestDownloadCLI(unittest.TestCase):
    def run_download(self, selection, root, *, wrong_hash=False):
        import hashlib
        digest = hashlib.sha256(b"binary").hexdigest() if not wrong_hash else "0" * 64
        assets = [
            {"name": "checksums", "browser_download_url": "https://github.com/checksums"},
            {"name": "claude-linux-x64", "browser_download_url": "https://github.com/binary"},
        ]
        def fetch(url, *args, **kwargs):
            if url.endswith("checksums"):
                return MagicMock(content=f"{digest}  claude-linux-x64\n".encode())
            return MagicMock(content=b"binary")
        previous = os.getcwd()
        try:
            os.chdir(root)
            with patch("sys.argv", ["github_dl", "download", "--url", "https://api.github.com/release",
                                    "--checksum_file", "checksums", *selection]), \
                 patch("github_dl.resolve_token", return_value=None), \
                 patch.dict(os.environ, {"REQUIRE_GITHUB_TOKEN": "false"}), \
                 patch("github_dl.list_assets", return_value=assets), \
                 patch("github_dl.get_url_with_authentication", side_effect=fetch):
                github_dl.main()
        finally:
            os.chdir(previous)

    def test_legacy_and_exact_cli_write_verified_basename(self):
        for selection in [["--platform", "linux-x64"], ["--asset_name", "claude-linux-x64"],
                          ["--exact_asset", "claude-linux-x64"]]:
            with tempfile.TemporaryDirectory() as root:
                self.run_download(selection, root)
                self.assertEqual((Path(root) / "claude-linux-x64").read_bytes(), b"binary")

    def test_bad_checksum_does_not_write(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(SystemExit):
                self.run_download(["--asset_name", "claude-linux-x64"], root, wrong_hash=True)
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_existing_file_or_symlink_not_overwritten(self):
        for symlink in [False, True]:
            with tempfile.TemporaryDirectory() as root:
                target = Path(root) / "target"
                target.write_bytes(b"keep")
                output = Path(root) / "claude-linux-x64"
                if symlink:
                    output.symlink_to(target)
                else:
                    output.write_bytes(b"keep")
                with self.assertRaises(SystemExit):
                    self.run_download(["--asset-name", "claude-linux-x64"], root)
                self.assertEqual(target.read_bytes(), b"keep")
                self.assertEqual(output.read_bytes(), b"keep")

    def test_require_token_still_fails_before_network(self):
        with patch("sys.argv", ["github_dl", "download", "--url", "https://api.github.com/release",
                                "--checksum_file", "checksums", "--asset_name", "tool"]), \
             patch("github_dl.resolve_token", return_value=None), \
             patch.dict(os.environ, {"REQUIRE_GITHUB_TOKEN": "true"}), \
             patch("github_dl.list_assets") as listing:
            with self.assertRaises(SystemExit):
                github_dl.main()
            listing.assert_not_called()


class TestBoundedDownloads(unittest.TestCase):
    @patch("github_dl.time.sleep")
    @patch("github_dl.requests.get")
    def test_server_errors_and_transport_errors_bounded(self, get, sleep):
        for failure in [MagicMock(status_code=503), requests.Timeout("secret URL")]:
            get.reset_mock()
            sleep.reset_mock()
            get.side_effect = failure if isinstance(failure, Exception) else None
            get.return_value = failure
            self.assertIsNone(github_dl.get_url_with_authentication("https://github.com/tool", max_retries=100))
            self.assertEqual(get.call_count, 6)
            self.assertEqual(sleep.call_count, 5)

    @patch("github_dl.time.sleep")
    @patch("github_dl.requests.get")
    def test_client_errors_not_retried(self, get, sleep):
        for code in [401, 403, 404, 429]:
            get.return_value = MagicMock(status_code=code)
            self.assertIsNone(github_dl.get_url_with_authentication("https://github.com/tool"))
        self.assertEqual(get.call_count, 4)
        sleep.assert_not_called()

    @patch("github_dl.requests.get")
    def test_redirect_credentials_not_sent_to_cdn_or_external_hosts(self, get):
        get.side_effect = [MagicMock(status_code=302, headers={"Location": "https://release-assets.githubusercontent.com/tool?signature=secret"}),
                           MagicMock(status_code=200)]
        self.assertIsNotNone(github_dl.get_url_with_authentication("https://github.com/tool", "secret"))
        self.assertEqual(get.call_args_list[0].kwargs["headers"]["Authorization"], "Bearer secret")
        self.assertNotIn("Authorization", get.call_args_list[1].kwargs["headers"])
        self.assertFalse(get.call_args_list[0].kwargs["allow_redirects"])
        for host in ["awscli.amazonaws.com", "mirror.openshift.com", "github.com.evil.test"]:
            get.side_effect = None
            get.return_value = MagicMock(status_code=200)
            github_dl.get_url_with_authentication(f"https://{host}/tool", "secret", {"authorization": "secret"})
            self.assertNotIn("Authorization", get.call_args.kwargs["headers"])
            self.assertNotIn("authorization", get.call_args.kwargs["headers"])

    @patch("github_dl.requests.get")
    def test_redirect_downgrade_and_loop_fail(self, get):
        get.return_value = MagicMock(status_code=302, headers={"Location": "http://github.com/tool"})
        self.assertIsNone(github_dl.get_url_with_authentication("https://github.com/tool", "secret"))
        self.assertEqual(get.call_count, 1)
        get.reset_mock()
        get.return_value = MagicMock(status_code=302, headers={"Location": "/tool"})
        self.assertIsNone(github_dl.get_url_with_authentication("https://github.com/tool", "secret"))
        self.assertEqual(get.call_count, 6)

    @patch("github_dl.requests.get")
    def test_invalid_urls_never_requested(self, get):
        for url in ["http://github.com/x", "file:///tmp/tool", "https://user:pass@github.com/x", "https://github.com:bad/x"]:
            self.assertIsNone(github_dl.get_url_with_authentication(url, "secret"))
        get.assert_not_called()


if __name__ == "__main__":
    unittest.main()

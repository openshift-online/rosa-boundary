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
from unittest.mock import patch, MagicMock

import jwt
import requests

import github_dl


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


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# github_dl — download GitHub Release assets with checksum verification.
#
# Authentication priority:
#   1. GitHub App token (GITHUB_APP_ID + GITHUB_APP_PEM + GITHUB_APP_INSTALL_ID)
#   2. Build secret mounts or GITHUB_TOKEN env var
#   3. Unauthenticated (if no credentials found)
#
# If some GITHUB_APP_* vars are set but not all, and GITHUB_TOKEN is
# available, falls back to GITHUB_TOKEN. If GITHUB_TOKEN is also missing,
# exits with an error listing the missing app vars.
#
# Usage:
#   github_dl download \
#     --url https://api.github.com/repos/ORG/REPO/releases/tags/v1.0.0 \
#     --checksum_file checksums.txt \
#     --checksum_algorithm sha256 \
#     --platform linux_amd64
#
#   github_dl quota  # Check GitHub API rate limits
#
# Ported from openshift/ocm-container (Apache 2.0).
# Fixed: added missing 'import time' for retry backoff.

import os
import sys
import time
import argparse
import hashlib

import jwt
import requests


# Build secret mount path patterns, checked in priority order.
# Each secret resolves by substituting its name into these paths,
# then falling back to the environment variable.
SECRET_PATH_PATTERNS = [
    "/additional-secret/{name}",
    "/run/secrets/read-only-github-pat/{name}",
    "/run/secrets/{name}",
]

GITHUB_APP_VARS = ["GITHUB_APP_ID", "GITHUB_APP_PEM", "GITHUB_APP_INSTALL_ID"]


def validate_binary(binary, checksum, raw_algorithm="sha256") -> bool:
    """Validate a downloaded binary against a checksum line."""
    hash_function = None
    expected_hash, _ = checksum.split()

    algorithm = raw_algorithm.removesuffix("sum").lower()

    if algorithm == "sha256":
        hash_function = hashlib.sha256
    elif algorithm == "md5":
        hash_function = hashlib.md5
    else:
        print(f"Unsupported hash algorithm: {raw_algorithm}")
        return False

    hash_object = hash_function(binary)
    calculated_hash = hash_object.hexdigest()

    if calculated_hash != expected_hash:
        print(f"Checksum validation failed: expected {expected_hash}, got {calculated_hash}")
        return False

    print("Checksum validation succeeded.")
    return True


def validate_token(token) -> bool:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        response = requests.get("https://api.github.com/rate_limit", headers=headers, timeout=30)
    except requests.RequestException as e:
        print(f"Error: Failed to validate GitHub token: {e}")
        return False

    if response.status_code == 401:
        print("Error: GitHub token is invalid or expired (HTTP 401). Please check your GITHUB_TOKEN.")
        return False

    if response.status_code in (403, 429):
        print(f"Error: GitHub API rate-limited or temporarily blocked (HTTP {response.status_code}): {response.text}")
        return False

    if response.status_code != 200:
        print(f"Error: Unexpected response validating GitHub token (HTTP {response.status_code}): {response.text}")
        return False

    try:
        remaining = response.json().get("rate", {}).get("remaining", 0)
    except (ValueError, AttributeError):
        print("Error: Malformed response from GitHub rate_limit API")
        return False
    # A full build makes ~32 GitHub API calls: 2 per github_dl invocation
    # (validate_token + list_assets) x2 stages, plus ~28 from backplane-tools
    # install all (10 GitHub-sourced tools x ~3 calls each). The threshold
    # of 50 provides headroom for retries and future tool additions.
    if remaining < 50:
        print(f"Error: GitHub API rate limit nearly exhausted ({remaining} remaining, need at least 50 for a full build)")
        return False
    print(f"GitHub token authenticated successfully (API calls remaining: {remaining})")
    return True


def get_url_with_authentication(url, token=None, additional_headers=None, retry=0, max_retries=5) -> requests.Response:
    """Fetch a URL with optional bearer token authentication and retry on server errors."""
    if retry > max_retries:
        print("max retries reached. Exiting")
        return None

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    if additional_headers:
        headers.update(additional_headers)

    response = requests.get(url, headers=headers, timeout=120)

    if response.status_code == 200:
        return response

    if response.status_code >= 500:
        print(f"Got {response.status_code}. Backing-off and retrying...")
        retry += 1
        time.sleep(3 * retry)

        return get_url_with_authentication(url, token, additional_headers, retry, max_retries)

    print(f"Failed to fetch data from {url}: {response.status_code} {response.text}")
    return None


def list_assets(url, token=None) -> list:
    """List release assets from a GitHub Releases API URL."""
    response = get_url_with_authentication(url, token)
    if response is None:
        print(f"Failed to fetch content from {url}")
        return []
    content = response.json()
    if not content:
        print(f"Failed to fetch content from {url}")
        return []

    if "assets" not in content:
        print(f"No assets found in the release at {url}")
        return []

    return content.get("assets", [])


def extract_browser_download_url(assets, asset) -> str:
    """Find the browser_download_url for a named asset."""
    for item in assets:
        if item.get("name") == asset:
            return item.get("browser_download_url")

    print(f"Asset '{asset}' not found in the release")
    print("Available assets:")
    for item in assets:
        print(f"\t{item.get('name')}")

    return ""


def get_checksum(assets, checksum_file, platform, token=None) -> str:
    """Download and parse the checksum file for a specific platform."""
    checksum = None
    checksum_download_url = extract_browser_download_url(assets, checksum_file)
    if not checksum_download_url:
        print(f"{checksum_file} not found")
        return ""

    print(f"Downloading checksum file from {checksum_download_url}")
    response = get_url_with_authentication(checksum_download_url, token)
    if not response.content:
        print(f"No content found in {checksum_file}")
        return ""

    checksum_file_content = response.content.decode('utf-8')
    checksum = list(filter(lambda line: platform in line, checksum_file_content.splitlines()))

    if not checksum:
        print(f"No checksum found for platform '{platform}' in {checksum_file}")
        return ""

    if len(checksum) > 1:
        print(f"Multiple checksums found for platform '{platform}' in {checksum_file}:")
        for item in checksum:
            print(f"\t{item}")
        return ""

    return checksum[0].strip()


def get_binary(assets, checksum, token=None) -> bytes:
    """Download the binary identified by the checksum line."""
    binary_name = checksum.split()[1]
    binary_download_url = extract_browser_download_url(assets, binary_name)
    if not binary_download_url:
        print(f"{binary_name} not found")
        return b""

    print(f"Downloading binary from {binary_download_url}")
    response = get_url_with_authentication(binary_download_url, token)
    if response is None:
        print(f"Failed to download binary from {binary_download_url}")
        return b""

    if not response.content:
        print(f"No content found for {binary_name}")
        return b""

    return response.content


def get_quota(token=None) -> list:
    """Check GitHub API rate limit status."""
    quota_errors = []

    additional_headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    response = get_url_with_authentication("https://api.github.com/rate_limit", token, additional_headers)

    if response is None:
        print("Failed to fetch GitHub API rate limit information.")
        return None

    print("GitHub API Rate Limit Information:")

    for key, value in response.json()['resources'].items():
        print(f"\n{key.capitalize()} Rate Limit:")

        if value['limit'] == 0:
            quota_errors.append((key, f"total: {value['limit']}, remaining: {value['remaining']}, reset: {value['reset']}"))

        for k, v in value.items():
            print(f"{k.capitalize()}: {v}")

    return quota_errors if quota_errors else None


def resolve_secret(name) -> str:
    """Resolve a secret from build secret mounts or environment.

    Checks SECRET_PATH_PATTERNS (with {name} substituted), then
    falls back to the environment variable. Returns None if not found.
    """
    for pattern in SECRET_PATH_PATTERNS:
        path = pattern.format(name=name)
        if os.path.isfile(path):
            print(f"Resolved {name} from {path}", file=sys.stderr)
            with open(path) as f:
                return f.read().strip()

    value = os.environ.get(name)
    if value:
        print(f"Resolved {name} from environment variable", file=sys.stderr)
        return value

    return None


def generate_github_app_token(app_id, pem_key, install_id) -> str:
    """Generate a GitHub App installation access token.

    Creates an RS256-signed JWT from the app's private key, then
    exchanges it for a short-lived installation token via the
    GitHub API — equivalent to:
      gh token generate --app-id $ID --key $PEM --installation-id $INSTALL_ID
    """
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + (10 * 60),
        "iss": str(app_id),
    }

    encoded_jwt = jwt.encode(payload, pem_key, algorithm="RS256")

    headers = {
        "Authorization": f"Bearer {encoded_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    url = f"https://api.github.com/app/installations/{install_id}/access_tokens"
    try:
        response = requests.post(url, headers=headers, timeout=30)
    except requests.RequestException as e:
        print(f"Error: Failed to generate GitHub App installation token: {e}")
        return None

    if response.status_code != 201:
        print(f"Error: GitHub App token request failed (HTTP {response.status_code}): {response.text}")
        return None

    token = response.json().get("token")
    if not token:
        print("Error: GitHub App token response did not contain a token")
        return None

    print("GitHub App installation token generated successfully.", file=sys.stderr)
    return token


def resolve_token() -> str:
    """Resolve GitHub token from app credentials, build secret mounts, or environment.

    Priority:
    1. GitHub App token (all three GITHUB_APP_* vars present)
    2. GITHUB_TOKEN via resolve_secret()
    3. None (unauthenticated)

    If some GITHUB_APP_* vars are set but not all, falls back to
    GITHUB_TOKEN. If GITHUB_TOKEN is also missing, exits with an error.
    """
    app_vars = {name: resolve_secret(name) for name in GITHUB_APP_VARS}
    present = {k for k, v in app_vars.items() if v is not None}
    missing = [k for k in GITHUB_APP_VARS if k not in present]

    if len(present) == len(GITHUB_APP_VARS):
        pem_key = app_vars["GITHUB_APP_PEM"]
        # GITHUB_APP_PEM may be a file path rather than raw PEM content
        if not pem_key.startswith("-----"):
            if os.path.isfile(pem_key):
                with open(pem_key) as f:
                    pem_key = f.read().strip()
            else:
                print(f"Error: GITHUB_APP_PEM value is not a PEM key and not a readable file path: {pem_key}", file=sys.stderr)
                pem_key = None

        if pem_key:
            token = generate_github_app_token(
                app_vars["GITHUB_APP_ID"],
                pem_key,
                app_vars["GITHUB_APP_INSTALL_ID"],
            )
            if token:
                print("Auth method: GitHub App installation token", file=sys.stderr)
                return token
        print("Warning: GitHub App token generation failed, falling back to GITHUB_TOKEN", file=sys.stderr)

    pat_token = resolve_secret("GITHUB_TOKEN")

    if 0 < len(present) < len(GITHUB_APP_VARS):
        if pat_token:
            print(f"Warning: Partial GitHub App config (missing: {', '.join(missing)}), using GITHUB_TOKEN instead", file=sys.stderr)
            print("Auth method: GITHUB_TOKEN (personal access token)", file=sys.stderr)
            return pat_token
        print(f"Error: Partial GitHub App config — missing: {', '.join(missing)}, "
              "and no GITHUB_TOKEN found as fallback.", file=sys.stderr)
        sys.exit(1)

    if pat_token:
        print("Auth method: GITHUB_TOKEN (personal access token)", file=sys.stderr)
    else:
        print("Auth method: none (unauthenticated)", file=sys.stderr)
    return pat_token


def main():
    parser = argparse.ArgumentParser(
        description="GitHub Downloader",
        epilog="Authenticates via GitHub App (GITHUB_APP_ID, GITHUB_APP_PEM, "
               "GITHUB_APP_INSTALL_ID), build secret mounts, or GITHUB_TOKEN env var.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("quota", help="Get GitHub API rate limit information")
    subparsers.add_parser("token", help="Validate token exists, is valid, and has sufficient API calls remaining")
    subparsers.add_parser("print-token", help="Print the resolved token to stdout (for use in command substitution)")

    download_parser = subparsers.add_parser("download", help="Download a GitHub asset")
    download_parser.add_argument("--url", required=True, help="GitHub Releases API URL")
    download_parser.add_argument("--checksum_file", required=True, help="Name of the checksum file in the release")
    download_parser.add_argument("--checksum_algorithm", default="sha256", help="Checksum algorithm (default: sha256)")
    download_parser.add_argument("--platform", required=True, help="Platform string to match in checksums")
    args = parser.parse_args()

    token = resolve_token()

    if args.command == "print-token":
        if token is None:
            print("Error: No GitHub credentials found.", file=sys.stderr)
            sys.exit(1)
        print(token)
        sys.exit(0)

    if token is None:
        if os.environ.get("REQUIRE_GITHUB_TOKEN", "false").lower() == "true":
            print("Error: No GitHub credentials found. Checked GITHUB_APP_ID/PEM/INSTALL_ID, "
                  "/run/secrets/GITHUB_TOKEN, /run/secrets/read-only-github-pat/token, "
                  "/additional-secret/token, and GITHUB_TOKEN env var.", file=sys.stderr)
            sys.exit(1)
        else:
            print("WARNING: No GitHub credentials found. API calls may be rate-limited.", file=sys.stderr)
    else:
        if not validate_token(token):
            sys.exit(1)

    if args.command == "token":
        if token is None:
            print("Error: No GitHub credentials found. Checked GITHUB_APP_ID/PEM/INSTALL_ID, "
                  "/run/secrets/GITHUB_TOKEN, /run/secrets/read-only-github-pat/token, "
                  "/additional-secret/token, and GITHUB_TOKEN env var.", file=sys.stderr)
            sys.exit(1)
        if not validate_token(token):
            sys.exit(1)
        sys.exit(0)

    if args.command == "quota":
        errors = get_quota(token)
        if errors is not None:
            for error in errors:
                print(f"Quota error: {error[0]} - {error[1]}")
            sys.exit(1)
        sys.exit(0)

    assets = list_assets(args.url, token)
    if not assets:
        sys.exit(1)

    checksum = get_checksum(assets, args.checksum_file, args.platform, token)
    if not checksum:
        sys.exit(1)

    binary = get_binary(assets, checksum, token)
    if not binary:
        sys.exit(1)

    if not validate_binary(binary, checksum, args.checksum_algorithm):
        sys.exit(1)

    output_filename = checksum.split()[1]
    with open(output_filename, "wb") as f:
        f.write(binary)

    print(f"Binary '{output_filename}' downloaded and validated successfully.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# github_dl — download GitHub Release assets with checksum verification.
#
# Authenticates via build secret mounts or GITHUB_TOKEN env var.
# All GitHub API calls are authenticated to avoid rate limiting.
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

import requests


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

    if response.status_code == 403:
        print(f"Error: GitHub token was rejected (HTTP 403): {response.text}")
        return False

    if response.status_code != 200:
        print(f"Error: Unexpected response validating GitHub token (HTTP {response.status_code}): {response.text}")
        return False

    remaining = response.json().get("rate", {}).get("remaining", 0)
    if remaining < 37:
        print(f"Error: GitHub API rate limit nearly exhausted ({remaining} remaining, need at least 37 for a full build)")
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


def resolve_token() -> str:
    """Resolve GitHub token from build secret mounts or environment.

    Priority: build secret mount > CI secret mount > GITHUB_TOKEN env var.
    Returns None if no token found — all GitHub API calls require authentication.
    """
    token_paths = [
        "/run/secrets/GITHUB_TOKEN",
        "/run/secrets/read-only-github-pat/token",
        "/additional-secret/token",
    ]

    for path in token_paths:
        if os.path.isfile(path):
            with open(path) as f:
                return f.read().strip()

    if os.environ.get("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"]

    return None


def main():
    parser = argparse.ArgumentParser(
        description="GitHub Downloader",
        epilog="Authenticates via build secret mounts or GITHUB_TOKEN environment variable.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("quota", help="Get GitHub API rate limit information")

    download_parser = subparsers.add_parser("download", help="Download a GitHub asset")
    download_parser.add_argument("--url", required=True, help="GitHub Releases API URL")
    download_parser.add_argument("--checksum_file", required=True, help="Name of the checksum file in the release")
    download_parser.add_argument("--checksum_algorithm", default="sha256", help="Checksum algorithm (default: sha256)")
    download_parser.add_argument("--platform", required=True, help="Platform string to match in checksums")
    args = parser.parse_args()

    token = resolve_token()
    if token is None:
        if os.environ.get("REQUIRE_GITHUB_TOKEN", "false").lower() == "true":
            print("Error: No GITHUB_TOKEN found. Checked /run/secrets/GITHUB_TOKEN, "
                  "/run/secrets/read-only-github-pat/token, /additional-secret/token, "
                  "and GITHUB_TOKEN env var.", file=sys.stderr)
            sys.exit(1)
        else:
            print("WARNING: No GITHUB_TOKEN found. API calls may be rate-limited.", file=sys.stderr)
    else:
        if not validate_token(token):
            sys.exit(1)

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

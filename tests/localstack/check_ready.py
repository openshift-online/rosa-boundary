#!/usr/bin/env python3
"""Live readiness assertion shared by Make, pytest fixtures, and test-all."""

import json
import os
import sys
import urllib.parse
import urllib.request

from required_services import REQUIRED


class NotReady(RuntimeError):
    """LocalStack is unavailable, malformed, or missing required services."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise NotReady("LocalStack health endpoint must not redirect")


def require_ready(endpoint=None):
    endpoint = endpoint or os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
    try:
        url = urllib.parse.urlsplit(endpoint)
    except ValueError as error:
        raise NotReady("LOCALSTACK_ENDPOINT must be a valid loopback HTTP URL") from error
    if url.scheme != "http" or url.hostname not in ("localhost", "127.0.0.1", "::1") or url.username or url.password or url.query or url.fragment:
        raise NotReady("LOCALSTACK_ENDPOINT must be a loopback HTTP endpoint")
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(endpoint.rstrip("/") + "/_localstack/health", timeout=5) as response:
            health = json.load(response)
        services = health.get("services") if isinstance(health, dict) else None
        if not isinstance(services, dict):
            raise NotReady("LocalStack health response has no services object")
        missing = [service for service in REQUIRED if services.get(service) not in ("available", "running")]
        if missing:
            raise NotReady("LocalStack services not ready: " + ", ".join(missing))
    except (OSError, ValueError) as error:
        raise NotReady(f"LocalStack health check failed ({type(error).__name__})") from error


def main():
    try:
        require_ready()
    except NotReady as error:
        print(f"ERROR: {error}. Start LocalStack with make localstack-up.", file=sys.stderr)
        return 1
    print("LocalStack required services are ready.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

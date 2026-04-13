#!/usr/bin/env python3
"""
OIDC token exchange reproducer for rosa-boundary PKCE clients.

This script performs the full PKCE authorization code flow and shows verbose
output at the token exchange step so the Keycloak admin can diagnose claim
mapper errors.

Usage:
    KEYCLOAK_URL=https://sso.example.com/auth \
    KEYCLOAK_REALM=MyRealm \
    OIDC_CLIENT_ID=my-client-id \
    python3 tests/oidc-token-debug.py

    # Against dev Keycloak (reads from .env):
    source .env && OIDC_CLIENT_ID=$OIDC_CLIENT_ID python3 tests/oidc-token-debug.py

Requirements: Python 3.8+ standard library only (no pip installs needed).
"""

import base64
import hashlib
import http.server
import json
import os
import secrets
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
from urllib.error import HTTPError

def _require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        print(f"Error: {name} environment variable is required", file=sys.stderr)
        print("See script docstring for usage.", file=sys.stderr)
        sys.exit(1)
    return val

KEYCLOAK_URL   = _require_env("KEYCLOAK_URL")
REALM          = _require_env("KEYCLOAK_REALM")
CLIENT_ID      = _require_env("OIDC_CLIENT_ID")
REDIRECT_URI   = "http://localhost:8400/callback"
CALLBACK_PORT  = 8400
SCOPES         = "openid profile email"

ISSUER         = f"{KEYCLOAK_URL}/realms/{REALM}"
AUTH_ENDPOINT  = f"{ISSUER}/protocol/openid-connect/auth"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"


# ── PKCE helpers ──────────────────────────────────────────────────────────────

def generate_pkce():
    verifier  = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest    = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def generate_state():
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode()


def build_auth_url(state, challenge):
    params = urllib.parse.urlencode({
        "client_id":             CLIENT_ID,
        "response_type":         "code",
        "redirect_uri":          REDIRECT_URI,
        "scope":                 SCOPES,
        "state":                 state,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
    })
    return f"{AUTH_ENDPOINT}?{params}"


# ── Local callback server ─────────────────────────────────────────────────────

class CallbackHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # suppress access log noise

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return

        qs = urllib.parse.parse_qs(parsed.query)
        error = qs.get("error", [None])[0]

        if error:
            desc = qs.get("error_description", ["(no description)"])[0]
            self.server.auth_result = {"error": f"{error}: {desc}"}
            body = b"<html><body><h2>Auth failed</h2><p>You may close this tab.</p></body></html>"
        else:
            code  = qs.get("code",  [None])[0]
            state = qs.get("state", [None])[0]
            self.server.auth_result = {"code": code, "state": state}
            body = b"<html><body><h2>Auth successful</h2><p>You may close this tab.</p></body></html>"

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)
        threading.Thread(target=self.server.shutdown, daemon=True).start()


def wait_for_callback(expected_state):
    server = http.server.HTTPServer(("127.0.0.1", CALLBACK_PORT), CallbackHandler)
    server.auth_result = None
    server.serve_forever()

    result = server.auth_result
    if result is None:
        raise RuntimeError("Callback server shut down without receiving a request")
    if "error" in result:
        raise RuntimeError(f"Auth error from IdP: {result['error']}")
    if result.get("state") != expected_state:
        raise RuntimeError("State mismatch — possible CSRF")
    return result["code"]


# ── Token exchange ────────────────────────────────────────────────────────────

def exchange_code(code, verifier):
    body = urllib.parse.urlencode({
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  REDIRECT_URI,
        "client_id":     CLIENT_ID,
        "code_verifier": verifier,
    }).encode()

    print("\n── Token exchange request ───────────────────────────────────────────")
    print(f"POST {TOKEN_ENDPOINT}")
    print(f"Content-Type: application/x-www-form-urlencoded")
    print(f"\nBody (decoded):")
    for k, v in urllib.parse.parse_qsl(body.decode()):
        display = v if k not in ("code", "code_verifier") else v[:20] + "…"
        print(f"  {k} = {display}")

    req = urllib.request.Request(
        TOKEN_ENDPOINT,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            status = resp.status
    except HTTPError as e:
        raw    = e.read()
        status = e.code

    print(f"\n── Token exchange response ──────────────────────────────────────────")
    print(f"HTTP {status}")
    try:
        parsed = json.loads(raw)
        print(json.dumps(parsed, indent=2))
    except json.JSONDecodeError:
        print(raw.decode(errors="replace"))

    if status != 200:
        print("\n[ERROR] Token exchange failed — see response above.")
        return None

    return parsed


# ── JWT decode ────────────────────────────────────────────────────────────────

def decode_jwt_payload(token, label):
    parts = token.split(".")
    if len(parts) != 3:
        print(f"[WARN] {label} does not look like a JWT")
        return {}
    payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
        print(f"\n── {label} claims ──────────────────────────────────────────────────")
        print(json.dumps(claims, indent=2))
        return claims
    except Exception as e:
        print(f"[WARN] Could not decode {label}: {e}")
        return {}


# ── Claim validation ──────────────────────────────────────────────────────────

def validate_claims(id_claims, access_claims):
    """
    Check that the tokens contain all claims required by the Lambda handler
    and AWS IAM trust policy.  Prints a pass/fail table and returns True if
    everything is present.
    """
    results = []  # list of (label, ok, detail)

    def check(label, ok, detail=""):
        results.append((label, ok, detail))

    # ── ID token checks ───────────────────────────────────────────────────────

    for claim in ("sub", "email", "preferred_username"):
        val = id_claims.get(claim)
        check(f"ID token: '{claim}' present", bool(val), val or "MISSING")

    # rhatUUID may appear as a top-level claim or only via the aws tags mapper
    rhat_uuid = id_claims.get("rhatUUID")
    aws_uuid   = (id_claims.get("https://aws.amazon.com/tags") or {}).get("principal_tags", {}).get("uuid", [])
    uuid_val   = rhat_uuid or (aws_uuid[0] if aws_uuid else None)
    check("ID token: UUID present (rhatUUID or principal_tags.uuid)",
          bool(uuid_val), uuid_val or "MISSING from both rhatUUID and principal_tags.uuid")

    # groups claim (flat array) or realm_access.roles (nested)
    groups_flat  = id_claims.get("groups", [])
    realm_roles  = id_claims.get("realm_access", {}).get("roles", [])
    has_groups   = bool(groups_flat or realm_roles)
    groups_found = f"groups={groups_flat}" if groups_flat else \
                   (f"realm_access.roles={realm_roles}" if realm_roles else "MISSING from ID token")
    check("ID token: group memberships present", has_groups, groups_found)

    # https://aws.amazon.com/tags structure
    aws_tags = id_claims.get("https://aws.amazon.com/tags")
    check("ID token: 'https://aws.amazon.com/tags' present", aws_tags is not None,
          "(needed for STS session tag propagation)" if aws_tags is None else "present")

    if aws_tags is not None:
        principal_tags = aws_tags.get("principal_tags", {})
        uuid_vals      = principal_tags.get("uuid", [])
        check("ID token: aws_tags.principal_tags.uuid is a non-empty list",
              isinstance(uuid_vals, list) and len(uuid_vals) > 0,
              str(uuid_vals) if uuid_vals else "MISSING or empty")

        transitive = aws_tags.get("transitive_tag_keys", [])
        check('ID token: aws_tags.transitive_tag_keys contains "uuid"',
              "uuid" in transitive, str(transitive) if transitive else "MISSING")

        if rhat_uuid and uuid_vals:
            check("ID token: aws_tags.principal_tags.uuid matches rhatUUID",
                  rhat_uuid in uuid_vals,
                  f"{uuid_vals} vs rhatUUID={rhat_uuid}")
        elif not rhat_uuid and uuid_vals:
            pass  # UUID only in aws tags — already checked above

    # aud must include client_id (required by Lambda token validation)
    aud = id_claims.get("aud", [])
    if isinstance(aud, str):
        aud = [aud]
    aud_lower = [a.lower() for a in aud]
    check(f"ID token: audience contains '{CLIENT_ID}'", CLIENT_ID.lower() in aud_lower, str(aud))

    # ── Access token checks ───────────────────────────────────────────────────

    if access_claims:
        at_groups_flat = access_claims.get("groups", [])
        at_realm_roles = access_claims.get("realm_access", {}).get("roles", [])
        has_at_groups  = bool(at_groups_flat or at_realm_roles)
        at_groups_str  = f"groups={at_groups_flat}" if at_groups_flat else \
                         (f"realm_access.roles={at_realm_roles}" if at_realm_roles else "MISSING from access token")
        check("Access token: group memberships present", has_at_groups, at_groups_str)
    else:
        check("Access token: received", False, "no access token in response")

    # ── Print results ─────────────────────────────────────────────────────────

    print("\n── Claim validation ─────────────────────────────────────────────────")
    passed = all(ok for _, ok, _ in results)
    for label, ok, detail in results:
        icon = "✅" if ok else "❌"
        print(f"  {icon}  {label}")
        if detail and not ok:
            print(f"       → {detail}")
        elif detail and ok and detail not in ("present",):
            print(f"       → {detail}")

    print()
    if passed:
        print("All checks passed — token looks correct for rosa-boundary.")
    else:
        fails = sum(1 for _, ok, _ in results if not ok)
        print(f"{fails} check(s) FAILED — see ❌ items above.")

    return passed


# ── Main ──────────────────────────────────────────────────────────────────────

def open_browser(url):
    if sys.platform == "darwin":
        subprocess.Popen(["open", url])
    elif sys.platform.startswith("linux"):
        subprocess.Popen(["xdg-open", url])
    else:
        print(f"Open this URL in your browser:\n{url}")


def main():
    verifier, challenge = generate_pkce()
    state               = generate_state()
    auth_url            = build_auth_url(state, challenge)

    print("━" * 68)
    print("  Rosa-boundary-sre  |  stage OIDC token debug")
    print("━" * 68)
    print(f"\nIssuer:    {ISSUER}")
    print(f"Client ID: {CLIENT_ID}")
    print(f"\nOpening browser for login…")
    print(f"\nAuth URL:\n{auth_url}\n")

    open_browser(auth_url)

    print(f"Waiting for callback on {REDIRECT_URI} …")
    try:
        code = wait_for_callback(state)
    except RuntimeError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

    print("Authorization code received.")

    token_response = exchange_code(code, verifier)
    if token_response is None:
        sys.exit(1)

    id_token     = token_response.get("id_token")
    access_token = token_response.get("access_token")

    if id_token:
        id_claims = decode_jwt_payload(id_token, "ID token")
    else:
        print("\n[WARN] No id_token in response")
        id_claims = {}

    access_claims = {}
    if access_token:
        access_claims = decode_jwt_payload(access_token, "Access token")

    ok = validate_claims(id_claims, access_claims)

    print("\n" + "━" * 68)
    print("Done. Share the output above with the Keycloak admin.")
    print("━" * 68)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

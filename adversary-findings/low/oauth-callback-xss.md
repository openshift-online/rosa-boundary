# L1: Reflected XSS in OAuth Callback Error Page

- **Severity**: Low
- **Category**: Application — Cross-Site Scripting (XSS)
- **File**: `internal/auth/callback.go:40`

## Issue

The OAuth callback handler writes error messages from query parameters directly into an HTML response without sanitization:

```go
writeHTML(w, "<html><body><h2>Authentication failed</h2><p>"+errMsg+": "+desc+"</p>...")
```

The `error` and `error_description` query parameters are rendered as-is into the HTML response body.

## Impact

An attacker could craft a malicious callback URL like `http://localhost:8400/callback?error=<script>alert(1)</script>` that executes JavaScript in the user's browser. Impact is limited because: (1) the callback server only listens on `127.0.0.1`, (2) it is short-lived (120-second timeout), and (3) it serves no authenticated content or cookies to steal. However, it could be used for phishing (e.g., displaying a fake "re-enter your password" form).

## Recommendation

HTML-escape the query parameter values before embedding them:

```go
import "html"

writeHTML(w, "<html><body><h2>Authentication failed</h2><p>"+
    html.EscapeString(errMsg)+": "+html.EscapeString(desc)+"</p>...")
```

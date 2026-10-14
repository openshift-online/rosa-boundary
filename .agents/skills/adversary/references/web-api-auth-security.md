# Web, API & Authentication Security

Combined reference for web application security, API security, authentication/authorization, and performance/scaling security checks.

---

# Web Application Security

## OWASP Top 10 Coverage

### A01: Broken Access Control

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing auth on routes | Route handlers without auth middleware | CRITICAL | Deny-by-default: global auth middleware, explicitly skip public routes |
| Client-side auth only | Authorization checks only in frontend JS | CRITICAL | Always enforce server-side. Client checks are UX only |
| IDOR vulnerabilities | Direct object references without ownership check | HIGH | Verify authenticated user owns the resource |
| Missing function-level access control | Admin endpoints without role verification | CRITICAL | RBAC middleware on every privileged endpoint |
| Directory traversal | `path.join(base, userInput)` without sanitization | HIGH | `path.resolve()` then verify path starts with allowed base |

### A02: Cryptographic Failures

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| HTTP without TLS | `http://` links/redirects in production | HIGH | Enforce HTTPS, add HSTS, redirect HTTP→HTTPS |
| Weak hashing | MD5/SHA1 for passwords | HIGH | Use Argon2id, bcrypt, or scrypt |
| Insecure random | `Math.random()` for tokens/IDs | HIGH | Use `crypto.randomUUID()` or `crypto.randomBytes()` |
| Sensitive data in URLs | Tokens/passwords in query params | MEDIUM | Move to POST bodies or HTTP headers |

### A03: Injection

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| XSS via innerHTML | `.innerHTML =`, `document.write()` | HIGH | Use `.textContent` or DOMPurify |
| XSS via dangerouslySetInnerHTML | React with user data | HIGH | Sanitize with DOMPurify or avoid raw HTML |
| Template injection | Unsanitized user input in server templates | CRITICAL | Use auto-escaping template engines |
| Header injection | User input in response headers | HIGH | Reject values containing `\r\n` |

### A07: CSRF

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing CSRF tokens | State-changing endpoints without protection | HIGH | CSRF tokens or `SameSite=Lax/Strict` cookies |
| GET with side effects | GET endpoints that modify data | HIGH | State changes via POST/PUT/DELETE only |

## Security Headers

| Header | Expected | Severity |
|--------|----------|----------|
| `Content-Security-Policy` | Restrictive (no `unsafe-inline`/`unsafe-eval`) | HIGH |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | HIGH |
| `X-Content-Type-Options` | `nosniff` | MEDIUM |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | MEDIUM |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | LOW |
| `Permissions-Policy` | Restrict unused features | LOW |

## Cookie Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing `Secure` flag | Auth cookies without `Secure` | HIGH | Only send over HTTPS |
| Missing `HttpOnly` | Session cookies without `HttpOnly` | HIGH | Prevent JS access |
| Missing `SameSite` | No `SameSite` attribute | MEDIUM | Set `Lax` or `Strict` |
| Long-lived session cookies | `Max-Age` > 24 hours | MEDIUM | Reasonable lifetime with sliding window |

## CORS Configuration

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Wildcard origin with credentials | `*` + `Allow-Credentials: true` | CRITICAL | Specific origin allowlist |
| Reflected origin | Echoing `Origin` without validation | HIGH | Validate against explicit allowlist |

## Client-Side Storage

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Tokens in localStorage | JWTs in `localStorage` | HIGH | Use `HttpOnly` cookies or BFF pattern |
| Missing `Cache-Control` for sensitive pages | No `no-store` on auth pages | MEDIUM | `Cache-Control: no-store, no-cache` |

## Frontend Framework Checks

| Framework | Check | Severity | Remediation |
|-----------|-------|----------|-------------|
| React | `dangerouslySetInnerHTML` with user data | HIGH | DOMPurify or avoid |
| React | `REACT_APP_*` / `NEXT_PUBLIC_*` with secrets | CRITICAL | Never put secrets in client-exposed env vars |
| Vue | `v-html` with user data | HIGH | Use `v-text` or DOMPurify |
| Angular | `bypassSecurityTrust*` | HIGH | Avoid bypass; use built-in sanitization |

---

# API Security

## Authentication & Authorization

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unauthenticated endpoints | API routes without auth | CRITICAL | Global auth middleware, deny-by-default |
| BOLA/IDOR | Resources by ID without ownership check | CRITICAL | Verify user owns/has access to resource |
| Broken function-level auth | Admin APIs accessible to regular users | CRITICAL | Role verification on every privileged endpoint |
| Mass assignment | Accepting all request body fields | HIGH | Explicit field allowlists |

## Input Validation

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| No request validation | No schema validation on bodies | HIGH | Use Zod, Pydantic, or framework validators |
| Missing request size limits | No `max-body-size` | HIGH | Set body size limits (e.g., 1MB) |
| Unvalidated file uploads | No type/size/name validation | HIGH | Validate MIME by magic bytes, enforce size limits, sanitize filenames |
| Executable file upload | Accepting `.php`, `.exe`, `.sh` | CRITICAL | Allowlist accepted file types |

## Rate Limiting

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| No rate limiting | API without throttling | HIGH | Tiered: 100/min general, 10/min auth, 5/min password reset |
| Missing rate limit on login | `/login`, `/auth` unthrottled | CRITICAL | 5-10 attempts/minute with exponential backoff |
| Rate limit bypass via headers | Limiting by spoofable `X-Forwarded-For` | MEDIUM | Use trusted proxy config, prefer user ID over IP |

## Response Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Verbose error messages | Stack traces/SQL in API responses | MEDIUM | Generic client errors, detailed server-side logging |
| Excessive data exposure | Full DB objects including internal fields | HIGH | Response DTOs with only needed fields |
| Missing pagination | Unbounded list results | HIGH | Always paginate, set max page size |

## GraphQL Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Introspection in production | `introspection: true` | MEDIUM | Disable in production |
| No query depth limit | Unlimited nesting | HIGH | Limit to 5-10 levels |
| No complexity analysis | No query cost limits | HIGH | Implement complexity analysis, reject over threshold |
| Missing field-level auth | Resolvers without permission checks | HIGH | Authorize at resolver level |

## WebSocket Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| No auth on connect | Connections without authentication | HIGH | Authenticate during handshake |
| No origin validation | Missing `Origin` header check | HIGH | Validate against allowed domains |
| No message validation | Messages processed without schema check | HIGH | Validate all incoming messages |
| Unbounded connections | No concurrent connection limit | HIGH | Limit per IP/user, set timeouts |

---

# Authentication & Authorization Security

## Password Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Plaintext password storage | No hashing | CRITICAL | Argon2id (preferred), bcrypt (cost ≥12), or scrypt |
| Weak hashing | MD5/SHA1/SHA256 for passwords | CRITICAL | Migrate to Argon2id on next login |
| Password in logs | Logging password values | CRITICAL | Redact in all logging middleware |
| Missing brute force protection | No lockout or rate limiting | HIGH | 5 attempts/min, lock after 10 failures for 15 min |

## Session Management

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Predictable session IDs | Low-entropy identifiers | CRITICAL | 128+ bit cryptographically random IDs |
| Missing session expiration | Sessions never expire | HIGH | Absolute timeout (8-24h), idle timeout (15-60min) |
| Session fixation | ID unchanged after login | HIGH | Regenerate session ID after authentication |
| No invalidation on logout | Session not destroyed | HIGH | Destroy server-side data, clear cookie |
| No invalidation on password change | Old sessions remain valid | HIGH | Invalidate all sessions except current |

## JWT Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| `alg: none` accepted | Not rejecting none algorithm | CRITICAL | Explicitly allow only expected algorithms: `['RS256']` |
| HS256 in distributed systems | Shared secret across services | HIGH | Use RS256/ES256 (asymmetric) |
| Missing expiration | No `exp` claim | HIGH | 15-60 min for access tokens, use refresh tokens |
| JWT in localStorage | XSS-accessible storage | HIGH | `HttpOnly` cookies or BFF pattern |
| Missing `aud`/`iss` validation | Not verifying audience/issuer | HIGH | Always verify both |

## OAuth 2.0 / OIDC

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing state parameter | No CSRF protection in OAuth | HIGH | Random `state` + PKCE |
| Missing PKCE | Auth code flow without proof key | HIGH | Implement PKCE for all clients |
| Client secret in frontend | Secret in client-side code | CRITICAL | Use PKCE public client or BFF |
| Open redirect in callback | Redirect URI not strictly validated | HIGH | Exact URI matching, no wildcards |

## API Key Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| API key in URL | Key as query parameter | MEDIUM | Send in `Authorization` or `X-API-Key` header |
| Key without scoping | Full access without restrictions | HIGH | Scoped keys with minimum permissions |
| Key stored in plaintext | Unhashed in database | HIGH | Store hash only, compare on verification |

## MFA

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| MFA bypass in API | Sensitive ops skip MFA | HIGH | Enforce on password change, payment, admin actions |
| TOTP without rate limiting | Unlimited code attempts | HIGH | 3-5 attempts per 30s window |
| No MFA for admin accounts | Privileged accounts without MFA | HIGH | Mandatory for all admin/privileged accounts |
| SMS as sole MFA | Only SMS (SIM swap risk) | MEDIUM | TOTP apps + WebAuthn/passkeys primary, SMS fallback |

## RBAC

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Hardcoded role checks | `if (role === 'admin')` scattered | MEDIUM | Centralize in policy engine/middleware |
| Permission escalation | Users can modify own role | CRITICAL | Admin-only role changes, verify higher privilege |
| Stale permissions | Removed users retaining access | HIGH | Revoke on deactivation, use short-lived tokens |

## Account Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| User enumeration | Different login/register/reset responses | MEDIUM | Identical responses regardless of account existence |
| Missing account lockout | No failed attempt protection | HIGH | Lock after 10 failures for 15-30 min |
| Insecure password reset | Predictable/long-lived/reusable tokens | HIGH | 128-bit random, 1h expiry, single use |

---

# Performance & Scaling Security

## Rate Limiting & Throttling

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| No rate limiting on public endpoints | No throttling | HIGH | Tiered limits: 100/min general, 10/min auth |
| No backoff on auth failures | No exponential backoff | HIGH | 1s, 2s, 4s, 8s after consecutive failures |

## Caching Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Cache poisoning risk | Varying by user headers not in cache key | HIGH | Include all varying headers in cache key |
| Sensitive data cached | Auth tokens/PII in shared caches | CRITICAL | `Cache-Control: no-store, private` for auth responses |
| Cache key injection | Raw user input in cache keys | HIGH | Sanitize and normalize cache keys |
| Redis without auth | No password required | CRITICAL | Set `requirepass`, use TLS, bind to private network |

## CDN & Load Balancer Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| CDN origin bypass | Origin accessible directly | HIGH | Restrict origin to CDN IPs only |
| Wildcard CORS on CDN | `*` on user-content CDN | HIGH | Specific origin allowlists |
| TLS termination without re-encryption | Plaintext to backend | MEDIUM | Re-encrypt LB→backend traffic |
| Trusting X-Forwarded-For | Without LB stripping/overwriting | HIGH | LB sets header, app trusts only LB-provided value |
| Missing request size limits at LB | No max body size | HIGH | Set at LB level: `client_max_body_size` |

## Connection Pools & Resources

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Unbounded connection pools | No max configured | HIGH | 10-50 for DB, 100-200 for HTTP |
| Missing connection timeouts | No idle/connect timeout | HIGH | Idle 30-60s, connect 5-10s, query 30s |
| Connection string in code | Hardcoded DB URL | CRITICAL | Use env vars or secret managers |

## Resource Exhaustion Prevention

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing timeouts on external calls | HTTP/gRPC without timeout | HIGH | Connect 5s, read 30s, total 60s |
| Unrestricted regex (ReDoS) | User input in regex | MEDIUM | Use RE2 or backtracking-limited libraries |
| Unbounded file reads | No size check before reading | HIGH | Check size first, stream large files |
| Unbounded query results | No LIMIT/pagination | HIGH | Always LIMIT, set max page size |

## Queue & Message Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Missing message validation | No schema validation before processing | HIGH | Validate schema, use dead-letter queue for invalid |
| Missing message size limits | No max at broker level | HIGH | Set at broker, validate on publish |
| Unencrypted broker | No TLS | HIGH | Enable TLS + SASL authentication |

## Data Processing Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| CSV/Excel injection | User data exported without sanitization | HIGH | Prefix cells starting with `=+\-@\t\r` with `'` |
| PII in exports | Sensitive data in spreadsheets | HIGH | Mask/redact, log exports, require additional auth |

## Logging Security

| Check | Pattern | Severity | Remediation |
|-------|---------|----------|-------------|
| Sensitive data in logs | Passwords, tokens, PII logged | HIGH | Structured logging with field-level redaction |
| Missing security event logging | No auth failure/denial logging | MEDIUM | Log all security events with correlation IDs |
| Log injection | User input unsanitized in logs | MEDIUM | Structured logging (JSON), escape newlines |

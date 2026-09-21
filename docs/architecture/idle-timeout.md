# Idle Timeout Implementation

## Overview

This document describes the implementation of the 15-minute idle timeout requirement for AWS credentials in rosa-boundary. The idle timeout ensures that credentials expire after 15 minutes of **inactivity**, not 15 minutes from when they were issued.

## Compliance Requirement

**Requirement**: Session timeout after 15 minutes of inactivity (idle timeout).

**NOT**: Maximum session duration of 15 minutes (fixed expiration).

This is a critical distinction:
- **Idle timeout**: Credentials expire after 15 minutes without use, but active use resets the timer
- **Fixed expiration**: Credentials expire 15 minutes after issuance regardless of activity

## AWS STS Limitation

AWS Security Token Service (STS) does not support idle timeouts. The `DurationSeconds` parameter in `AssumeRoleWithWebIdentity` creates credentials with a **fixed expiration timestamp** that cannot be extended:

```
Credentials issued at:  10:00 AM
DurationSeconds: 900 (15 minutes)
Expiration:            10:15 AM (FIXED)

User activity at 10:14 AM → still expires at 10:15 AM
No user activity         → still expires at 10:15 AM
```

There is no AWS API to:
- Extend credentials when they're used
- Implement a sliding window based on activity
- Detect "last used" and apply idle logic

## Solution: Application-Layer Activity Tracking

Since AWS doesn't track credential activity, we implement idle timeout logic at the **CLI application layer** by wrapping credential management with activity tracking.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  CLI Command (start-task, list-tasks, etc.)                │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  CredentialManager.GetCredentials()                         │
│                                                              │
│  1. Load cached credentials from disk                       │
│  2. Check if idle timeout exceeded (LastUsedAt + 15min)     │
│  3. Check if max duration exceeded (IssuedAt + 1hour)       │
│  4. If valid: update LastUsedAt, return cached credentials  │
│  5. If expired: call refresh function                       │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼ (only when refresh needed)
┌─────────────────────────────────────────────────────────────┐
│  Refresh Function                                           │
│                                                              │
│  1. GetToken() - OIDC authentication (may trigger browser)  │
│  2. AssumeRoleWithWebIdentity() - Exchange for AWS creds   │
│  3. Return fresh credentials                                │
└─────────────────────────────────────────────────────────────┘
```

### Components

#### 1. `CachedCredentials` Structure

Stores AWS credentials with activity metadata:

```go
type CachedCredentials struct {
    Credentials  *aws.TemporaryCredentials  // AWS access keys + session token
    IssuedAt     time.Time                  // When credentials were obtained
    LastUsedAt   time.Time                  // When last used by ANY command
    Expiration   time.Time                  // STS expiration timestamp (from AWS)
    IdleTimeout  time.Duration              // 15 minutes (configurable)
    MaxDuration  time.Duration              // 1 hour (defense-in-depth)
    RoleARN      string                     // AWS role ARN (cache identity validation)
    OIDCIssuer   string                     // OIDC issuer URL (cache identity validation)
}
```

**Storage location**: `~/.cache/rosa-boundary/credentials-cache`

Persisted to disk so idle timeout state survives CLI process restarts.

#### 2. `CredentialManager`

Manages credential lifecycle with idle timeout enforcement:

```go
type CredentialManager struct {
    idleTimeout time.Duration  // 15 minutes
    maxDuration time.Duration  // 1 hour
}

func (cm *CredentialManager) GetCredentials(
    ctx context.Context,
    roleARN string,
    oidcIssuer string,
    refresh func(context.Context) (*aws.TemporaryCredentials, error),
) (*aws.TemporaryCredentials, error)
```

**Called before every AWS API operation** by all CLI commands.

**Parameters:**
- `roleARN` - AWS IAM role ARN for cache identity validation
- `oidcIssuer` - OIDC provider URL for cache identity validation  
- `refresh` - Callback to obtain fresh credentials when cache miss/expired

#### 3. Decision Logic

```
GetCredentials(roleARN, oidcIssuer, refresh):
  ├─ Load cached credentials from disk
  │
  ├─ If cache exists:
  │   ├─ Validate cache identity: roleARN and oidcIssuer match?
  │   │   └─ NO → Refresh (prevent cross-role/environment credential reuse)
  │   ├─ Check STS expiration: now > expiration - 5min?
  │   │   └─ YES → Refresh + clear from disk
  │   ├─ Check idle timeout: now - LastUsedAt > 15 min?
  │   │   └─ YES → Refresh + clear from disk
  │   ├─ Check max duration: now - IssuedAt > 1 hour?
  │   │   └─ YES → Refresh + clear from disk
  │   └─ If valid:
  │       ├─ Update LastUsedAt = now (reset idle timer)
  │       ├─ Save to disk
  │       └─ Return cached credentials
  │
  └─ If cache missing/expired:
      ├─ Call refresh() → OIDC login + AssumeRole
      ├─ Create CachedCredentials (IssuedAt=now, LastUsedAt=now)
      ├─ Save to disk
      └─ Return fresh credentials
```

### Two-Tier Expiration

The system enforces **two independent timeout rules**:

| Timeout | Duration | Purpose |
|---------|----------|---------|
| **Idle timeout** | 15 minutes | Compliance: credentials expire after inactivity |
| **Max duration** | 1 hour | Defense-in-depth: even active users must re-auth eventually |

**Why both?**

Without max duration, a user running commands every 14 minutes could keep credentials alive indefinitely:

```
10:00 - Get credentials
10:14 - Run command (LastUsedAt updated) ← resets idle timer
10:28 - Run command (LastUsedAt updated) ← resets idle timer
10:42 - Run command (LastUsedAt updated) ← resets idle timer
... continues forever ...
```

With max duration: credentials expire at 11:00 AM (1 hour from IssuedAt) even if user stays active.

## User Experience

### Scenario 1: Active Use (No Re-Auth)

```bash
# 10:00 AM - First command
$ rosa-boundary start-task --cluster c1 --investigation inv-123
[Opens browser for OIDC login]
✓ Task started

# 10:05 AM - Second command (5 min later, within idle timeout)
$ rosa-boundary list-tasks --cluster c1
✓ Listed tasks (no browser prompt, uses cached credentials)

# 10:18 AM - Third command (13 min since last use, still within 15 min idle)
$ rosa-boundary join-task --cluster c1 --investigation inv-123
✓ Joined task (no browser prompt)
```

**Result**: Three commands, only one authentication.

### Scenario 2: Idle Timeout Expiration

```bash
# 10:00 AM - First command
$ rosa-boundary start-task --cluster c1 --investigation inv-123
[Opens browser]
✓ Task started (LastUsedAt = 10:00)

# 10:25 AM - Idle for 25 minutes
$ rosa-boundary list-investigations
⚠ Credentials expired due to 15 minutes of inactivity
[Opens browser for re-authentication]
✓ Listed investigations (LastUsedAt = 10:25)
```

**Result**: Re-authentication triggered because idle time (25 min) exceeded threshold (15 min).

### Scenario 3: Max Duration Expiration (Active User)

```bash
# 10:00 AM - Get credentials (IssuedAt = 10:00)

# 10:10, 10:20, 10:30, 10:40, 10:50 - Commands every 10 minutes
# LastUsedAt keeps updating, idle timeout never triggers

# 11:05 AM - Next command (1 hour 5 min from IssuedAt)
$ rosa-boundary stop-task --cluster c1 --investigation inv-123
⚠ Credentials expired due to maximum duration (1 hour)
[Opens browser for re-authentication]
✓ Task stopped
```

**Result**: Even though user was active (idle timeout didn't trigger), max duration forces re-auth after 1 hour.

### Scenario 4: Inside Container (No Impact)

```bash
# 10:00 AM
$ rosa-boundary join-task --cluster c1 --investigation inv-123
[Authenticates, starts ECS Exec session]

# Now inside container
root@task:/home/sre$ oc get nodes
root@task:/home/sre$ oc logs pod-xyz
root@task:/home/sre$ vim analysis.txt

# ... work for 2 hours inside container ...

root@task:/home/sre$ exit

# 12:15 PM - Back to local shell, run another rosa-boundary command
$ rosa-boundary list-tasks --cluster c1
⚠ Credentials expired due to 15 minutes of inactivity
[Re-authenticates]
✓ Listed tasks
```

**Result**: Time spent inside the container doesn't count as credential activity. The idle timeout is based on **CLI commands**, not container sessions.

## Integration Points

### Terraform (Infrastructure)

```terraform
# deploy/regional/variables.tf
variable "oidc_session_duration" {
  description = "Max session duration for OIDC role (seconds). Must be >= 3600 (AWS IAM minimum). The CLI enforces idle timeout separately."
  type        = number
  default     = 3600  # AWS IAM minimum (NOT the idle timeout)

  validation {
    condition     = var.oidc_session_duration >= 3600 && var.oidc_session_duration <= 43200
    error_message = "oidc_session_duration must be between 3600 (1 hour, AWS minimum) and 43200 seconds (12 hours)"
  }
}
```

**Key point**: The IAM role's `max_session_duration` is set to 3600 seconds (AWS minimum), NOT 900 seconds. The 15-minute idle timeout is enforced client-side.

### CLI (Application)

```go
// internal/cmd/root.go
var credentialManager = auth.NewCredentialManager(15*time.Minute, 1*time.Hour)

func assumeRoleWithRetry(...) (string, *awsclient.TemporaryCredentials, error) {
    refresh := func(ctx context.Context) (*aws.TemporaryCredentials, error) {
        idToken, err := auth.GetToken(ctx, pkce, forceLogin)
        // ...
        return awsclient.AssumeRoleWithWebIdentity(ctx, region, roleARN, idToken, sessionName)
    }

    oidcIssuer := fmt.Sprintf("%s/realms/%s", pkce.KeycloakURL, pkce.Realm)
    creds, err := credentialManager.GetCredentials(ctx, roleARN, oidcIssuer, refresh)
    // ...
}
```

The credential manager **wraps** the existing OIDC authentication flow without replacing it.

## Security Benefits

### Credential Lifecycle and Idle Timeout

**IMPORTANT**: The idle timeout controls cache reuse through the CLI, not AWS-side credential validity. Stolen AWS credentials remain valid at AWS until their STS expiration timestamp.

#### What Idle Timeout Protects Against

**Scenario: Credential theft from disk**

```
10:00 AM - User obtains AWS credentials (STS expiration: 11:00 AM)
10:00 AM - Credentials cached to ~/.cache/rosa-boundary/credentials-cache
10:05 AM - Attacker gains read access to cache file
10:05 AM - Attacker steals: ASIA...access key, secret, session token
```

**Without idle timeout:**
- Cache remains valid for 1 hour
- Legitimate user unknowingly continues using same credentials
- Attacker uses stolen credentials directly against AWS APIs
- Both attacker and legitimate user share same credentials until 11:00 AM
- Detection difficult (same session, same principal tags)

**With 15-minute idle timeout:**
- 10:15 AM - Idle timeout expires in CLI cache
- 10:16 AM - User runs next command, triggers credential refresh
- New credentials issued with different session token
- Old credentials (stolen at 10:05) still valid until 11:00 AM STS expiration
- But legitimate user is now on different credentials
- Attacker activity now distinguishable from legitimate user

**Security benefit**: Limits window where legitimate user and attacker share the same AWS session. Improves detection and forensics.

### Residual Risk (FedRAMP AC-12 Consideration)

**Credentials stolen from cache file remain valid at AWS for the STS session duration.**

```
10:00 AM - Credentials issued (STS expiration: 11:00 AM)
10:05 AM - Attacker steals credentials from cache
10:15 AM - CLI cache expires (idle timeout)
10:16 AM - User gets fresh credentials
11:00 AM - STOLEN credentials finally expire at AWS
```

**Residual risk window**: Up to 1 hour from credential issuance (IAM role `max_session_duration`).

**Mitigations applied:**
1. **Idle timeout (15 min)** - Limits credential sharing window
2. **Max duration (1 hour)** - Hard limit on credential lifetime
3. **Cache clearing on expiry** - Removes expired credentials from disk
4. **File permissions (0600)** - Restricts cache file access to owner only

**Residual risk statement for AC-12 compliance:**
> The idle timeout mechanism limits credential reuse through the application cache but does not revoke AWS-side validity. Stolen AWS temporary credentials remain valid until their STS expiration (max 1 hour). This is an inherent limitation of AWS STS temporary credentials, which cannot be revoked after issuance.

### Defense-in-Depth Layers

| Layer | Protection | Residual Risk |
|-------|-----------|---------------|
| File permissions (0600) | Prevents unauthorized read | Root/admin access bypasses |
| Idle timeout (15 min) | Limits cache reuse | AWS credentials still valid |
| Max duration (1 hour) | Hard session limit | Can't extend beyond 1 hour |
| Cache clearing | Removes expired creds from disk | Already-stolen creds unaffected |

The max duration (1 hour) provides defense-in-depth: even if an attacker could simulate activity to keep credentials "warm" in the cache, they expire after 1 hour regardless.

## Testing

Comprehensive test coverage in `internal/auth/credentials_test.go`:

**Core Functionality:**
- ✅ First-time credential fetch (no cache)
- ✅ Using cached credentials when valid
- ✅ Refreshing on idle timeout (15 min inactivity)
- ✅ Refreshing on max duration exceeded (1 hour absolute)
- ✅ Refreshing on STS expiration (5 min buffer)
- ✅ Updating LastUsedAt to reset idle timer
- ✅ Handling refresh errors
- ✅ Clearing credentials cache
- ✅ Handling corrupted cache files
- ✅ Default timeout values

**Security Tests:**
- ✅ Refreshing on role ARN mismatch (prevents cross-role credential reuse)
- ✅ Refreshing on OIDC issuer mismatch (prevents cross-environment reuse)
- ✅ Cache file permissions (0600 - owner read/write only)

Run tests:
```bash
cd internal/auth
go test -v -run TestCredentialManager
```

## Configuration

### Current Defaults

| Setting | Value | Rationale |
|---------|-------|-----------|
| Idle timeout | 15 minutes | Compliance requirement |
| Max duration | 1 hour | AWS STS default, defense-in-depth |
| IAM role max_session_duration | 3600 seconds | AWS IAM minimum |

### Future Enhancements

If needed, idle timeout could be made configurable:

```go
// Via environment variable
idleTimeout := getEnvDuration("ROSA_BOUNDARY_IDLE_TIMEOUT", 15*time.Minute)
credentialManager = auth.NewCredentialManager(idleTimeout, 1*time.Hour)

// Or via CLI flag
rootCmd.PersistentFlags().Duration("idle-timeout", 15*time.Minute, "Credential idle timeout")
```

Currently hardcoded to 15 minutes to match compliance requirement.

## Cache Files

The credential manager creates two cache files in `~/.cache/rosa-boundary/`:

| File | Purpose | Format |
|------|---------|--------|
| `token-cache` | OIDC ID token | Raw JWT string |
| `credentials-cache` | AWS credentials + activity | JSON (CachedCredentials struct) |

**Security**:
- Both files have `0600` permissions (owner read/write only)
- Credentials cache cleared on every `rosa-boundary login` (prevents cross-user reuse)
- OIDC token cache cleared when `--force-login` is used
- Expired credentials automatically removed from disk
- Can be manually deleted to force re-authentication

**Example `credentials-cache` contents:**

```json
{
  "credentials": {
    "AccessKeyID": "ASIAV...",
    "SecretAccessKey": "...",
    "SessionToken": "...",
    "Expiration": "2024-01-15T11:00:00Z"
  },
  "issued_at": "2024-01-15T10:00:00Z",
  "last_used_at": "2024-01-15T10:14:32Z",
  "expiration": "2024-01-15T11:00:00Z",
  "idle_timeout": 900000000000,
  "max_duration": 3600000000000,
  "role_arn": "arn:aws:iam::123456789012:role/rosa-boundary-sre",
  "oidc_issuer": "https://keycloak.example.com/realms/EmployeeIDP"
}
```

## Troubleshooting

### Frequent Re-Authentication

**Symptom**: CLI keeps prompting for login even during active use.

**Cause**: Idle timeout may be too aggressive, or clock skew between systems.

**Debug**:
```bash
# Enable verbose output to see credential expiration reasons
rosa-boundary --verbose list-tasks

# Check for clock skew
date
```

### Credentials Not Expiring

**Symptom**: Credentials seem to last longer than 15 minutes of inactivity.

**Possible causes**:
1. Commands are being run more frequently than expected
2. Other tools are using the CLI and updating LastUsedAt
3. Cache file was corrupted and defaults applied

**Debug**:
```bash
# Check cache file directly
cat ~/.cache/rosa-boundary/credentials-cache | jq .

# Clear and retry
rm ~/.cache/rosa-boundary/credentials-cache
rosa-boundary --force-login start-task ...
```

## References

- NIST 800-53 Rev 5: AC-12 (Session Termination)
- FedRAMP High Baseline: 15-minute idle timeout requirement
- AWS STS AssumeRoleWithWebIdentity: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
- AWS IAM Role max_session_duration: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html#id_roles_use_view-role-max-session

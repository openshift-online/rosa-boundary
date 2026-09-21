package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/config"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

const (
	credentialsCacheFile = "credentials-cache"
	// defaultIdleTimeout is the time after which cached credentials are considered
	// expired due to inactivity. This enforces the 15-minute idle timeout requirement.
	defaultIdleTimeout = 15 * time.Minute
	// defaultMaxDuration is the absolute maximum lifetime for credentials,
	// regardless of activity. This aligns with the AWS STS session duration.
	defaultMaxDuration = 1 * time.Hour
)

// CachedCredentials represents AWS credentials with activity tracking for idle timeout enforcement.
type CachedCredentials struct {
	Credentials *aws.TemporaryCredentials `json:"credentials"`
	IssuedAt    time.Time                 `json:"issued_at"`
	LastUsedAt  time.Time                 `json:"last_used_at"`
	Expiration  time.Time                 `json:"expiration"`
	IdleTimeout time.Duration             `json:"idle_timeout"`
	MaxDuration time.Duration             `json:"max_duration"`
	RoleARN     string                    `json:"role_arn"`
	OIDCIssuer  string                    `json:"oidc_issuer"`
}

// CredentialManager handles credential caching with idle timeout enforcement.
type CredentialManager struct {
	idleTimeout time.Duration
	maxDuration time.Duration
}

// NewCredentialManager creates a new credential manager with the specified timeouts.
// If idleTimeout is 0, defaults to 15 minutes.
// If maxDuration is 0, defaults to 1 hour.
func NewCredentialManager(idleTimeout, maxDuration time.Duration) *CredentialManager {
	if idleTimeout == 0 {
		idleTimeout = defaultIdleTimeout
	}
	if maxDuration == 0 {
		maxDuration = defaultMaxDuration
	}
	return &CredentialManager{
		idleTimeout: idleTimeout,
		maxDuration: maxDuration,
	}
}

// GetCredentials returns valid credentials, refreshing if necessary due to idle timeout or expiration.
// The refresh function is called only when credentials need to be renewed.
// roleARN and oidcIssuer are validated against cached credentials to prevent credential reuse across different roles or OIDC providers.
func (cm *CredentialManager) GetCredentials(ctx context.Context, roleARN, oidcIssuer string, refresh func(context.Context) (*aws.TemporaryCredentials, error)) (*aws.TemporaryCredentials, error) {
	now := time.Now()

	// Try to load cached credentials
	cached, err := cm.loadCachedCredentials()
	if err != nil {
		_ = output.Debug("Failed to load cached credentials: %v", err)
		output.Status("Warning: Credential cache is not accessible (%v). Performance may be degraded.", err)
		// Continue with refresh if cache load failed
		cached = nil
	}

	// Check if cached credentials are still valid
	if cached != nil {
		// Validate cache identity matches requested role and environment
		if cached.RoleARN != roleARN {
			_ = output.Debug("Cached credentials role mismatch, refreshing")
			cached = nil
		} else if cached.OIDCIssuer != oidcIssuer {
			_ = output.Debug("Cached credentials OIDC issuer mismatch, refreshing")
			cached = nil
		} else {
			// Check STS expiration first with 5-minute buffer to prevent mid-operation failures
			expirationBuffer := 5 * time.Minute
			if now.After(cached.Expiration.Add(-expirationBuffer)) {
				timeUntilExpiry := time.Until(cached.Expiration)
				_ = output.Debug("Credentials near or past STS expiration (%v remaining), refreshing", timeUntilExpiry.Round(time.Second))
				// Clear expired credentials from disk for security
				_ = cm.ClearCredentials()
				cached = nil
			} else {
				idleTime := now.Sub(cached.LastUsedAt)
				totalAge := now.Sub(cached.IssuedAt)

				if idleTime > cm.idleTimeout {
					_ = output.Debug("Credentials expired due to %v idle timeout (idle for %v)", cm.idleTimeout, idleTime.Round(time.Second))
					// Clear expired credentials from disk for security
					_ = cm.ClearCredentials()
					cached = nil
				} else if totalAge > cm.maxDuration {
					_ = output.Debug("Credentials expired due to maximum duration of %v (age: %v)", cm.maxDuration, totalAge.Round(time.Second))
					// Clear expired credentials from disk for security
					_ = cm.ClearCredentials()
					cached = nil
				} else {
					// Credentials still valid - update last used time
					remaining := cm.idleTimeout - idleTime
					_ = output.Debug("Using cached credentials (%v until idle timeout)", remaining.Round(time.Second))
					cached.LastUsedAt = now
					if err := cm.saveCachedCredentials(cached); err != nil {
						_ = output.Debug("Failed to update credential last-used timestamp: %v", err)
						output.Status("Warning: Could not update credential cache (%v). Subsequent commands may require re-authentication.", err)
						// Non-fatal - we can still use the credentials
					}
					return cached.Credentials, nil
				}
			}
		}
	}

	// Need to refresh credentials
	_ = output.Debug("Refreshing credentials...")

	creds, err := refresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh credentials: %w", err)
	}

	// Cache the new credentials with fresh timestamp after successful refresh
	refreshedAt := time.Now()
	cached = &CachedCredentials{
		Credentials: creds,
		IssuedAt:    refreshedAt,
		LastUsedAt:  refreshedAt,
		Expiration:  creds.Expiration,
		IdleTimeout: cm.idleTimeout,
		MaxDuration: cm.maxDuration,
		RoleARN:     roleARN,
		OIDCIssuer:  oidcIssuer,
	}

	if err := cm.saveCachedCredentials(cached); err != nil {
		_ = output.Debug("Failed to cache credentials: %v", err)
		output.Status("Warning: Could not cache credentials (%v). Subsequent commands will require re-authentication.", err)
		// Non-fatal - we can still use the credentials
	}

	return creds, nil
}

// ClearCredentials removes the cached credentials.
func (cm *CredentialManager) ClearCredentials() error {
	cacheDir, err := config.CacheDir()
	if err != nil {
		return err
	}
	cachePath := filepath.Join(cacheDir, credentialsCacheFile)
	if err := os.Remove(cachePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove credentials cache: %w", err)
	}
	return nil
}

// loadCachedCredentials reads credentials from the cache file.
func (cm *CredentialManager) loadCachedCredentials() (*CachedCredentials, error) {
	cacheDir, err := config.CacheDir()
	if err != nil {
		return nil, err
	}
	cachePath := filepath.Join(cacheDir, credentialsCacheFile)

	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read credentials cache: %w", err)
	}

	var cached CachedCredentials
	if err := json.Unmarshal(data, &cached); err != nil {
		// Corrupted cache - clean up and warn user
		_ = output.Debug("Corrupted credentials cache detected: %v", err)
		output.Status("Warning: Credential cache was corrupted and has been cleared.")
		if removeErr := os.Remove(cachePath); removeErr != nil && !os.IsNotExist(removeErr) {
			return nil, fmt.Errorf("corrupted credentials cache: %w; cannot remove: %w", err, removeErr)
		}
		return nil, nil
	}

	// Validate required fields
	if cached.Credentials == nil {
		return nil, nil
	}

	return &cached, nil
}

// saveCachedCredentials writes credentials to the cache file atomically.
func (cm *CredentialManager) saveCachedCredentials(cached *CachedCredentials) error {
	cacheDir, err := config.CacheDir()
	if err != nil {
		return err
	}
	cachePath := filepath.Join(cacheDir, credentialsCacheFile)
	tempPath := cachePath + ".tmp"

	data, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("cannot marshal credentials: %w", err)
	}

	// Write to temporary file with mode 0600
	if err := os.WriteFile(tempPath, data, 0o600); err != nil {
		return fmt.Errorf("cannot write credentials cache: %w", err)
	}

	// Atomically replace the cache file
	if err := os.Rename(tempPath, cachePath); err != nil {
		// Clean up temp file on rename failure
		_ = os.Remove(tempPath)
		return fmt.Errorf("cannot write credentials cache: %w", err)
	}

	return nil
}

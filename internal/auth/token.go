package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/config"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

const (
	tokenCacheFile = "token-cache"
	// expirationBuffer is the time before actual expiration when we consider a token expired.
	// This prevents race conditions where a token expires between validation and use.
	expirationBuffer = 30 * time.Second
)

// CachedToken reads the token from cache if it is still valid.
// Returns empty string and nil error if there is no valid cached token.
// Validates the token by parsing the JWT exp claim and checking expiration.
func CachedToken() (string, error) {
	cacheDir, err := config.CacheDir()
	if err != nil {
		return "", err
	}
	cachePath := filepath.Join(cacheDir, tokenCacheFile)

	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("cannot read token cache: %w", err)
	}

	token := string(data)
	if token == "" {
		return "", nil
	}

	// Parse JWT expiration from the token
	expiration, err := parseTokenExpiration(token)
	if err != nil {
		// Invalid token format — clean up corrupted cache so it does not keep failing.
		output.Debug("Cached token invalid: %v", err)
		if removeErr := os.Remove(cachePath); removeErr != nil && !os.IsNotExist(removeErr) {
			return "", fmt.Errorf("cached token invalid: %w; cannot remove token cache: %w", err, removeErr)
		}
		return "", nil
	}

	// Check if token is expired (with buffer)
	if time.Now().Add(expirationBuffer).After(expiration) {
		output.Debug("Cached token expired")
		return "", nil
	}

	remaining := time.Until(expiration)
	output.Debug("Using cached token (%d seconds remaining)", int(remaining.Seconds()))
	return token, nil
}

// SaveToken writes the token to the cache file.
func SaveToken(token string) error {
	cacheDir, err := config.CacheDir()
	if err != nil {
		return err
	}
	cachePath := filepath.Join(cacheDir, tokenCacheFile)

	if err := os.WriteFile(cachePath, []byte(token), 0o600); err != nil {
		return fmt.Errorf("cannot write token cache: %w", err)
	}
	return nil
}

// ClearToken removes the cached token.
func ClearToken() error {
	cacheDir, err := config.CacheDir()
	if err != nil {
		return err
	}
	cachePath := filepath.Join(cacheDir, tokenCacheFile)
	if err := os.Remove(cachePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove token cache: %w", err)
	}
	return nil
}

// parseTokenExpiration extracts the expiration time from a JWT token.
// Returns an error if the token is malformed or the exp claim is missing/invalid.
func parseTokenExpiration(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (middle part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse the JSON claims
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	if claims.Exp == 0 {
		return time.Time{}, fmt.Errorf("JWT missing exp claim")
	}

	return time.Unix(claims.Exp, 0), nil
}

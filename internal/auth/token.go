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
	return cachedTokenForIssuer("", "")
}

// CachedTokenForConfig returns only tokens cached for this exact OIDC issuer and client.
// Legacy, unscoped caches are deliberately not trusted for configured clients.
func CachedTokenForConfig(cfg PKCEConfig) (string, error) {
	return cachedTokenForIssuer(issuerForConfig(cfg), cfg.ClientID)
}

type scopedToken struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
	Token    string `json:"token"`
}

func issuerForConfig(cfg PKCEConfig) string {
	if cfg.KeycloakURL == "" && cfg.Realm == "" {
		return ""
	}
	return strings.TrimRight(cfg.KeycloakURL, "/") + "/realms/" + cfg.Realm
}

func cachedTokenForIssuer(issuer, clientID string) (string, error) {
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
	var entry scopedToken
	if json.Unmarshal(data, &entry) == nil && entry.Token != "" {
		if entry.Issuer != issuer || entry.ClientID != clientID {
			return "", nil
		}
		token = entry.Token
	} else if issuer != "" || clientID != "" {
		return "", nil
	}
	if token == "" {
		return "", nil
	}

	// Parse JWT expiration from the token
	expiration, err := parseTokenExpiration(token)
	if err != nil {
		// Invalid token format — clean up corrupted cache so it does not keep failing.
		if debugErr := output.Debug("Cached token invalid"); debugErr != nil {
			return "", fmt.Errorf("debug output failed: %w", debugErr)
		}
		if removeErr := os.Remove(cachePath); removeErr != nil && !os.IsNotExist(removeErr) {
			return "", fmt.Errorf("cached token invalid: %w; cannot remove token cache: %w", err, removeErr)
		}
		return "", nil
	}

	// Check if token is expired (with buffer)
	if time.Now().Add(expirationBuffer).After(expiration) {
		if debugErr := output.Debug("Cached token expired"); debugErr != nil {
			return "", fmt.Errorf("debug output failed: %w", debugErr)
		}
		return "", nil
	}

	remaining := time.Until(expiration)
	if debugErr := output.Debug("Using cached token (%d seconds remaining)", int(remaining.Seconds())); debugErr != nil {
		return "", fmt.Errorf("debug output failed: %w", debugErr)
	}
	return token, nil
}

// SaveToken writes the token to the cache file.
func SaveToken(token string) error {
	return saveToken(token, "", "")
}

// SaveTokenForConfig persists the ID token bound to its configured issuer and client.
func SaveTokenForConfig(token string, cfg PKCEConfig) error {
	return saveToken(token, issuerForConfig(cfg), cfg.ClientID)
}

func saveToken(token, issuer, clientID string) error {
	cacheDir, err := config.CacheDir()
	if err != nil {
		return err
	}
	cachePath := filepath.Join(cacheDir, tokenCacheFile)

	data := []byte(token)
	if issuer != "" || clientID != "" {
		data, err = json.Marshal(scopedToken{Issuer: issuer, ClientID: clientID, Token: token})
		if err != nil {
			return fmt.Errorf("cannot encode token cache: %w", err)
		}
	}
	if err := os.WriteFile(cachePath, data, 0o600); err != nil {
		return fmt.Errorf("cannot write token cache: %w", err)
	}
	// Existing caches may have permissive permissions. Restrict them on every write.
	if err := os.Chmod(cachePath, 0o600); err != nil {
		return fmt.Errorf("cannot restrict token cache permissions: %w", err)
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

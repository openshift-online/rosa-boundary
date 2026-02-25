package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openshift/rosa-boundary/internal/config"
)

const (
	tokenCacheFile      = "token-cache"
	cacheValidityPeriod = 4 * time.Minute
)

// CachedToken reads the token from cache if it is still valid.
// Returns empty string and nil error if there is no valid cached token.
func CachedToken() (string, error) {
	cacheDir, err := config.CacheDir()
	if err != nil {
		return "", err
	}
	cachePath := filepath.Join(cacheDir, tokenCacheFile)

	info, err := os.Stat(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("cannot stat token cache: %w", err)
	}

	age := time.Since(info.ModTime())
	if age >= cacheValidityPeriod {
		return "", nil
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		return "", fmt.Errorf("cannot read token cache: %w", err)
	}

	token := string(data)
	if token == "" {
		return "", nil
	}

	remaining := cacheValidityPeriod - age
	fmt.Fprintf(os.Stderr, "Using cached token (%d seconds remaining)\n", int(remaining.Seconds()))
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

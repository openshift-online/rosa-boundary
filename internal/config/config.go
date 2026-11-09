package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the resolved settings for a selected deployment profile.
type Config struct {
	AccountID          string
	Environment        string
	Project            string
	LambdaFunctionName string
	KeycloakURL        string
	KeycloakRealm      string
	OIDCClientID       string
	OIDCUseDeviceCode  bool
	AWSRegion          string
	ClusterName        string
	SRERoleARN         string
	InvokerRoleARN     string
	EFSFilesystemID    string
}

// ConfigDir returns the XDG config directory for rosa-boundary,
// creating it if it does not exist.
func ConfigDir() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		base = filepath.Join(home, ".config")
	}
	dir := filepath.Join(base, "rosa-boundary")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("cannot create config directory %s: %w", dir, err)
	}
	return dir, nil
}

// CacheDir returns the XDG cache directory for rosa-boundary,
// creating it if it does not exist.
func CacheDir() (string, error) {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		base = filepath.Join(home, ".cache")
	}
	dir := filepath.Join(base, "rosa-boundary")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("cannot create cache directory %s: %w", dir, err)
	}
	return dir, nil
}

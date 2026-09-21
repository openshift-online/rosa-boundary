package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/aws"
)

func TestCredentialManager_GetCredentials_FirstTime(t *testing.T) {
	// Setup: use temporary cache directory
	cacheDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheDir)

	cm := NewCredentialManager(15*time.Minute, 1*time.Hour)

	refreshCalled := false
	refresh := func(ctx context.Context) (*aws.TemporaryCredentials, error) {
		refreshCalled = true
		return &aws.TemporaryCredentials{
			AccessKeyID:     "AKIA_TEST_KEY",
			SecretAccessKey: "test-secret",
			SessionToken:    "test-token",
			Expiration:      time.Now().Add(1 * time.Hour),
		}, nil
	}

	roleARN := "arn:aws:iam::123456789012:role/test-role"
	oidcIssuer := "https://keycloak.example.com/realms/test"
	creds, err := cm.GetCredentials(context.Background(), roleARN, oidcIssuer, refresh)
	if err != nil {
		t.Fatalf("GetCredentials failed: %v", err)
	}

	if !refreshCalled {
		t.Error("Expected refresh to be called when no cached credentials exist")
	}

	if creds.AccessKeyID != "AKIA_TEST_KEY" {
		t.Errorf("Got AccessKeyID %q, want %q", creds.AccessKeyID, "AKIA_TEST_KEY")
	}
}

func TestCredentialManager_GetCredentials_UsesCachedIfValid(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheDir)

	cm := NewCredentialManager(15*time.Minute, 1*time.Hour)

	// First call - populate cache
	refresh := func(ctx context.Context) (*aws.TemporaryCredentials, error) {
		return &aws.TemporaryCredentials{
			AccessKeyID:     "AKIA_FIRST",
			SecretAccessKey: "first-secret",
			SessionToken:    "first-token",
			Expiration:      time.Now().Add(1 * time.Hour),
		}, nil
	}

	_, err := cm.GetCredentials(context.Background(), "arn:aws:iam::123456789012:role/test-role", "https://keycloak.example.com/realms/test", refresh)
	if err != nil {
		t.Fatalf("First GetCredentials failed: %v", err)
	}

	// Second call - should use cache without calling refresh
	refreshCalled := false
	refresh2 := func(ctx context.Context) (*aws.TemporaryCredentials, error) {
		refreshCalled = true
		return &aws.TemporaryCredentials{
			AccessKeyID:     "AKIA_SECOND",
			SecretAccessKey: "second-secret",
			SessionToken:    "second-token",
			Expiration:      time.Now().Add(1 * time.Hour),
		}, nil
	}

	creds, err := cm.GetCredentials(context.Background(), "arn:aws:iam::123456789012:role/test-role", "https://keycloak.example.com/realms/test", refresh2)
	if err != nil {
		t.Fatalf("Second GetCredentials failed: %v", err)
	}

	if refreshCalled {
		t.Error("Expected cached credentials to be used without calling refresh")
	}

	if creds.AccessKeyID != "AKIA_FIRST" {
		t.Errorf("Got AccessKeyID %q, want cached %q", creds.AccessKeyID, "AKIA_FIRST")
	}
}

func TestCredentialManager_GetCredentials_RefreshesOnIdleTimeout(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheDir)

	// Use very short idle timeout for testing
	cm := NewCredentialManager(100*time.Millisecond, 1*time.Hour)

	// First call - populate cache
	refresh := func(ctx context.Context) (*aws.TemporaryCredentials, error) {
		return &aws.TemporaryCredentials{
			AccessKeyID:     "AKIA_FIRST",
			SecretAccessKey: "first-secret",
			SessionToken:    "first-token",
			Expiration:      time.Now().Add(1 * time.Hour),
		}, nil
	}

	_, err := cm.GetCredentials(context.Background(), "arn:aws:iam::123456789012:role/test-role", "https://keycloak.example.com/realms/test", refresh)
	if err != nil {
		t.Fatalf("First GetCredentials failed: %v", err)
	}

	// Wait for idle timeout to expire
	time.Sleep(150 * time.Millisecond)

	// Second call - should refresh due to idle timeout
	refreshCalled := false
	refresh2 := func(ctx context.Context) (*aws.TemporaryCredentials, error) {
		refreshCalled = true
		return &aws.TemporaryCredentials{
			AccessKeyID:     "AKIA_SECOND",
			SecretAccessKey: "second-secret",
			SessionToken:    "second-token",
			Expiration:      time.Now().Add(1 * time.Hour),
		}, nil
	}

	creds, err := cm.GetCredentials(context.Background(), "arn:aws:iam::123456789012:role/test-role", "https://keycloak.example.com/realms/test", refresh2)
	if err != nil {
		t.Fatalf("Second GetCredentials failed: %v", err)
	}

	if !refreshCalled {
		t.Error("Expected refresh to be called after idle timeout")
	}

	if creds.AccessKeyID != "AKIA_SECOND" {
		t.Errorf("Got AccessKeyID %q, want refreshed %q", creds.AccessKeyID, "AKIA_SECOND")
	}
}

func TestCredentialManager_GetCredentials_RefreshesOnMaxDuration(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheDir)

	// Use very short max duration for testing
	cm := NewCredentialManager(1*time.Hour, 100*time.Millisecond)

	// First call - populate cache
	refresh := func(ctx context.Context) (*aws.TemporaryCredentials, error) {
		return &aws.TemporaryCredentials{
			AccessKeyID:     "AKIA_FIRST",
			SecretAccessKey: "first-secret",
			SessionToken:    "first-token",
			Expiration:      time.Now().Add(1 * time.Hour),
		}, nil
	}

	_, err := cm.GetCredentials(context.Background(), "arn:aws:iam::123456789012:role/test-role", "https://keycloak.example.com/realms/test", refresh)
	if err != nil {
		t.Fatalf("First GetCredentials failed: %v", err)
	}

	// Wait for max duration to expire
	time.Sleep(150 * time.Millisecond)

	// Second call - should refresh due to max duration exceeded
	refreshCalled := false
	refresh2 := func(ctx context.Context) (*aws.TemporaryCredentials, error) {
		refreshCalled = true
		return &aws.TemporaryCredentials{
			AccessKeyID:     "AKIA_SECOND",
			SecretAccessKey: "second-secret",
			SessionToken:    "second-token",
			Expiration:      time.Now().Add(1 * time.Hour),
		}, nil
	}

	creds, err := cm.GetCredentials(context.Background(), "arn:aws:iam::123456789012:role/test-role", "https://keycloak.example.com/realms/test", refresh2)
	if err != nil {
		t.Fatalf("Second GetCredentials failed: %v", err)
	}

	if !refreshCalled {
		t.Error("Expected refresh to be called after max duration exceeded")
	}

	if creds.AccessKeyID != "AKIA_SECOND" {
		t.Errorf("Got AccessKeyID %q, want refreshed %q", creds.AccessKeyID, "AKIA_SECOND")
	}
}

func TestCredentialManager_GetCredentials_UpdatesLastUsedTime(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheDir)

	cm := NewCredentialManager(200*time.Millisecond, 1*time.Hour)

	// First call
	refresh := func(ctx context.Context) (*aws.TemporaryCredentials, error) {
		return &aws.TemporaryCredentials{
			AccessKeyID:     "AKIA_TEST",
			SecretAccessKey: "test-secret",
			SessionToken:    "test-token",
			Expiration:      time.Now().Add(1 * time.Hour),
		}, nil
	}

	_, err := cm.GetCredentials(context.Background(), "arn:aws:iam::123456789012:role/test-role", "https://keycloak.example.com/realms/test", refresh)
	if err != nil {
		t.Fatalf("First GetCredentials failed: %v", err)
	}

	// Wait 100ms (less than 200ms idle timeout)
	time.Sleep(100 * time.Millisecond)

	// Second call - should use cache and update LastUsedAt
	_, err = cm.GetCredentials(context.Background(), "arn:aws:iam::123456789012:role/test-role", "https://keycloak.example.com/realms/test", refresh)
	if err != nil {
		t.Fatalf("Second GetCredentials failed: %v", err)
	}

	// Wait another 100ms (total 200ms from first call, but only 100ms from second)
	time.Sleep(100 * time.Millisecond)

	// Third call - should still use cache because LastUsedAt was updated
	refreshCalled := false
	refresh2 := func(ctx context.Context) (*aws.TemporaryCredentials, error) {
		refreshCalled = true
		return refresh(ctx)
	}

	_, err = cm.GetCredentials(context.Background(), "arn:aws:iam::123456789012:role/test-role", "https://keycloak.example.com/realms/test", refresh2)
	if err != nil {
		t.Fatalf("Third GetCredentials failed: %v", err)
	}

	if refreshCalled {
		t.Error("Expected cached credentials to be used because LastUsedAt was updated by second call")
	}
}

func TestCredentialManager_GetCredentials_RefreshError(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheDir)

	cm := NewCredentialManager(15*time.Minute, 1*time.Hour)

	expectedErr := errors.New("authentication failed")
	refresh := func(ctx context.Context) (*aws.TemporaryCredentials, error) {
		return nil, expectedErr
	}

	_, err := cm.GetCredentials(context.Background(), "arn:aws:iam::123456789012:role/test-role", "https://keycloak.example.com/realms/test", refresh)
	if err == nil {
		t.Fatal("Expected error when refresh fails, got nil")
	}

	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected error to wrap %v, got %v", expectedErr, err)
	}
}

func TestCredentialManager_ClearCredentials(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheDir)

	cm := NewCredentialManager(15*time.Minute, 1*time.Hour)

	// Populate cache
	refresh := func(ctx context.Context) (*aws.TemporaryCredentials, error) {
		return &aws.TemporaryCredentials{
			AccessKeyID:     "AKIA_TEST",
			SecretAccessKey: "test-secret",
			SessionToken:    "test-token",
		}, nil
	}

	_, err := cm.GetCredentials(context.Background(), "arn:aws:iam::123456789012:role/test-role", "https://keycloak.example.com/realms/test", refresh)
	if err != nil {
		t.Fatalf("GetCredentials failed: %v", err)
	}

	// Verify cache file exists
	cachePath := filepath.Join(cacheDir, "rosa-boundary", credentialsCacheFile)
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		t.Fatal("Expected cache file to exist after GetCredentials")
	}

	// Clear credentials
	if err := cm.ClearCredentials(); err != nil {
		t.Fatalf("ClearCredentials failed: %v", err)
	}

	// Verify cache file is deleted
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Error("Expected cache file to be deleted after ClearCredentials")
	}

	// Next call should refresh
	refreshCalled := false
	refresh2 := func(ctx context.Context) (*aws.TemporaryCredentials, error) {
		refreshCalled = true
		return refresh(ctx)
	}

	_, err = cm.GetCredentials(context.Background(), "arn:aws:iam::123456789012:role/test-role", "https://keycloak.example.com/realms/test", refresh2)
	if err != nil {
		t.Fatalf("GetCredentials after clear failed: %v", err)
	}

	if !refreshCalled {
		t.Error("Expected refresh to be called after clearing credentials")
	}
}

func TestCredentialManager_HandlesCorruptedCache(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheDir)

	cm := NewCredentialManager(15*time.Minute, 1*time.Hour)

	// Write corrupted cache file
	cachePath := filepath.Join(cacheDir, "rosa-boundary", credentialsCacheFile)
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatalf("Failed to create cache directory: %v", err)
	}
	if err := os.WriteFile(cachePath, []byte("corrupted json{{{"), 0o600); err != nil {
		t.Fatalf("Failed to write corrupted cache: %v", err)
	}

	// GetCredentials should handle corrupted cache gracefully
	refreshCalled := false
	refresh := func(ctx context.Context) (*aws.TemporaryCredentials, error) {
		refreshCalled = true
		return &aws.TemporaryCredentials{
			AccessKeyID:     "AKIA_TEST",
			SecretAccessKey: "test-secret",
			SessionToken:    "test-token",
		}, nil
	}

	_, err := cm.GetCredentials(context.Background(), "arn:aws:iam::123456789012:role/test-role", "https://keycloak.example.com/realms/test", refresh)
	if err != nil {
		t.Fatalf("GetCredentials failed with corrupted cache: %v", err)
	}

	if !refreshCalled {
		t.Error("Expected refresh to be called when cache is corrupted")
	}
}

func TestNewCredentialManager_Defaults(t *testing.T) {
	// Test with zero values
	cm := NewCredentialManager(0, 0)

	if cm.idleTimeout != defaultIdleTimeout {
		t.Errorf("Got idle timeout %v, want default %v", cm.idleTimeout, defaultIdleTimeout)
	}

	if cm.maxDuration != defaultMaxDuration {
		t.Errorf("Got max duration %v, want default %v", cm.maxDuration, defaultMaxDuration)
	}
}

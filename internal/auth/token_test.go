package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseTokenExpiration(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid token with exp claim",
			token:     createValidJWT(time.Now().Add(1 * time.Hour).Unix()),
			wantError: false,
		},
		{
			name:      "invalid format - only 2 parts",
			token:     "header.payload",
			wantError: true,
			errorMsg:  "expected 3 parts, got 2",
		},
		{
			name:      "invalid format - 4 parts",
			token:     "header.payload.signature.extra",
			wantError: true,
			errorMsg:  "expected 3 parts, got 4",
		},
		{
			name:      "invalid base64 in payload",
			token:     "header.!!!invalid-base64!!!.signature",
			wantError: true,
			errorMsg:  "failed to decode JWT payload",
		},
		{
			name:      "invalid JSON in payload",
			token:     "header." + base64.RawURLEncoding.EncodeToString([]byte("not-json")) + ".signature",
			wantError: true,
			errorMsg:  "failed to parse JWT claims",
		},
		{
			name:      "missing exp claim",
			token:     createJWTWithoutExp(),
			wantError: true,
			errorMsg:  "missing exp claim",
		},
		{
			name:      "zero exp claim",
			token:     createValidJWT(0),
			wantError: true,
			errorMsg:  "missing exp claim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exp, err := parseTokenExpiration(tt.token)

			if tt.wantError {
				if err == nil {
					t.Errorf("parseTokenExpiration() expected error containing %q, got nil", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("parseTokenExpiration() error = %q, want error containing %q", err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("parseTokenExpiration() unexpected error: %v", err)
				}
				if exp.IsZero() {
					t.Error("parseTokenExpiration() returned zero time for valid token")
				}
			}
		})
	}
}

func TestParseTokenExpiration_CorrectExpirationTime(t *testing.T) {
	expectedExp := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	token := createValidJWT(expectedExp.Unix())

	got, err := parseTokenExpiration(token)
	if err != nil {
		t.Fatalf("parseTokenExpiration() unexpected error: %v", err)
	}

	if !got.Equal(expectedExp) {
		t.Errorf("parseTokenExpiration() = %v, want %v", got, expectedExp)
	}
}

func TestCachedToken(t *testing.T) {
	// Set up temporary cache directory
	tmpDir := t.TempDir()
	originalCacheDir := os.Getenv("XDG_CACHE_HOME")
	os.Setenv("XDG_CACHE_HOME", tmpDir)
	t.Cleanup(func() {
		if originalCacheDir != "" {
			os.Setenv("XDG_CACHE_HOME", originalCacheDir)
		} else {
			os.Unsetenv("XDG_CACHE_HOME")
		}
	})

	tests := []struct {
		name          string
		setupToken    string
		setupExp      time.Time
		expectToken   bool
		expectStderr  string
	}{
		{
			name:         "valid cached token",
			setupExp:     time.Now().Add(1 * time.Hour),
			expectToken:  true,
			expectStderr: "Using cached token",
		},
		{
			name:         "expired token",
			setupExp:     time.Now().Add(-1 * time.Hour),
			expectToken:  false,
			expectStderr: "Cached token expired",
		},
		{
			name:         "token expiring within buffer",
			setupExp:     time.Now().Add(15 * time.Second), // Less than 30s buffer
			expectToken:  false,
			expectStderr: "Cached token expired",
		},
		{
			name:         "invalid token format",
			setupToken:   "not-a-jwt",
			expectToken:  false,
			expectStderr: "Cached token invalid",
		},
		{
			name:         "empty token",
			setupToken:   "",
			expectToken:  false,
			expectStderr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create rosa-boundary cache directory
			cacheDir := filepath.Join(tmpDir, "rosa-boundary")
			if err := os.MkdirAll(cacheDir, 0o755); err != nil {
				t.Fatalf("failed to create cache dir: %v", err)
			}
			cachePath := filepath.Join(cacheDir, tokenCacheFile)

			// Set up token file if needed
			if tt.setupToken != "" {
				if err := os.WriteFile(cachePath, []byte(tt.setupToken), 0o600); err != nil {
					t.Fatalf("failed to write test token: %v", err)
				}
			} else if !tt.setupExp.IsZero() {
				token := createValidJWT(tt.setupExp.Unix())
				if err := os.WriteFile(cachePath, []byte(token), 0o600); err != nil {
					t.Fatalf("failed to write test token: %v", err)
				}
			}

			// Capture stderr
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			token, err := CachedToken()

			w.Close()
			os.Stderr = oldStderr

			var stderrBuf bytes.Buffer
			io.Copy(&stderrBuf, r)
			stderr := stderrBuf.String()

			if err != nil {
				t.Errorf("CachedToken() unexpected error: %v", err)
			}

			if tt.expectToken {
				if token == "" {
					t.Error("CachedToken() expected token, got empty string")
				}
			} else {
				if token != "" {
					t.Errorf("CachedToken() expected empty token, got %q", token)
				}
			}

			if tt.expectStderr != "" && !strings.Contains(stderr, tt.expectStderr) {
				t.Errorf("CachedToken() stderr = %q, want substring %q", stderr, tt.expectStderr)
			}

			// Clean up for next test
			os.RemoveAll(cacheDir)
		})
	}
}

func TestCachedToken_NoFile(t *testing.T) {
	// Set up temporary cache directory with no token file
	tmpDir := t.TempDir()
	originalCacheDir := os.Getenv("XDG_CACHE_HOME")
	os.Setenv("XDG_CACHE_HOME", tmpDir)
	t.Cleanup(func() {
		if originalCacheDir != "" {
			os.Setenv("XDG_CACHE_HOME", originalCacheDir)
		} else {
			os.Unsetenv("XDG_CACHE_HOME")
		}
	})

	// Create cache directory but no token file
	cacheDir := filepath.Join(tmpDir, "rosa-boundary")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("failed to create cache dir: %v", err)
	}

	token, err := CachedToken()
	if err != nil {
		t.Errorf("CachedToken() with missing file returned error: %v", err)
	}
	if token != "" {
		t.Errorf("CachedToken() with missing file = %q, want empty string", token)
	}
}

func TestSaveToken(t *testing.T) {
	// Set up temporary cache directory
	tmpDir := t.TempDir()
	originalCacheDir := os.Getenv("XDG_CACHE_HOME")
	os.Setenv("XDG_CACHE_HOME", tmpDir)
	t.Cleanup(func() {
		if originalCacheDir != "" {
			os.Setenv("XDG_CACHE_HOME", originalCacheDir)
		} else {
			os.Unsetenv("XDG_CACHE_HOME")
		}
	})

	testToken := createValidJWT(time.Now().Add(1 * time.Hour).Unix())

	if err := SaveToken(testToken); err != nil {
		t.Fatalf("SaveToken() unexpected error: %v", err)
	}

	cacheDir := filepath.Join(tmpDir, "rosa-boundary")
	cachePath := filepath.Join(cacheDir, tokenCacheFile)

	// Verify file exists
	data, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("saved token file not readable: %v", err)
	}

	if string(data) != testToken {
		t.Errorf("SaveToken() saved token = %q, want %q", string(data), testToken)
	}

	// Verify file permissions are 0600
	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatalf("cannot stat token file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("SaveToken() file permissions = %o, want 0600", perm)
	}
}

func TestClearToken(t *testing.T) {
	// Set up temporary cache directory
	tmpDir := t.TempDir()
	originalCacheDir := os.Getenv("XDG_CACHE_HOME")
	os.Setenv("XDG_CACHE_HOME", tmpDir)
	t.Cleanup(func() {
		if originalCacheDir != "" {
			os.Setenv("XDG_CACHE_HOME", originalCacheDir)
		} else {
			os.Unsetenv("XDG_CACHE_HOME")
		}
	})

	cacheDir := filepath.Join(tmpDir, "rosa-boundary")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("failed to create cache dir: %v", err)
	}
	cachePath := filepath.Join(cacheDir, tokenCacheFile)

	// Create a token file
	testToken := createValidJWT(time.Now().Add(1 * time.Hour).Unix())
	if err := os.WriteFile(cachePath, []byte(testToken), 0o600); err != nil {
		t.Fatalf("failed to create test token file: %v", err)
	}

	// Clear the token
	if err := ClearToken(); err != nil {
		t.Errorf("ClearToken() unexpected error: %v", err)
	}

	// Verify file is deleted
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Error("ClearToken() did not delete token file")
	}
}

func TestClearToken_AlreadyMissing(t *testing.T) {
	// Set up temporary cache directory with no token file
	tmpDir := t.TempDir()
	originalCacheDir := os.Getenv("XDG_CACHE_HOME")
	os.Setenv("XDG_CACHE_HOME", tmpDir)
	t.Cleanup(func() {
		if originalCacheDir != "" {
			os.Setenv("XDG_CACHE_HOME", originalCacheDir)
		} else {
			os.Unsetenv("XDG_CACHE_HOME")
		}
	})

	cacheDir := filepath.Join(tmpDir, "rosa-boundary")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("failed to create cache dir: %v", err)
	}

	// Clear token when file doesn't exist (should not error)
	if err := ClearToken(); err != nil {
		t.Errorf("ClearToken() on missing file returned error: %v", err)
	}
}

// Test helper: creates a valid JWT with the given expiration timestamp
func createValidJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := map[string]any{
		"exp": exp,
		"sub": "test-user",
		"iss": "test-issuer",
	}
	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

	return header + "." + encodedPayload + "." + signature
}

// Test helper: creates a JWT without an exp claim
func createJWTWithoutExp() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := map[string]any{
		"sub": "test-user",
		"iss": "test-issuer",
	}
	payloadBytes, _ := json.Marshal(payload)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

	return header + "." + encodedPayload + "." + signature
}

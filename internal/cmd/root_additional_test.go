package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestIsAuthError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "ExpiredToken error",
			err:      errors.New("ExpiredToken: The security token included in the request is expired"),
			expected: true,
		},
		{
			name:     "InvalidClientTokenId error",
			err:      errors.New("InvalidClientTokenId: The security token is invalid"),
			expected: true,
		},
		{
			name:     "InvalidIdentityToken error",
			err:      errors.New("InvalidIdentityToken: Invalid identity token"),
			expected: true,
		},
		{
			name:     "ExpiredToken substring match",
			err:      errors.New("failed to assume role: ExpiredToken"),
			expected: true,
		},
		{
			name:     "InvalidClientTokenId substring match",
			err:      errors.New("aws error: InvalidClientTokenId occurred"),
			expected: true,
		},
		{
			name:     "InvalidIdentityToken substring match",
			err:      errors.New("oidc validation failed: InvalidIdentityToken"),
			expected: true,
		},
		{
			name:     "SignatureDoesNotMatch error - should NOT be auth error",
			err:      errors.New("SignatureDoesNotMatch: The request signature we calculated does not match"),
			expected: false,
		},
		{
			name:     "AccessDenied error - not an auth retry candidate",
			err:      errors.New("AccessDenied: User is not authorized"),
			expected: false,
		},
		{
			name:     "generic network error",
			err:      errors.New("connection timeout"),
			expected: false,
		},
		{
			name:     "empty error message",
			err:      errors.New(""),
			expected: false,
		},
		{
			name:     "case sensitivity - should match ExpiredToken",
			err:      errors.New("error: ExpiredToken detected"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAuthError(tt.err)
			if result != tt.expected {
				t.Errorf("isAuthError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestGetConfig(t *testing.T) {
	// Save original viper state and restore after test
	originalViper := viper.GetViper()
	defer func() {
		viper.Reset()
		for k, v := range originalViper.AllSettings() {
			viper.Set(k, v)
		}
	}()

	tests := []struct {
		name              string
		keycloakURL       string
		requireKeycloakURL bool
		wantError         bool
		errorMsg          string
	}{
		{
			name:              "keycloak URL required and provided",
			keycloakURL:       "https://keycloak.example.com",
			requireKeycloakURL: true,
			wantError:         false,
		},
		{
			name:              "keycloak URL required but missing",
			keycloakURL:       "",
			requireKeycloakURL: true,
			wantError:         true,
			errorMsg:          "keycloak URL is required",
		},
		{
			name:              "keycloak URL not required and not provided",
			keycloakURL:       "",
			requireKeycloakURL: false,
			wantError:         false,
		},
		{
			name:              "keycloak URL not required but provided",
			keycloakURL:       "https://keycloak.example.com",
			requireKeycloakURL: false,
			wantError:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper before each test
			viper.Reset()
			viper.Set("keycloak_url", tt.keycloakURL)

			cfg, err := getConfig(tt.requireKeycloakURL)

			if tt.wantError {
				if err == nil {
					t.Errorf("getConfig() expected error containing %q, got nil", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("getConfig() error = %q, want error containing %q", err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("getConfig() unexpected error: %v", err)
				}
				if cfg == nil {
					t.Error("getConfig() returned nil config without error")
				}
			}
		})
	}
}

func TestDebugf(t *testing.T) {
	tests := []struct {
		name          string
		verboseMode   bool
		format        string
		args          []any
		expectOutput  bool
		expectedMsg   string
	}{
		{
			name:         "verbose mode enabled - simple message",
			verboseMode:  true,
			format:       "test message",
			args:         nil,
			expectOutput: true,
			expectedMsg:  "[debug] test message",
		},
		{
			name:         "verbose mode enabled - formatted message",
			verboseMode:  true,
			format:       "user %s logged in at %d",
			args:         []any{"alice", 12345},
			expectOutput: true,
			expectedMsg:  "[debug] user alice logged in at 12345",
		},
		{
			name:         "verbose mode disabled - no output",
			verboseMode:  false,
			format:       "this should not appear",
			args:         nil,
			expectOutput: false,
		},
		{
			name:         "verbose mode enabled - multiple args",
			verboseMode:  true,
			format:       "values: %v, %v, %v",
			args:         []any{1, "two", 3.0},
			expectOutput: true,
			expectedMsg:  "[debug] values: 1, two, 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set verbose flag
			oldVerbose := verbose
			verbose = tt.verboseMode
			defer func() { verbose = oldVerbose }()

			// Capture stderr
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			debugf(tt.format, tt.args...)

			w.Close()
			os.Stderr = oldStderr

			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			if tt.expectOutput {
				if !strings.Contains(output, tt.expectedMsg) {
					t.Errorf("debugf() output = %q, want to contain %q", output, tt.expectedMsg)
				}
			} else {
				if output != "" {
					t.Errorf("debugf() with verbose=false produced output: %q", output)
				}
			}
		})
	}
}

func TestDebugf_OutputToStderr(t *testing.T) {
	// Verify debugf writes to stderr, not stdout
	oldVerbose := verbose
	verbose = true
	defer func() { verbose = oldVerbose }()

	// Capture stdout
	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut

	// Capture stderr
	oldStderr := os.Stderr
	rErr, wErr, _ := os.Pipe()
	os.Stderr = wErr

	debugf("test message")

	wOut.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var stdoutBuf, stderrBuf bytes.Buffer
	io.Copy(&stdoutBuf, rOut)
	io.Copy(&stderrBuf, rErr)

	stdout := stdoutBuf.String()
	stderr := stderrBuf.String()

	if stdout != "" {
		t.Errorf("debugf() wrote to stdout: %q, expected only stderr output", stdout)
	}

	if !strings.Contains(stderr, "[debug] test message") {
		t.Errorf("debugf() stderr = %q, want to contain '[debug] test message'", stderr)
	}
}

func TestDebugf_NewlineAppended(t *testing.T) {
	// Verify debugf always appends a newline
	oldVerbose := verbose
	verbose = true
	defer func() { verbose = oldVerbose }()

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	debugf("test without newline")

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !strings.HasSuffix(output, "\n") {
		t.Errorf("debugf() output = %q, expected to end with newline", output)
	}

	// Should have exactly one newline at the end
	expectedLines := 1
	actualLines := strings.Count(output, "\n")
	if actualLines != expectedLines {
		t.Errorf("debugf() output has %d newlines, want %d", actualLines, expectedLines)
	}
}

func TestGetConfig_SuggestsEnvironmentVariables(t *testing.T) {
	// Verify error message suggests both flag and environment variables
	viper.Reset()
	viper.Set("keycloak_url", "")

	_, err := getConfig(true)

	if err == nil {
		t.Fatal("getConfig() expected error, got nil")
	}

	errorMsg := err.Error()

	// Error should mention the flag
	if !strings.Contains(errorMsg, "--keycloak-url") {
		t.Errorf("error message should mention --keycloak-url flag, got: %q", errorMsg)
	}

	// Error should mention environment variables
	if !strings.Contains(errorMsg, "ROSA_BOUNDARY_KEYCLOAK_URL") || !strings.Contains(errorMsg, "KEYCLOAK_URL") {
		t.Errorf("error message should mention ROSA_BOUNDARY_KEYCLOAK_URL or KEYCLOAK_URL env vars, got: %q", errorMsg)
	}
}

// Benchmark debugf overhead when verbose is disabled (should be near-zero)
func BenchmarkDebugf_Disabled(b *testing.B) {
	verbose = false
	for i := 0; i < b.N; i++ {
		debugf("benchmark message %d", i)
	}
}

// Benchmark debugf when verbose is enabled
func BenchmarkDebugf_Enabled(b *testing.B) {
	verbose = true
	// Discard output
	oldStderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	defer func() { os.Stderr = oldStderr }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		debugf("benchmark message %d", i)
	}
}

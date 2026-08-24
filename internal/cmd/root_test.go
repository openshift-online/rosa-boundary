package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestRequiresAuth(t *testing.T) {
	tests := []struct {
		name           string
		cmdName        string
		parentName     string
		expectedResult bool
	}{
		// Commands that should NOT require auth
		{"version command", "version", "", false},
		{"configure command", "configure", "", false},
		{"login command", "login", "", false},
		{"create-investigation command", "create-investigation", "", false},
		{"start-task command", "start-task", "", false},
		{"help command", "help", "", false},

		// Completion commands should NOT require auth
		{"completion command", "completion", "", false},
		{"completion bash", "bash", "completion", false},
		{"completion zsh", "zsh", "completion", false},
		{"completion fish", "fish", "completion", false},
		{"completion powershell", "powershell", "completion", false},
		{"__complete hidden command", "__complete", "", false},
		{"__completeNoDesc hidden command", "__completeNoDesc", "", false},

		// Commands that SHOULD require auth
		{"list-tasks command", "list-tasks", "", true},
		{"list-investigations command", "list-investigations", "", true},
		{"stop-task command", "stop-task", "", true},
		{"join-task command", "join-task", "", true},
		{"close-investigation command", "close-investigation", "", true},

		// Edge cases: standalone shell commands (NOT under completion) SHOULD require auth
		{"standalone bash", "bash", "", true},
		{"standalone zsh", "zsh", "", true},
		{"standalone fish", "fish", "", true},
		{"standalone powershell", "powershell", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{
				Use: tt.cmdName,
			}

			// Set up parent if specified
			if tt.parentName != "" {
				parent := &cobra.Command{
					Use: tt.parentName,
				}
				parent.AddCommand(cmd)
			}

			result := requiresAuth(cmd)
			if result != tt.expectedResult {
				t.Errorf("requiresAuth(%s) = %v, want %v", tt.cmdName, result, tt.expectedResult)
			}
		})
	}
}

func TestRequiresAuthCompletionRegression(t *testing.T) {
	// Regression test: Ensure completion commands don't trigger auth
	// This prevents users from needing OIDC tokens just to generate shell completions

	t.Run("completion bash does not require auth", func(t *testing.T) {
		bashCmd := &cobra.Command{Use: "bash"}
		completionCmd := &cobra.Command{Use: "completion"}
		completionCmd.AddCommand(bashCmd)

		if requiresAuth(bashCmd) {
			t.Error("completion bash should not require authentication")
		}
	})

	t.Run("__complete does not require auth", func(t *testing.T) {
		completeCmd := &cobra.Command{Use: "__complete"}
		if requiresAuth(completeCmd) {
			t.Error("__complete should not require authentication")
		}
	})

	t.Run("__completeNoDesc does not require auth", func(t *testing.T) {
		completeNoDescCmd := &cobra.Command{Use: "__completeNoDesc"}
		if requiresAuth(completeNoDescCmd) {
			t.Error("__completeNoDesc should not require authentication")
		}
	})

	// Edge case: standalone "bash" command (not under completion) SHOULD require auth
	t.Run("standalone bash command requires auth", func(t *testing.T) {
		bashCmd := &cobra.Command{Use: "bash"}
		if !requiresAuth(bashCmd) {
			t.Error("standalone bash command should require authentication")
		}
	})

	// Edge case: child of non-completion "bash" command SHOULD require auth
	t.Run("child of non-completion bash requires auth", func(t *testing.T) {
		bashCmd := &cobra.Command{Use: "bash"}
		childCmd := &cobra.Command{Use: "subcommand"}
		bashCmd.AddCommand(childCmd)

		if !requiresAuth(childCmd) {
			t.Error("child of non-completion bash should require authentication")
		}
	})
}

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
	// Do NOT call viper.Reset() - it destroys Cobra flag bindings from package init
	originalSettings := viper.AllSettings()
	defer func() {
		// Restore original settings without Reset to preserve bindings
		for k := range viper.AllSettings() {
			if _, exists := originalSettings[k]; !exists {
				// Remove keys added by the test
				viper.Set(k, nil)
			}
		}
		for k, v := range originalSettings {
			viper.Set(k, v)
		}
	}()

	tests := []struct {
		name               string
		keycloakURL        string
		requireKeycloakURL bool
		wantError          bool
		errorMsg           string
	}{
		{
			name:               "keycloak URL required and provided",
			keycloakURL:        "https://keycloak.example.com",
			requireKeycloakURL: true,
			wantError:          false,
		},
		{
			name:               "keycloak URL required but missing",
			keycloakURL:        "",
			requireKeycloakURL: true,
			wantError:          true,
			errorMsg:           "keycloak URL is required",
		},
		{
			name:               "keycloak URL not required and not provided",
			keycloakURL:        "",
			requireKeycloakURL: false,
			wantError:          false,
		},
		{
			name:               "keycloak URL not required but provided",
			keycloakURL:        "https://keycloak.example.com",
			requireKeycloakURL: false,
			wantError:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set test-specific configuration without Reset to preserve bindings
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
		name         string
		verboseMode  bool
		format       string
		args         []any
		expectOutput bool
		expectedMsg  string
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
			r, w, pipeErr := os.Pipe()
			if pipeErr != nil {
				t.Fatalf("os.Pipe() failed: %v", pipeErr)
			}
			os.Stderr = w

			debugf(tt.format, tt.args...)

			if closeErr := w.Close(); closeErr != nil {
				t.Fatalf("w.Close() failed: %v", closeErr)
			}
			os.Stderr = oldStderr

			var buf bytes.Buffer
			if _, copyErr := io.Copy(&buf, r); copyErr != nil {
				t.Fatalf("io.Copy() failed: %v", copyErr)
			}
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
	rOut, wOut, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("os.Pipe() for stdout failed: %v", pipeErr)
	}
	os.Stdout = wOut

	// Capture stderr
	oldStderr := os.Stderr
	rErr, wErr, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("os.Pipe() for stderr failed: %v", pipeErr)
	}
	os.Stderr = wErr

	debugf("test message")

	if closeErr := wOut.Close(); closeErr != nil {
		t.Fatalf("wOut.Close() failed: %v", closeErr)
	}
	if closeErr := wErr.Close(); closeErr != nil {
		t.Fatalf("wErr.Close() failed: %v", closeErr)
	}
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var stdoutBuf, stderrBuf bytes.Buffer
	if _, copyErr := io.Copy(&stdoutBuf, rOut); copyErr != nil {
		t.Fatalf("io.Copy() for stdout failed: %v", copyErr)
	}
	if _, copyErr := io.Copy(&stderrBuf, rErr); copyErr != nil {
		t.Fatalf("io.Copy() for stderr failed: %v", copyErr)
	}

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
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("os.Pipe() failed: %v", pipeErr)
	}
	os.Stderr = w

	debugf("test without newline")

	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("w.Close() failed: %v", closeErr)
	}
	os.Stderr = oldStderr

	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Fatalf("io.Copy() failed: %v", copyErr)
	}
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

	// Capture Viper state before reset
	savedSettings := viper.AllSettings()
	t.Cleanup(func() {
		viper.Reset()
		if len(savedSettings) > 0 {
			_ = viper.MergeConfigMap(savedSettings)
		}
	})

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
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		b.Fatalf("os.Open(os.DevNull) failed: %v", err)
	}
	os.Stderr = devNull
	b.Cleanup(func() {
		os.Stderr = oldStderr
		devNull.Close()
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		debugf("benchmark message %d", i)
	}
}

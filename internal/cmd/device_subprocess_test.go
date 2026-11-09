package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This subprocess contract ensures an operator can receive a challenge while
// the CLI is still running, including in JSON mode.
func TestDeviceLoginSubprocessStreamsChallengeBeforeApproval(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a local CLI subprocess")
	}
	approved := make(chan struct{})
	var deny atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/test/protocol/openid-connect/auth/device":
			if deny.Load() {
				http.Error(w, "not authorized", http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "secret-device-code", "user_code": "CODE-1234", "verification_uri": "https://example.invalid/verify", "interval": 1, "expires_in": 20})
		case "/realms/test/protocol/openid-connect/token":
			select {
			case <-approved:
				_ = json.NewEncoder(w).Encode(map[string]string{"id_token": testJWT(time.Now().Add(time.Hour))})
			case <-r.Context().Done():
				return
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	bin := filepath.Join(root, "rosa-boundary")
	configHome := filepath.Join(root, "config")
	configDir := filepath.Join(configHome, "rosa-boundary")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	profile := map[string]any{"active_profile": "local", "profiles": map[string]any{"local": map[string]any{
		"account_id": "123456789012", "aws_region": "us-east-1", "keycloak_url": server.URL,
		"keycloak_realm": "test", "oidc_client_id": "cli",
	}}}
	profileData, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), profileData, 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", bin, "../../cmd/rosa-boundary")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v: %s", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, bin, "--profile", "local", "--use-device-code", "login", "--force", "-o", "json")
	process.Env = append(os.Environ(), "XDG_CONFIG_HOME="+configHome, "XDG_CACHE_HOME="+filepath.Join(root, "cache"))
	stdout, err := process.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := process.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 16)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	challenge := false
	for !challenge {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatal("CLI exited before challenge")
			}
			if strings.Contains(line, "secret-device-code") {
				t.Fatal("device secret leaked to stderr")
			}
			if strings.Contains(line, "ROSA_BOUNDARY_AUTH_EVENT") {
				t.Fatal("obsolete auth event emitted")
			}
			if strings.Contains(line, "CODE-1234") && strings.Contains(line, "https://example.invalid/verify") {
				challenge = true
			}
		case <-ctx.Done():
			t.Fatalf("challenge was not emitted before approval: %v", ctx.Err())
		}
	}
	close(approved)
	for line := range lines {
		if strings.Contains(line, "secret-device-code") || strings.Contains(line, "ROSA_BOUNDARY_AUTH_EVENT") {
			t.Fatal("device secret or obsolete event leaked")
		}
	}
	out, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(fmt.Errorf("CLI exit: %w", err))
	}
	assertOneJSON(t, string(out), map[string]any{"profile": "local", "authenticated": true})

	// Authentication failure must never reuse a cached success document.
	deny.Store(true)
	failed := exec.CommandContext(ctx, bin, "--profile", "local", "--use-device-code", "login", "--force", "-o", "json")
	failed.Env = process.Env
	var diagnostics bytes.Buffer
	failed.Stderr = &diagnostics
	failedOut, failedErr := failed.Output()
	if failedErr == nil || !strings.Contains(diagnostics.String(), "Error:") || strings.Contains(diagnostics.String(), "ROSA_BOUNDARY_AUTH_EVENT") {
		t.Fatalf("failed login: error=%v stdout=%q stderr=%q", failedErr, failedOut, diagnostics.String())
	}
	assertJSONFailure(t, string(failedOut), "authentication failed")
}

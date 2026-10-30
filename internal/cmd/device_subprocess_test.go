package cmd

import (
	"bufio"
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
	"testing"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/authstatus"
)

// This subprocess contract ensures a script can receive a challenge while the
// CLI is still running. Unit tests alone cannot prove stderr is drained early.
func TestDeviceLoginSubprocessStreamsChallengeBeforeApproval(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a local CLI subprocess")
	}
	approved := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/test/protocol/openid-connect/auth/device":
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
	build := exec.Command("go", "build", "-o", bin, "../../cmd/rosa-boundary")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v: %s", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, bin, "--keycloak-url", server.URL, "--realm", "test", "--client-id", "cli", "--use-device-code", "login", "--force", "-o", "json")
	process.Env = append(os.Environ(), "XDG_CONFIG_HOME="+filepath.Join(root, "config"), "XDG_CACHE_HOME="+filepath.Join(root, "cache"))
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
	var challenge map[string]any
	for challenge == nil {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatal("CLI exited before challenge")
			}
			if strings.Contains(line, "secret-device-code") {
				t.Fatal("device secret leaked to stderr")
			}
			if strings.HasPrefix(line, authstatus.Prefix) {
				var event map[string]any
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, authstatus.Prefix)), &event); err != nil {
					t.Fatal(err)
				}
				if event["event"] == "device_authorization" {
					challenge = event
				}
			}
		case <-ctx.Done():
			t.Fatalf("challenge was not emitted before approval: %v", ctx.Err())
		}
	}
	if challenge["provider"] != "boundary" || challenge["user_code"] != "CODE-1234" || challenge["verification_uri"] != "https://example.invalid/verify" {
		t.Fatalf("bad challenge metadata: %v", challenge)
	}
	close(approved)
	terminal := 0
	for line := range lines {
		if strings.Contains(line, "secret-device-code") {
			t.Fatal("device secret leaked")
		}
		if strings.HasPrefix(line, authstatus.Prefix) {
			var event map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, authstatus.Prefix)), &event); err != nil {
				t.Fatal(err)
			}
			if event["event"] == "authenticated" && event["source"] == "device" && event["provider"] == "boundary" {
				terminal++
			}
		}
	}
	out, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(fmt.Errorf("CLI exit: %w", err))
	}
	if len(out) != 0 || terminal != 1 {
		t.Fatalf("stdout bytes=%d terminal events=%d", len(out), terminal)
	}
}

package cmd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestForceFreshLogin(t *testing.T) {
	tests := []struct {
		name             string
		globalForceLogin bool
		loginForce       bool
		want             bool
	}{
		{name: "no force flags", want: false},
		{name: "login force flag", loginForce: true, want: true},
		{name: "global force login flag", globalForceLogin: true, want: true},
		{name: "both force flags", globalForceLogin: true, loginForce: true, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := forceFreshLogin(tt.globalForceLogin, tt.loginForce); got != tt.want {
				t.Errorf("forceFreshLogin(%t, %t) = %t, want %t", tt.globalForceLogin, tt.loginForce, got, tt.want)
			}
		})
	}
}

func TestRunLoginDoesNotWriteTokenToStdout(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	viper.Set("keycloak_url", "https://keycloak.example.test/auth")
	t.Cleanup(func() { viper.Set("keycloak_url", nil) })

	token := testJWT(time.Now().Add(time.Hour))
	if err := auth.SaveToken(token); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Use the cache so the test does not start the interactive browser flow.
	loginForce = false
	forceLogin = false

	oldStdout := os.Stdout
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stdout = stdoutWriter

	runErr := runLogin(&cobra.Command{}, nil)
	if err := stdoutWriter.Close(); err != nil {
		t.Errorf("closing captured stdout writer: %v", err)
	}
	os.Stdout = oldStdout

	var stdout bytes.Buffer
	if _, err := io.Copy(&stdout, stdoutReader); err != nil {
		t.Fatalf("reading stdout: %v", err)
	}
	if err := stdoutReader.Close(); err != nil {
		t.Errorf("closing captured stdout reader: %v", err)
	}

	if runErr != nil {
		t.Fatalf("runLogin() error = %v", runErr)
	}
	if stdout.Len() != 0 {
		t.Errorf("runLogin() wrote %d bytes to stdout", stdout.Len())
	}
}

// testJWT creates a minimally valid JWT for exercising the local cache path.
func testJWT(expiration time.Time) string {
	payload := fmt.Sprintf(`{"exp":%d}`, expiration.Unix())
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}

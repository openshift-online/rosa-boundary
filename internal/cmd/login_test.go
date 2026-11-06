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
	"github.com/openshift-online/rosa-boundary/internal/config"
	"github.com/spf13/cobra"
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
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := config.SaveProfile("test", config.Config{AccountID: "123456789012", KeycloakURL: "https://keycloak.example.test/auth", KeycloakRealm: "EmployeeIDP", OIDCClientID: "rosa-boundary-sre"}, true, false); err != nil {
		t.Fatal(err)
	}

	token := testJWT(time.Now().Add(time.Hour))
	if err := auth.SaveTokenForConfig(token, auth.PKCEConfig{KeycloakURL: "https://keycloak.example.test/auth", Realm: "EmployeeIDP", ClientID: "rosa-boundary-sre"}); err != nil {
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

	runErr := runNewLogin(&cobra.Command{})
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

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
)

func TestLoginForceFlagIsCommandScoped(t *testing.T) {
	root := buildRootCommand()
	login := commandAtPath(t, root, "login")
	if force := login.LocalNonPersistentFlags().Lookup("force"); force == nil || force.DefValue != "false" {
		t.Fatalf("login --force flag = %+v", force)
	}
	if root.PersistentFlags().Lookup("force-login") != nil {
		t.Fatal("obsolete global --force-login flag remains available")
	}
	if commandAtPath(t, root, "session", "create").LocalNonPersistentFlags().Lookup("force") != nil {
		t.Fatal("login --force leaked to session create")
	}
}

func TestRunLoginDoesNotWriteTokenToStdout(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := saveTestProfile("test", config.Config{AccountID: "123456789012", KeycloakURL: "https://keycloak.example.test/auth", KeycloakRealm: "EmployeeIDP", OIDCClientID: "rosa-boundary-sre"}, true, false); err != nil {
		t.Fatal(err)
	}

	token := testJWT(time.Now().Add(time.Hour))
	if err := auth.SaveTokenForConfig(token, auth.PKCEConfig{KeycloakURL: "https://keycloak.example.test/auth", Realm: "EmployeeIDP", ClientID: "rosa-boundary-sre"}); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Use the cache so the test does not start the interactive browser flow.

	oldStdout := os.Stdout
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stdout = stdoutWriter

	_, runErr := runTestCLI(t, "login")
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

func TestCachedLoginJSONResultDoesNotExposeToken(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := saveTestProfile("test", config.Config{KeycloakURL: "https://keycloak.example.test/auth"}, true, false); err != nil {
		t.Fatal(err)
	}
	token := testJWT(time.Now().Add(time.Hour))
	if err := auth.SaveTokenForConfig(token, auth.PKCEConfig{KeycloakURL: "https://keycloak.example.test/auth", Realm: "EmployeeIDP", ClientID: "rosa-boundary-sre"}); err != nil {
		t.Fatal(err)
	}
	stdout, err := runTestCLI(t, "login", "-o", "json")
	if err != nil || bytes.Contains([]byte(stdout), []byte(token)) {
		t.Fatalf("login stdout=%q error=%v", stdout, err)
	}
	assertOneJSON(t, stdout, map[string]any{"profile": "test", "authenticated": true})
}

// testJWT creates a minimally valid JWT for exercising the local cache path.
func testJWT(expiration time.Time) string {
	payload := fmt.Sprintf(`{"exp":%d}`, expiration.Unix())
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}

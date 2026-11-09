package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/spf13/cobra"
)

func TestOutputFlagsAreCommandScoped(t *testing.T) {
	root := buildRootCommand()
	for _, path := range [][]string{
		{"login"}, {"config", "init"}, {"session", "create"}, {"investigation", "create"},
		{"session", "join"}, {"session", "close"}, {"session", "list"},
		{"investigation", "list"}, {"investigation", "close"},
		{"session", "credentials", "configure", "ocm"}, {"session", "credentials", "clear", "ocm"},
	} {
		command := commandAtPath(t, root, path...)
		flag := command.LocalNonPersistentFlags().Lookup("output")
		if flag == nil || flag.Shorthand != "o" {
			t.Errorf("%s lacks local -o", command.CommandPath())
		}
	}
	for _, path := range [][]string{{}, {"version"}, {"session", "credentials"}, {"config", "list-profiles"}, {"config", "use-profile"}, {"config", "get"}} {
		command := commandAtPath(t, root, path...)
		if command.LocalNonPersistentFlags().Lookup("output") != nil {
			t.Errorf("offline/group command %s advertises -o", command.CommandPath())
		}
	}
	for _, path := range [][]string{{"login"}, {"config", "init"}, {"session", "join"}, {"session", "credentials", "configure", "ocm"}} {
		command := commandAtPath(t, root, path...)
		if !strings.Contains(command.Flags().Lookup("output").Usage, "authentication guidance goes to stderr") {
			t.Errorf("%s lacks authentication guidance help", command.CommandPath())
		}
	}
}

func commandAtPath(t *testing.T, root *cobra.Command, path ...string) *cobra.Command {
	t.Helper()
	command := root
	for _, name := range path {
		var found *cobra.Command
		for _, child := range command.Commands() {
			if child.Name() == name {
				found = child
				break
			}
		}
		if found == nil {
			t.Fatalf("missing command %s under %s", name, command.CommandPath())
		}
		command = found
	}
	return command
}

func TestConfigureDeviceBootstrapRequiresExplicitTrue(t *testing.T) {
	parent := &cobra.Command{Use: "root"}
	parent.PersistentFlags().Bool("use-device-code", false, "")
	child := &cobra.Command{Use: "init"}
	parent.AddCommand(child)
	t.Setenv("ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE", "true")
	if configureDeviceCode(child) {
		t.Fatal("env selected config init bootstrap")
	}
	for _, tc := range []struct {
		arg  string
		want bool
	}{{"true", true}, {"false", false}} {
		if err := parent.PersistentFlags().Set("use-device-code", tc.arg); err != nil {
			t.Fatal(err)
		}
		if got := configureDeviceCode(child); got != tc.want {
			t.Errorf("flag %s: %t", tc.arg, got)
		}
	}
}

func TestInvalidOutputBeforeAuth(t *testing.T) {
	cmd := &cobra.Command{Use: "login"}
	addOutputFlag(cmd)
	if err := cmd.Flags().Set("output", "xml"); err != nil {
		t.Fatal(err)
	}
	if _, err := commandOutput(cmd); err == nil || !strings.Contains(err.Error(), "invalid --output") {
		t.Fatalf("error = %v", err)
	}
}

func TestOutputAfterPositionalArgument(t *testing.T) {
	for _, args := range [][]string{{"-o", "json", "task-1"}, {"task-1", "--output", "json"}} {
		command := &cobra.Command{Use: "join-task <task-id>"}
		addOutputFlag(command)
		if err := command.ParseFlags(args); err != nil {
			t.Fatal(err)
		}
		value, err := commandOutput(command)
		if err != nil || value != "json" || len(command.Flags().Args()) != 1 || command.Flags().Args()[0] != "task-1" {
			t.Fatalf("args %v: output %q, positionals %v, error %v", args, value, command.Flags().Args(), err)
		}
	}
}

func TestJSONJoinRequiresTerminalBeforeAuthentication(t *testing.T) {
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		_ = tty.Close()
		t.Skip("test process has a controlling terminal")
	}
	if _, err := runTestCLI(t, "session", "join", "task-1", "-o", "json"); err == nil || !strings.Contains(err.Error(), "controlling terminal") {
		t.Fatalf("preflight = %v", err)
	}
}

func TestJoinRejectsInvalidOutputBeforeAuth(t *testing.T) {
	if _, err := runTestCLI(t, "session", "join", "task-1", "-o", "xml"); err == nil || !strings.Contains(err.Error(), "invalid --output") {
		t.Fatalf("join error = %v", err)
	}
}

func TestSTSCacheRejectionRetriesWithDeviceFlow(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	fresh := testJWT(time.Now().Add(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/test/protocol/openid-connect/auth/device":
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "secret-device-code", "user_code": "ABCD-1234", "verification_uri": "https://example.test/device", "expires_in": 10, "interval": 1})
		case "/realms/test/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": fresh})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	pkce := auth.PKCEConfig{KeycloakURL: server.URL, Realm: "test", ClientID: "boundary"}
	if err := auth.SaveTokenForConfig(testJWT(time.Now().Add(time.Hour)), pkce); err != nil {
		t.Fatal(err)
	}
	old := assumeWebIdentity
	t.Cleanup(func() { assumeWebIdentity = old })
	tries := 0
	assumeWebIdentity = func(_ context.Context, _, _, _, _ string) (*awsclient.TemporaryCredentials, error) {
		tries++
		if tries == 1 {
			return nil, fmt.Errorf("ExpiredToken")
		}
		return &awsclient.TemporaryCredentials{AccessKeyID: "key", SecretAccessKey: "secret", SessionToken: "session"}, nil
	}
	// A cached token may be rejected by STS: the selected device flow must
	// show a fresh challenge rather than silently falling back to a browser.
	read, write, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatal(pipeErr)
	}
	oldStderr := os.Stderr
	os.Stderr = write
	t.Cleanup(func() { os.Stderr = oldStderr; _ = read.Close(); _ = write.Close() })
	_, _, err := assumeRoleWithRetryOptions(context.Background(), pkce, "us-east-1", "role", "session", false, auth.Options{UseDeviceCode: true})
	_ = write.Close()
	events, readErr := io.ReadAll(read)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if tries != 2 {
		t.Fatalf("STS attempts %d", tries)
	}
	if !bytes.Contains(events, []byte("ABCD-1234")) || !bytes.Contains(events, []byte("https://example.test/device")) || bytes.Contains(events, []byte("ROSA_BOUNDARY_AUTH_EVENT")) || bytes.Contains(events, []byte("secret-device-code")) || bytes.Contains(events, []byte(fresh)) {
		t.Fatalf("missing approval guidance or secret/event leaked: %s", events)
	}
}

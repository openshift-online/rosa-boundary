package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	"github.com/openshift-online/rosa-boundary/internal/authstatus"
	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/spf13/cobra"
)

func TestOutputFlagsAreCommandScoped(t *testing.T) {
	for _, command := range []*cobra.Command{loginCmd, configureCmd, startTaskCmd, createInvestigationCmd, joinTaskCmd, stopTaskCmd, listTasksCmd, listInvestigationsCmd, closeInvestigationCmd, credentialsConfigureOCMCmd, credentialsClearOCMCmd} {
		flag := command.LocalNonPersistentFlags().Lookup("output")
		if flag == nil || flag.Shorthand != "o" {
			t.Errorf("%s lacks local -o", command.CommandPath())
		}
	}
	for _, command := range []*cobra.Command{rootCmd, versionCmd, credentialsCmd} {
		if command.LocalNonPersistentFlags().Lookup("output") != nil {
			t.Errorf("offline/group command %s advertises -o", command.CommandPath())
		}
	}
	for _, command := range []*cobra.Command{loginCmd, configureCmd, joinTaskCmd, credentialsConfigureOCMCmd} {
		if !strings.Contains(command.Flags().Lookup("output").Usage, "auth events on stderr") {
			t.Errorf("%s lacks event help", command.CommandPath())
		}
	}
}

func TestConfigureDeviceBootstrapRequiresExplicitTrue(t *testing.T) {
	parent := &cobra.Command{Use: "root"}
	parent.PersistentFlags().Bool("use-device-code", false, "")
	child := &cobra.Command{Use: "configure"}
	parent.AddCommand(child)
	t.Setenv("ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE", "true")
	if configureDeviceCode(child) {
		t.Fatal("env selected configure bootstrap")
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
	addOutputFlag(cmd, false)
	if err := cmd.Flags().Set("output", "xml"); err != nil {
		t.Fatal(err)
	}
	if _, err := authReporter(cmd); err == nil || !strings.Contains(err.Error(), "invalid --output") {
		t.Fatalf("error = %v", err)
	}
}

func TestOutputAfterPositionalArgument(t *testing.T) {
	for _, args := range [][]string{{"-o", "json", "task-1"}, {"task-1", "--output", "json"}} {
		command := &cobra.Command{Use: "join-task <task-id>"}
		addOutputFlag(command, false)
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
	command := &cobra.Command{Use: "join-task"}
	addOutputFlag(command, false)
	if err := command.Flags().Set("output", "json"); err != nil {
		t.Fatal(err)
	}
	if err := requireInteractiveTerminal(command); err == nil || !strings.Contains(err.Error(), "controlling terminal") {
		t.Fatalf("preflight = %v", err)
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
	var events bytes.Buffer
	_, _, err := assumeRoleWithRetryOptions(context.Background(), pkce, "us-east-1", "role", "session", false, auth.Options{UseDeviceCode: true, Reporter: &authstatus.Reporter{Format: "json", Writer: &events}})
	if err != nil {
		t.Fatal(err)
	}
	if tries != 2 {
		t.Fatalf("STS attempts %d", tries)
	}
	lines := strings.Split(strings.TrimSpace(events.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("events = %s", events.String())
	}
	for index, event := range []string{`"source":"cache"`, `"event":"device_authorization"`, `"source":"device"`} {
		if !strings.Contains(lines[index], event) {
			t.Errorf("event %d lacks %s", index, event)
		}
	}
	if strings.Contains(events.String(), "secret-device-code") || strings.Contains(events.String(), fresh) {
		t.Fatal("secret leaked into auth events")
	}
}

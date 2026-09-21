package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/openshift-online/rosa-boundary/internal/config"
	credentials "github.com/openshift-online/rosa-boundary/internal/credentials/ocm"
)

func TestNestedCredentialCommandsUseSRERole(t *testing.T) {
	cfg := &config.Config{SRERoleARN: "arn:aws:iam::123:role/sre", InvokerRoleARN: "arn:aws:iam::123:role/invoker"}
	for _, command := range []*cobra.Command{credentialsConfigureOCMCmd, credentialsClearOCMCmd} {
		role, session, err := authenticationRole(cfg, command)
		if err != nil {
			t.Fatal(err)
		}
		if role != cfg.SRERoleARN || session != "rosa-boundary-session" {
			t.Fatalf("%s selected role %q session %q", command.CommandPath(), role, session)
		}
	}
}

func TestAuthenticationRoleValidation(t *testing.T) {
	// Test that invoker commands require InvokerRoleARN
	t.Run("InvokerRoleRequired", func(t *testing.T) {
		cfg := &config.Config{SRERoleARN: "arn:aws:iam::123:role/sre"}
		invokerCommands := []*cobra.Command{
			{Use: "create-investigation"},
			{Use: "start-task"},
		}
		for _, cmd := range invokerCommands {
			_, _, err := authenticationRole(cfg, cmd)
			if err == nil {
				t.Fatalf("expected error for %s with empty InvokerRoleARN", cmd.Name())
			}
			if !strings.Contains(err.Error(), "invoker role ARN is required") {
				t.Fatalf("unexpected error message: %v", err)
			}
			if !strings.Contains(err.Error(), cmd.Name()) {
				t.Fatalf("error message should include command name: %v", err)
			}
		}
	})

	// Test that SRE role commands require SRERoleARN
	t.Run("SRERoleRequired", func(t *testing.T) {
		cfg := &config.Config{InvokerRoleARN: "arn:aws:iam::123:role/invoker"}
		sreCommands := []*cobra.Command{
			credentialsConfigureOCMCmd,
			credentialsClearOCMCmd,
			{Use: "list-investigations"},
			{Use: "list-tasks"},
			{Use: "join-task"},
		}
		for _, cmd := range sreCommands {
			_, _, err := authenticationRole(cfg, cmd)
			if err == nil {
				t.Fatalf("expected error for %s with empty SRERoleARN", cmd.Name())
			}
			if !strings.Contains(err.Error(), "SRE role ARN is required") {
				t.Fatalf("unexpected error message: %v", err)
			}
			if !strings.Contains(err.Error(), cmd.Name()) {
				t.Fatalf("error message should include command name: %v", err)
			}
		}
	})

	// Test happy path with both roles configured
	t.Run("BothRolesConfigured", func(t *testing.T) {
		cfg := &config.Config{
			SRERoleARN:     "arn:aws:iam::123:role/sre",
			InvokerRoleARN: "arn:aws:iam::123:role/invoker",
		}

		// Test invoker commands
		role, session, err := authenticationRole(cfg, &cobra.Command{Use: "create-investigation"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if role != cfg.InvokerRoleARN || session != "rosa-boundary-invoker" {
			t.Fatalf("create-investigation: got role=%q session=%q", role, session)
		}

		// Test SRE commands
		role, session, err = authenticationRole(cfg, &cobra.Command{Use: "list-investigations"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if role != cfg.SRERoleARN || session != "rosa-boundary-session" {
			t.Fatalf("list-investigations: got role=%q session=%q", role, session)
		}
	})
}

func TestParseOCMFlow(t *testing.T) {
	for _, value := range []string{"auth-code", "device"} {
		if _, err := parseOCMFlow(value); err != nil {
			t.Fatalf("parseOCMFlow(%q): %v", value, err)
		}
	}
	if _, err := parseOCMFlow("refresh"); err == nil {
		t.Fatal("unsupported flow succeeded")
	}
}

func TestValidateStartCredentials(t *testing.T) {
	originalCredentials, originalNoWait, originalURL, originalFlow := startCredentials, startNoWait, startOCMURL, startOCMFlow
	t.Cleanup(func() {
		startCredentials, startNoWait, startOCMURL, startOCMFlow = originalCredentials, originalNoWait, originalURL, originalFlow
	})

	startCredentials = []string{"ocm"}
	startNoWait = false
	startOCMURL = "staging"
	startOCMFlow = "device"
	enabled, environment, flow, err := validateStartCredentials()
	if err != nil || !enabled || environment.URL != credentials.StagingURL || flow != credentials.FlowDevice {
		t.Fatalf("valid start credentials = %t, %#v, %q, %v", enabled, environment, flow, err)
	}

	startNoWait = true
	if _, _, _, err := validateStartCredentials(); err == nil || !strings.Contains(err.Error(), "--no-wait") {
		t.Fatalf("--no-wait combination error = %v", err)
	}
	startNoWait = false
	startCredentials = []string{"vault"}
	if _, _, _, err := validateStartCredentials(); err == nil {
		t.Fatal("unsupported provider succeeded")
	}
	startCredentials = []string{"ocm", "ocm"}
	if _, _, _, err := validateStartCredentials(); err == nil {
		t.Fatal("duplicate provider succeeded")
	}
}

func TestStartCredentialFailureRetainsTaskAndCleanupCommand(t *testing.T) {
	err := startCredentialFailure(
		"INV-1",
		"task-123",
		"boundary",
		"us-east-2",
		credentials.Environment{Name: "staging", URL: credentials.StagingURL},
		credentials.FlowDevice,
		errors.New("configure failed"),
	)
	for _, expected := range []string{"INV-1", "task-123", "still running", "credentials configure ocm --ocm-url staging --auth-flow device task-123", "stop-task task-123"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("error %q does not contain %q", err, expected)
		}
	}
}

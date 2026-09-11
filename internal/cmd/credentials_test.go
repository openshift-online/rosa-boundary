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
	err := startCredentialFailure("INV-1", "task-123", "boundary", "us-east-2", errors.New("configure failed"))
	for _, expected := range []string{"INV-1", "task-123", "still running", "stop-task task-123"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("error %q does not contain %q", err, expected)
		}
	}
}

func TestCredentialHelperUnavailableErrorIsActionable(t *testing.T) {
	err := credentialHelperUnavailableError("task-123", errors.New("marker missing"))
	for _, expected := range []string{
		"credential helper is unavailable",
		"task-123",
		"rebuild and deploy",
		"/usr/local/bin/rosa-boundary-credential-helper",
		"start a new task",
	} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("error %q does not contain %q", err, expected)
		}
	}
}

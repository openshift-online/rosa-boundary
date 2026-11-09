package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/config"
	credentials "github.com/openshift-online/rosa-boundary/internal/credentials/ocm"
)

func TestActiveCommandsSelectInvokerAndSRERoles(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	cfg := config.Config{AccountID: "123456789012", AWSRegion: "us-east-1", KeycloakURL: "https://auth.example.test", ClusterName: "ecs", EFSFilesystemID: "fs-example", SRERoleARN: "arn:aws:iam::123456789012:role/sre", InvokerRoleARN: "arn:aws:iam::123456789012:role/invoker", LambdaFunctionName: "create"}
	if err := saveTestProfile("stage", cfg, true, false); err != nil {
		t.Fatal(err)
	}
	if err := auth.SaveTokenForConfig(testJWT(time.Now().Add(time.Hour)), auth.PKCEConfig{KeycloakURL: cfg.KeycloakURL, Realm: "EmployeeIDP", ClientID: "rosa-boundary-sre"}); err != nil {
		t.Fatal(err)
	}
	previous := assumeWebIdentity
	t.Cleanup(func() { assumeWebIdentity = previous })
	for _, tc := range []struct {
		path    []string
		role    string
		session string
	}{
		{[]string{"investigation", "create"}, cfg.InvokerRoleARN, "rosa-boundary-invoker"},
		{[]string{"session", "create"}, cfg.InvokerRoleARN, "rosa-boundary-invoker"},
		{[]string{"investigation", "list"}, cfg.SRERoleARN, "rosa-boundary-session"},
		{[]string{"session", "list"}, cfg.SRERoleARN, "rosa-boundary-session"},
		{[]string{"session", "close"}, cfg.SRERoleARN, "rosa-boundary-session"},
		{[]string{"session", "credentials", "configure", "ocm"}, cfg.SRERoleARN, "rosa-boundary-session"},
		{[]string{"session", "credentials", "clear", "ocm"}, cfg.SRERoleARN, "rosa-boundary-session"},
	} {
		var role, session string
		assumeWebIdentity = func(_ context.Context, _, arn, _, name string) (*awsclient.TemporaryCredentials, error) {
			role, session = arn, name
			return &awsclient.TemporaryCredentials{}, nil
		}
		selectedProfile = ""
		command := commandAtPath(t, buildRootCommand(), tc.path...)
		command.SetContext(context.Background())
		err := commandPreRun(command, nil)
		if err != nil {
			t.Fatal(err)
		}
		if role != tc.role || session != tc.session {
			t.Fatalf("%s selected role %q session %q", command.CommandPath(), role, session)
		}
		if commandCancel != nil {
			commandCancel()
			commandCancel = nil
		}
	}
}

func TestCommandRoleValidation(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg := config.Config{AccountID: "123456789012", AWSRegion: "us-east-1", KeycloakURL: "https://auth.example.test", ClusterName: "ecs", EFSFilesystemID: "fs-example", LambdaFunctionName: "create", InvokerRoleARN: "arn:aws:iam::123456789012:role/invoker", SRERoleARN: "arn:aws:iam::123456789012:role/sre"}
	for _, tc := range []struct {
		name, missing string
		commands      [][]string
	}{
		{"invoker", "invoker_role_arn", [][]string{{"investigation", "create"}, {"session", "create"}}},
		{"sre", "sre_role_arn", [][]string{{"investigation", "list"}, {"session", "list"}, {"session", "close"}, {"session", "credentials", "configure", "ocm"}, {"session", "credentials", "clear", "ocm"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := cfg
			if tc.name == "invoker" {
				profile.InvokerRoleARN = ""
			} else {
				profile.SRERoleARN = ""
			}
			if err := saveTestProfile("stage", profile, true, tc.name == "sre"); err != nil {
				t.Fatal(err)
			}
			for _, path := range tc.commands {
				selectedProfile = ""
				command := commandAtPath(t, buildRootCommand(), path...)
				command.SetContext(context.Background())
				if err := commandPreRun(command, nil); err == nil || !strings.Contains(err.Error(), tc.missing) {
					t.Fatalf("%s: missing %s: %v", command.CommandPath(), tc.missing, err)
				}
				if commandCancel != nil {
					commandCancel()
					commandCancel = nil
				}
			}
		})
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

	startCredentials = "ocm"
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
	startCredentials = "vault"
	if _, _, _, err := validateStartCredentials(); err == nil {
		t.Fatal("unsupported provider succeeded")
	}
	startCredentials = ""
	if enabled, _, _, err := validateStartCredentials(); err != nil || enabled {
		t.Fatalf("omitted provider = %t, %v", enabled, err)
	}
}

func TestSessionCredentialFailureRetainsSessionAndCleanupCommand(t *testing.T) {
	err := sessionCredentialFailure(
		"INV-1",
		"task-123",
		"boundary",
		"us-east-2",
		credentials.Environment{Name: "staging", URL: credentials.StagingURL},
		credentials.FlowDevice,
		errors.New("configure failed"),
	)
	for _, expected := range []string{"INV-1", "task-123", "still running", "session credentials configure ocm \"task-123\" --ocm-url \"staging\" --auth-flow \"device\"", "session close \"task-123\" --yes"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("error %q does not contain %q", err, expected)
		}
	}
}

package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
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
		path            []string
		role            string
		session         string
		durationSeconds int32
	}{
		{[]string{"investigation", "create"}, cfg.InvokerRoleARN, "rosa-boundary-invoker", 900},
		{[]string{"session", "create"}, cfg.InvokerRoleARN, "rosa-boundary-invoker", 900},
		{[]string{"investigation", "list"}, cfg.SRERoleARN, "rosa-boundary-session", 3600},
		{[]string{"session", "list"}, cfg.SRERoleARN, "rosa-boundary-session", 3600},
		{[]string{"session", "close"}, cfg.SRERoleARN, "rosa-boundary-session", 3600},
		{[]string{"session", "credentials", "configure", "ocm"}, cfg.SRERoleARN, "rosa-boundary-session", 3600},
		{[]string{"session", "credentials", "clear", "ocm"}, cfg.SRERoleARN, "rosa-boundary-session", 3600},
	} {
		var role, session string
		var durationSeconds int32
		assumeWebIdentity = func(_ context.Context, _, arn, _, name string, seconds int32) (*awsclient.TemporaryCredentials, error) {
			role, session, durationSeconds = arn, name, seconds
			return &awsclient.TemporaryCredentials{}, nil
		}
		selectedProfile = ""
		command := commandAtPath(t, buildRootCommand(), tc.path...)
		command.SetContext(context.Background())
		err := commandPreRun(command, nil)
		if err != nil {
			t.Fatal(err)
		}
		if role != tc.role || session != tc.session || durationSeconds != tc.durationSeconds {
			t.Fatalf("%s selected role %q session %q duration %ds; want %q %q %ds", command.CommandPath(), role, session, durationSeconds, tc.role, tc.session, tc.durationSeconds)
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
	if _, _, _, err := validateStartCredentials(false, true); err == nil || !strings.Contains(err.Error(), "--no-wait") {
		t.Fatalf("--no-wait combination error = %v", err)
	}
	startNoWait = false
	startCredentials = "vault"
	if _, _, _, err := validateStartCredentials(); err == nil {
		t.Fatal("unsupported provider succeeded")
	}
	startCredentials = "none"
	if enabled, _, _, err := validateStartCredentials(); err != nil || enabled {
		t.Fatalf("opted-out provider = %t, %v", enabled, err)
	}
}

func TestStartCredentialsDefaultNoWaitAndExplicitOptOut(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	previousCredentials, previousNoWait, previousURL, previousFlow := startCredentials, startNoWait, startOCMURL, startOCMFlow
	t.Cleanup(func() {
		startCredentials, startNoWait, startOCMURL, startOCMFlow = previousCredentials, previousNoWait, previousURL, previousFlow
	})
	cmd := commandAtPath(t, buildRootCommand(), "session", "create")
	startCredentials = cmd.Flags().Lookup("with-credentials").DefValue
	startOCMURL, startOCMFlow = "", ""
	startNoWait = false
	if enabled, environment, _, err := validateStartCredentials(false, false); err != nil || !enabled || environment.Name != "" {
		t.Fatalf("default OCM injection = %t, %#v, %v", enabled, environment, err)
	}
	startNoWait = true
	if enabled, _, _, err := validateStartCredentials(false, false); err != nil || enabled {
		t.Fatalf("implicit --no-wait must skip OCM injection: %t, %v", enabled, err)
	}
	if _, _, _, err := validateStartCredentials(false, true); err == nil || !strings.Contains(err.Error(), "--no-wait") {
		t.Fatalf("explicit --with-credentials ocm must be rejected: %v", err)
	}
	startCredentials = "none"
	if enabled, _, _, err := validateStartCredentials(false, true); err != nil || enabled {
		t.Fatalf("explicit opt out = %t, %v", enabled, err)
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
	for _, expected := range []string{"INV-1", "task-123", "still running", `session credentials configure ocm 'task-123' --region 'us-east-2' --ecs-cluster 'boundary' --ocm-url 'https://api.stage.openshift.com' --auth-flow 'device'`, `session close 'task-123' --yes`} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("error %q does not contain %q", err, expected)
		}
	}
}

func TestSessionCredentialFailureWithoutLocalOCMURL(t *testing.T) {
	previous := selectedProfile
	selectedProfile = "stage-east"
	t.Cleanup(func() { selectedProfile = previous })
	warning := sessionCredentialFailure("INV-1", "task-123", "boundary", "us-east-1", credentials.Environment{}, credentials.FlowDevice, errors.New("local URL unavailable")).Error()
	for _, want := range []string{"without confirmed OCM credentials", `session credentials configure ocm 'task-123' --region 'us-east-1' --ecs-cluster 'boundary' --auth-flow 'device'`, "specify --ocm-url", "session close"} {
		if !strings.Contains(warning, want) {
			t.Errorf("missing %q in %q", want, warning)
		}
	}
	if strings.Contains(warning, `--ocm-url ''`) {
		t.Errorf("retry contains empty URL: %s", warning)
	}
}

func TestFailedStartOCMLoginEmitsRetryWarning(t *testing.T) {
	previous := selectedProfile
	selectedProfile = "stage-east"
	t.Cleanup(func() { selectedProfile = previous })
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() {
		os.Stderr = old
		_ = r.Close()
	}()
	warning := warnStartCredentialFailure("INV-1", "task-123", "boundary", "us-east-1",
		ocmSetup{environment: credentials.Environment{Name: "staging", URL: credentials.StagingURL}, flow: credentials.FlowDevice}, errors.New("OCM login denied"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if _, err := stderr.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	if stderr.String() != "Warning: "+warning+"\n" {
		t.Errorf("warning not displayed on stderr: %q", stderr.String())
	}
	for _, want := range []string{"OCM login denied", `--profile 'stage-east' session credentials configure ocm 'task-123'`, `--ocm-url 'https://api.stage.openshift.com' --auth-flow 'device'`, "session close"} {
		if !strings.Contains(warning, want) {
			t.Errorf("warning missing %q: %s", want, warning)
		}
	}
}

func TestBackplaneLoginFailureWarnsWithRetryAndCleanup(t *testing.T) {
	previous := selectedProfile
	selectedProfile = "stage-east"
	t.Cleanup(func() { selectedProfile = previous })
	err := backplaneLoginFailure("task-123", "2abc", "boundary", "us-east-1", errors.New("denied"))
	for _, want := range []string{"task-123", `"2abc"`, "was not initialized", "denied", "ocm backplane login -- '2abc'", `--profile "stage-east" session close "task-123"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "initialized for") {
		t.Errorf("claims success: %v", err)
	}
}

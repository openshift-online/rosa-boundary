package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openshift-online/rosa-boundary/internal/config"
	"github.com/openshift-online/rosa-boundary/internal/lambda"
)

func runNewTestCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newCLI()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	err := cmd.Execute()
	newSelectedProfile = ""
	return stdout.String(), err
}

func TestNewCLIManualProfiles(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, err := runNewTestCLI(t, "config", "init", "--name", "stage-east", "--auto-discover=false",
		"--account-id", "123456789012", "--region", "us-east-1", "--keycloak-url", "https://auth.example.com",
		"--lambda-function-name", "create", "--invoker-role-arn", "arn:aws:iam::123456789012:role/invoker",
		"--sre-role-arn", "arn:aws:iam::123456789012:role/sre", "--ecs-cluster", "ecs", "--efs-filesystem-id", "fs-example")
	if err != nil {
		t.Fatal(err)
	}
	file, err := config.LoadFile()
	if err != nil {
		t.Fatal(err)
	}
	if file.ActiveProfile != "stage-east" || file.Profiles["stage-east"].OIDCUseDeviceCode == nil || *file.Profiles["stage-east"].OIDCUseDeviceCode {
		t.Fatalf("unexpected saved profile: %+v", file)
	}
	info, err := os.Stat(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "rosa-boundary", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v, want 0600", info.Mode().Perm())
	}
	_, err = runNewTestCLI(t, "config", "init", "--name", "stage-east", "--auto-discover=false")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate init error = %v", err)
	}
	_, err = runNewTestCLI(t, "config", "init", "--name", "prod-west", "--auto-discover=false",
		"--account-id", "210987654321", "--region", "us-west-1", "--keycloak-url", "https://auth.example.com",
		"--lambda-function-name", "create", "--invoker-role-arn", "arn:aws:iam::210987654321:role/invoker",
		"--sre-role-arn", "arn:aws:iam::210987654321:role/sre", "--ecs-cluster", "ecs", "--efs-filesystem-id", "fs-example")
	if err != nil {
		t.Fatal(err)
	}
	list, err := runNewTestCLI(t, "config", "list")
	if err != nil || !strings.Contains(list, "* stage-east") || !strings.Contains(list, "prod-west") {
		t.Fatalf("list = %q, error = %v", list, err)
	}
	if _, err := runNewTestCLI(t, "config", "use", "prod-west"); err != nil {
		t.Fatal(err)
	}
	value, err := runNewTestCLI(t, "--profile", "stage-east", "config", "get", "aws_region")
	if err != nil || value != "us-east-1\n" {
		t.Fatalf("get = %q, error = %v", value, err)
	}
	t.Setenv("ROSA_BOUNDARY_AWS_REGION", "us-west-2")
	value, err = runNewTestCLI(t, "--profile", "stage-east", "config", "get", "aws_region")
	if err != nil || value != "us-east-1\n" {
		t.Fatalf("config get must ignore environment: %q, %v", value, err)
	}
	file, err = config.LoadFile()
	if err != nil || file.ActiveProfile != "prod-west" {
		t.Fatalf("active profile = %+v, error = %v", file, err)
	}
}

func TestNewCLIManualInitReportsMissingSettingsTogether(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, err := runNewTestCLI(t, "config", "init", "--auto-discover=false")
	if err == nil {
		t.Fatal("manual initialization unexpectedly succeeded")
	}
	for _, flag := range []string{"--name", "--account-id", "--region", "--keycloak-url", "--lambda-function-name", "--invoker-role-arn", "--sre-role-arn", "--ecs-cluster", "--efs-filesystem-id"} {
		if !strings.Contains(err.Error(), flag) {
			t.Errorf("missing %s from required-settings error: %v", flag, err)
		}
	}
}

func TestNewCLIManualInitJSONDoesNotEmitStatusOnStdout(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stdout, err := runNewTestCLI(t, "config", "init", "--name", "test", "--account-id", "123456789012", "--region", "us-east-1", "--auto-discover=false", "--keycloak-url", "https://auth.example.com", "--lambda-function-name", "create", "--invoker-role-arn", "arn:aws:iam::123456789012:role/invoker", "--sre-role-arn", "arn:aws:iam::123456789012:role/sre", "--ecs-cluster", "ecs", "--efs-filesystem-id", "fs-example", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "" {
		t.Fatalf("JSON auth event mode wrote status to stdout: %q", stdout)
	}
}

func TestNewCLINoLegacyCommandsAndValidatesBeforeAuth(t *testing.T) {
	root := newCLI()
	for _, legacy := range []string{"start-task", "join-task", "configure", "list-tasks", "stop-task"} {
		for _, child := range root.Commands() {
			if child.Name() == legacy {
				t.Fatalf("legacy command %q is visible", legacy)
			}
		}
	}
	for _, args := range [][]string{{"session", "start"}, {"session", "start", "cluster", "--no-wait", "--connect"}, {"session", "start", "cluster", "--no-wait", "--with-credentials", "ocm"}, {"session", "start", "cluster", "--session-timeout", "-1s"}, {"session", "start", "cluster", "--session-timeout", "24h1s"}, {"session", "start", "cluster", "--with-credentials", "bogus"}, {"session", "list", "--status", "bad"}, {"investigation", "close", "cluster"}} {
		if _, err := runNewTestCLI(t, args...); err == nil {
			t.Errorf("%v should be rejected", args)
		}
	}
	if _, err := runNewTestCLI(t, "session", "stop", "task"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("stop without terminal: %v", err)
	}
	if _, err := runNewTestCLI(t, "investigation", "close", "cluster", "incident"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("close without terminal: %v", err)
	}
	if _, err := runNewTestCLI(t, "investigation", "close", "cluster", "incident", "--dry-run", "--timeout", "-1s"); err == nil || !strings.Contains(err.Error(), "--timeout") {
		t.Fatalf("dry-run should pass terminal validation: %v", err)
	}
}

func TestNewCLIRejectsInvalidConfigWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	path := filepath.Join(dir, "rosa-boundary", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte("aws_region: us-east-1\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runNewTestCLI(t, "config", "list"); err == nil || !strings.Contains(err.Error(), "field aws_region not found") {
		t.Fatalf("invalid config error: %v", err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != string(data) {
		t.Fatalf("invalid config modified: %q, %v", actual, err)
	}
}

func TestNewCLIProfileSafetyAndDeadlines(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, args := range [][]string{{"login", "--timeout", "-1s"}, {"config", "init", "--timeout", "0s"}} {
		_, err := runNewTestCLI(t, args...)
		if err == nil || !strings.Contains(err.Error(), "--timeout") {
			t.Fatalf("%v: expected deadline error, got %v", args, err)
		}
	}
	file := &config.ProfilesFile{ActiveProfile: "wrong", Profiles: map[string]config.Profile{
		"wrong": {AccountID: "123456789012", AWSRegion: "us-east-1", KeycloakURL: "https://auth.example.com", SRERoleARN: "arn:aws:iam::210987654321:role/sre", ClusterName: "ecs"},
	}}
	if err := config.SaveProfiles(file); err != nil {
		t.Fatal(err)
	}
	_, err := runNewTestCLI(t, "session", "list")
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected role/account mismatch before login, got %v", err)
	}
	for _, args := range [][]string{{"config"}, {"investigation"}, {"session"}, {"session", "credentials"}, {"version"}, {"completion", "bash"}} {
		if _, err := runNewTestCLI(t, args...); err != nil {
			t.Errorf("help-only %v: %v", args, err)
		}
	}
}

func TestNewCLIMissingDeploymentSettingsBeforeAuth(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	file := &config.ProfilesFile{ActiveProfile: "incomplete", Profiles: map[string]config.Profile{"incomplete": {KeycloakURL: "https://auth.example.com", SRERoleARN: "arn:aws:iam::123456789012:role/sre", ClusterName: "ecs"}}}
	if err := config.SaveProfiles(file); err != nil {
		t.Fatal(err)
	}
	if _, err := runNewTestCLI(t, "session", "list"); err == nil || !strings.Contains(err.Error(), "account_id") {
		t.Fatalf("missing account_id: %v", err)
	}
	profile := file.Profiles["incomplete"]
	profile.AccountID = "123456789012"
	file.Profiles["incomplete"] = profile
	if err := config.SaveProfiles(file); err != nil {
		t.Fatal(err)
	}
	if _, err := runNewTestCLI(t, "session", "list"); err == nil || !strings.Contains(err.Error(), "aws_region") {
		t.Fatalf("missing region: %v", err)
	}
	if _, err := runNewTestCLI(t, "config", "init", "--name", "bad", "--auto-discover=false", "--account-id", "123456789012", "--region", "us-east-1", "--keycloak-url", "https://auth.example.com", "--lambda-function-name", "create", "--invoker-role-arn", "arn:aws:iam::210987654321:role/invoker", "--sre-role-arn", "arn:aws:iam::123456789012:role/sre", "--ecs-cluster", "ecs", "--efs-filesystem-id", "fs-example"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("cross-account manual init: %v", err)
	}
	file, err := config.LoadFile()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := file.Profiles["bad"]; ok {
		t.Fatal("failed init saved cross-account profile")
	}
}

func TestNewCLIDiscoveryCannotSwitchIssuerOrRegion(t *testing.T) {
	seed := config.Profile{AWSRegion: "us-east-1", KeycloakURL: "https://auth.example.com", KeycloakRealm: "EmployeeIDP", OIDCClientID: "rosa-boundary-sre"}
	for _, response := range []lambda.ConfigResponse{
		{AWSRegion: "us-west-2"}, {KeycloakURL: "https://other.example.com"},
		{KeycloakRealm: "other"}, {OIDCClientID: "other-client"},
	} {
		if err := newCheckDiscoveryIdentity(seed, &response); err == nil {
			t.Errorf("accepted mismatched discovery %+v", response)
		}
	}
	if err := newCheckDiscoveryIdentity(seed, &lambda.ConfigResponse{AWSRegion: seed.AWSRegion, KeycloakURL: seed.KeycloakURL, KeycloakRealm: seed.KeycloakRealm, OIDCClientID: seed.OIDCClientID}); err != nil {
		t.Fatal(err)
	}
}

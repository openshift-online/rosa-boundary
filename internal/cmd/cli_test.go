package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/openshift-online/rosa-boundary/internal/config"
	"github.com/openshift-online/rosa-boundary/internal/lambda"
)

func runTestCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	selectedProfile = ""
	cmd := buildRootCommand()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	err := cmd.Execute()
	if commandCancel != nil {
		commandCancel()
		commandCancel = nil
	}
	selectedProfile = ""
	return stdout.String(), err
}

func saveTestProfile(name string, cfg config.Config, use, overwrite bool) error {
	f, err := config.LoadProfiles()
	if err != nil {
		return err
	}
	device := cfg.OIDCUseDeviceCode
	p := config.Profile{AccountID: cfg.AccountID, Environment: cfg.Environment, Project: cfg.Project,
		AWSRegion: cfg.AWSRegion, KeycloakURL: cfg.KeycloakURL, KeycloakRealm: cfg.KeycloakRealm,
		OIDCClientID: cfg.OIDCClientID, OIDCUseDeviceCode: &device,
		LambdaFunctionName: cfg.LambdaFunctionName, InvokerRoleARN: cfg.InvokerRoleARN,
		SRERoleARN: cfg.SRERoleARN, ClusterName: cfg.ClusterName, EFSFilesystemID: cfg.EFSFilesystemID}
	if err := f.AddProfile(name, p, overwrite, use); err != nil {
		return err
	}
	return config.SaveProfiles(f)
}

func TestCLIManualProfiles(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, err := runTestCLI(t, "config", "init", "--name", "stage-east", "--auto-discover=false",
		"--account-id", "123456789012", "--region", "us-east-1", "--keycloak-url", "https://auth.example.com",
		"--lambda-function-name", "create", "--invoker-role-arn", "arn:aws:iam::123456789012:role/invoker",
		"--sre-role-arn", "arn:aws:iam::123456789012:role/sre", "--ecs-cluster", "ecs", "--efs-filesystem-id", "fs-example")
	if err != nil {
		t.Fatal(err)
	}
	file, err := config.LoadProfiles()
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
	_, err = runTestCLI(t, "config", "init", "--name", "stage-east", "--auto-discover=false")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate init error = %v", err)
	}
	_, err = runTestCLI(t, "config", "init", "--name", "prod-west", "--auto-discover=false",
		"--account-id", "210987654321", "--region", "us-west-1", "--keycloak-url", "https://auth.example.com",
		"--lambda-function-name", "create", "--invoker-role-arn", "arn:aws:iam::210987654321:role/invoker",
		"--sre-role-arn", "arn:aws:iam::210987654321:role/sre", "--ecs-cluster", "ecs", "--efs-filesystem-id", "fs-example")
	if err != nil {
		t.Fatal(err)
	}
	list, err := runTestCLI(t, "config", "list-profiles")
	if err != nil || !strings.Contains(list, "*       stage-east") || !strings.Contains(list, "prod-west") {
		t.Fatalf("list = %q, error = %v", list, err)
	}
	confirmation, err := runTestCLI(t, "config", "use-profile", "prod-west")
	if err != nil || confirmation != "Active profile: prod-west\nAWS account ID: 210987654321\nAWS region: us-west-1\n" {
		t.Fatalf("use-profile = %q, error = %v", confirmation, err)
	}
	value, err := runTestCLI(t, "--profile", "stage-east", "config", "get", "aws_region")
	if err != nil || value != "us-east-1\n" {
		t.Fatalf("get = %q, error = %v", value, err)
	}
	t.Setenv("ROSA_BOUNDARY_AWS_REGION", "us-west-2")
	value, err = runTestCLI(t, "--profile", "stage-east", "config", "get", "aws_region")
	if err != nil || value != "us-east-1\n" {
		t.Fatalf("config get must ignore environment: %q, %v", value, err)
	}
	file, err = config.LoadProfiles()
	if err != nil || file.ActiveProfile != "prod-west" {
		t.Fatalf("active profile = %+v, error = %v", file, err)
	}
}

func TestCLIManualInitReportsMissingSettingsTogether(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, err := runTestCLI(t, "config", "init", "--auto-discover=false")
	if err == nil {
		t.Fatal("manual initialization unexpectedly succeeded")
	}
	for _, flag := range []string{"--name", "--account-id", "--region", "--keycloak-url", "--lambda-function-name", "--invoker-role-arn", "--sre-role-arn", "--ecs-cluster", "--efs-filesystem-id"} {
		if !strings.Contains(err.Error(), flag) {
			t.Errorf("missing %s from required-settings error: %v", flag, err)
		}
	}
}

func TestCLIManualInitJSONSeparatesStdoutAndStderr(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stderr, err := os.CreateTemp(t.TempDir(), "stderr-")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	previousStderr := os.Stderr
	os.Stderr = stderr
	defer func() { os.Stderr = previousStderr }()
	stdout, err := runTestCLI(t, "config", "init", "--name", "test", "--account-id", "123456789012", "--region", "us-east-1", "--auto-discover=false", "--keycloak-url", "https://auth.example.com", "--lambda-function-name", "create", "--invoker-role-arn", "arn:aws:iam::123456789012:role/invoker", "--sre-role-arn", "arn:aws:iam::123456789012:role/sre", "--ecs-cluster", "ecs", "--efs-filesystem-id", "fs-example", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	assertOneJSON(t, stdout, map[string]any{"profile": "test", "active": true, "discovered": false})
	if _, err := stderr.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	diagnostics, err := io.ReadAll(stderr)
	if err != nil || !strings.Contains(string(diagnostics), "Saved profile test") || strings.Contains(string(diagnostics), "ROSA_BOUNDARY_AUTH_EVENT") {
		t.Fatalf("stderr=%q error=%v", diagnostics, err)
	}
}

func assertOneJSON(t *testing.T, stdout string, want map[string]any) {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(stdout))
	var got map[string]any
	if err := decoder.Decode(&got); err != nil {
		t.Fatalf("stdout is not JSON: %q: %v", stdout, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("stdout has more than one JSON object: %q: %v", stdout, err)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %v, want %v (stdout=%q)", key, got[key], value, stdout)
		}
	}
}

func TestCLINoLegacyCommandsAndValidatesBeforeAuth(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	previousTerminal := requireTerminal
	requireTerminal = func() error { return errors.New("no terminal") }
	t.Cleanup(func() { requireTerminal = previousTerminal })
	root := buildRootCommand()
	// Check every public level: old task commands must not be reachable beneath
	// a supported group, and no unexpected leaf can silently enter the contract.
	assertCommandTree(t, root, map[string]any{
		"config":        map[string]any{"init": nil, "list-profiles": nil, "use-profile": nil, "get": nil},
		"investigation": map[string]any{"create": nil, "list": nil, "close": nil},
		"session": map[string]any{
			"create": nil, "list": nil, "join": nil, "close": nil,
			"credentials": map[string]any{
				"configure": map[string]any{"ocm": nil},
				"clear":     map[string]any{"ocm": nil},
			},
		},
		"login": nil, "version": nil,
	})
	for _, args := range [][]string{{"session", "create"}, {"session", "create", "cluster", "--no-wait", "--connect"}, {"session", "create", "cluster", "--no-wait", "--with-credentials", "ocm"}, {"session", "create", "cluster", "--session-timeout", "-1s"}, {"session", "create", "cluster", "--session-timeout", "24h1s"}, {"session", "create", "cluster", "--with-credentials", "bogus"}, {"session", "list", "--status", "bad"}, {"investigation", "close", "cluster"}} {
		if _, err := runTestCLI(t, args...); err == nil {
			t.Errorf("%v should be rejected", args)
		}
	}
	if _, err := runTestCLI(t, "session", "close", "task"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("stop without terminal: %v", err)
	}
	if _, err := runTestCLI(t, "investigation", "close", "cluster", "incident"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("close without terminal: %v", err)
	}
	if _, err := runTestCLI(t, "investigation", "close", "cluster", "incident", "--dry-run", "--timeout", "-1s"); err == nil || !strings.Contains(err.Error(), "--timeout") {
		t.Fatalf("dry-run should pass terminal validation: %v", err)
	}
}

func TestSessionOldVerbsRejectedWithMigrationGuidance(t *testing.T) {
	for _, tc := range []struct{ old, replacement string }{
		{"start", "create"},
		{"stop", "close"},
	} {
		_, err := runTestCLI(t, "session", tc.old, "task")
		if err == nil || !strings.Contains(err.Error(), "no longer supported") || !strings.Contains(err.Error(), "session "+tc.replacement) {
			t.Errorf("session %s: expected rejection with %s guidance, got %v", tc.old, tc.replacement, err)
		}
	}
}

func TestSessionLifecycleHelpKeepsFlagsAndSeparation(t *testing.T) {
	for _, tc := range []struct {
		verb string
		want []string
	}{
		{"create", []string{"create <cluster-id>", "--investigation-id", "--session-timeout", "--connect", "--no-wait", "--with-credentials", "--ocm-url", "--ocm-auth-flow"}},
		{"close", []string{"close <session-id>", "without closing its investigation", "--reason", "--wait", "--yes"}},
	} {
		stdout, err := runTestCLI(t, "session", tc.verb, "--help")
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range tc.want {
			if !strings.Contains(stdout, want) {
				t.Errorf("session %s --help missing %q: %s", tc.verb, want, stdout)
			}
		}
	}
}

func TestSessionParentHelpExamplesAndBooleanFlags(t *testing.T) {
	stdout, err := runTestCLI(t, "session", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"new, auto-generated investigation ID",
		"existing investigation",
		"fresh OCM credentials in an existing session",
		"new investigation and OCM credentials",
		"separate human approvals",
		"cannot be combined with --no-wait",
		"--use-device-code",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("session --help missing %q: %s", want, stdout)
		}
	}
	examples := []string{
		"rosa-boundary session create <cluster-id>",
		"rosa-boundary session create <cluster-id> --investigation-id <investigation-id>",
		"rosa-boundary session credentials configure ocm <session-id>",
		"rosa-boundary session create <cluster-id> --with-credentials ocm",
	}
	for _, example := range examples {
		if !strings.Contains(stdout, "  "+example+"\n") {
			t.Errorf("session --help missing example %q: %s", example, stdout)
		}
	}
	if got := strings.Count(stdout, "  rosa-boundary session create <cluster-id>") + strings.Count(stdout, "  rosa-boundary session credentials configure ocm <session-id>"); got != len(examples) {
		t.Errorf("session --help contains %d examples, want %d: %s", got, len(examples), stdout)
	}
	if strings.Contains(stdout, "--ocm-url") || strings.Contains(stdout, "[=true|false]") {
		t.Errorf("session --help shows an environment or boolean syntax in examples/help: %s", stdout)
	}

	// Explicit false is still accepted by the parser despite the bare help form.
	stdout, err = runTestCLI(t, "--use-device-code=false", "session", "--help")
	if err != nil || !strings.Contains(stdout, "--use-device-code") {
		t.Errorf("explicit false help: %v, %q", err, stdout)
	}
	for _, args := range [][]string{{"--help"}, {"session", "create", "--help"}, {"login", "--help"}} {
		stdout, err := runTestCLI(t, args...)
		if err != nil || !strings.Contains(stdout, "--use-device-code") || strings.Contains(stdout, "[=true|false]") {
			t.Errorf("%v: boolean help = %q, error = %v", args, stdout, err)
		}
	}
}

func assertCommandTree(t *testing.T, parent interface {
	Commands() []*cobra.Command
	CommandPath() string
}, expected map[string]any) {
	t.Helper()
	for _, child := range parent.Commands() {
		// Cobra's generated help and completion are not part of the public contract.
		if child.Name() == "help" || child.Name() == "completion" {
			continue
		}
		nested, ok := expected[child.Name()]
		if !ok {
			t.Errorf("unexpected command %s", child.CommandPath())
			continue
		}
		delete(expected, child.Name())
		if nested == nil {
			assertCommandTree(t, child, map[string]any{})
		} else {
			assertCommandTree(t, child, nested.(map[string]any))
		}
	}
	for name := range expected {
		t.Errorf("%s missing command %s", parent.CommandPath(), name)
	}
}

func TestStartSessionJSONResultContract(t *testing.T) {
	previous := selectedProfile
	t.Cleanup(func() { selectedProfile = previous })
	selectedProfile = "stage-east"
	for _, withOCM := range []bool{false, true} {
		result := startSessionResult("cluster", "investigation", "abc123", "boundary-ecs", "arn:aws:ecs:us-east-1:123456789012:task/boundary-ecs/abc123", "4.20", 3600, "fsap-123", "arn:aws:iam::123456789012:role/sre", withOCM)
		data, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		wantFields := map[string]any{"profile": "stage-east", "session_id": "abc123", "ecs_cluster": "boundary-ecs", "cluster_id": "cluster", "investigation_id": "investigation", "task_id": "abc123", "task_arn": "arn:aws:ecs:us-east-1:123456789012:task/boundary-ecs/abc123", "oc_version": "4.20", "session_timeout": float64(3600), "task_timeout": float64(3600), "access_point_id": "fsap-123", "role_arn": "arn:aws:iam::123456789012:role/sre"}
		if withOCM {
			wantFields["credentials"] = []any{"ocm"}
		}
		if len(decoded) != len(wantFields) {
			t.Errorf("JSON keys = %v, want exactly %v", decoded, wantFields)
		}
		for key, want := range wantFields {
			if key == "credentials" {
				if got, ok := decoded[key].([]any); !ok || len(got) != 1 || got[0] != "ocm" {
					t.Errorf("credentials = %v, want [ocm]", decoded[key])
				}
				continue
			}
			if got := decoded[key]; got != want {
				t.Errorf("%s = %v, want %v", key, got, want)
			}
		}
	}
}

func TestCLIRejectsInvalidConfigWithoutOverwrite(t *testing.T) {
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
	for _, args := range [][]string{{"config", "list-profiles"}, {"config", "init", "--auto-discover=false"}, {"login"}, {"session", "list"}} {
		_, err := runTestCLI(t, args...)
		if err == nil {
			t.Fatalf("%v accepted invalid config", args)
		}
		for _, want := range []string{"could not read Boundary configuration file", path, "old flat config", "back it up or move it aside", "rosa-boundary config init", "Details:", "field aws_region not found"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%v error %q missing %q", args, err, want)
			}
		}
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != string(data) {
		t.Fatalf("invalid config modified: %q, %v", actual, err)
	}
}

func TestCLIUserErrorsSuggestRecoveryBeforeAuth(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"session", "list"}, []string{"no active profile", "config list-profiles", "config use-profile", "config init"}},
		{[]string{"--profile", "missing", "session", "list"}, []string{"unknown profile", "config list-profiles", "config use-profile"}},
		{[]string{"session", "create", "cluster", "--with-credentials", "bad"}, []string{"unsupported credential provider", "--with-credentials ocm"}},
		{[]string{"session", "credentials", "configure", "ocm", "task", "--auth-flow", "bad"}, []string{"invalid --auth-flow", "auth-code or device"}},
	} {
		_, err := runTestCLI(t, tc.args...)
		if err == nil {
			t.Fatalf("%v unexpectedly succeeded", tc.args)
		}
		for _, want := range tc.want {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%v: error %q missing %q", tc.args, err, want)
			}
		}
	}
}

func TestCLIProfileSafetyAndDeadlines(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, args := range [][]string{{"login", "--timeout", "-1s"}, {"config", "init", "--timeout", "0s"}} {
		_, err := runTestCLI(t, args...)
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
	_, err := runTestCLI(t, "session", "list")
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected role/account mismatch before login, got %v", err)
	}
	for _, args := range [][]string{{"config"}, {"investigation"}, {"session"}, {"session", "credentials"}, {"version"}, {"completion", "bash"}} {
		if _, err := runTestCLI(t, args...); err != nil {
			t.Errorf("help-only %v: %v", args, err)
		}
	}
}

func TestCLIMissingDeploymentSettingsBeforeAuth(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	file := &config.ProfilesFile{ActiveProfile: "incomplete", Profiles: map[string]config.Profile{"incomplete": {KeycloakURL: "https://auth.example.com", SRERoleARN: "arn:aws:iam::123456789012:role/sre", ClusterName: "ecs"}}}
	if err := config.SaveProfiles(file); err != nil {
		t.Fatal(err)
	}
	if _, err := runTestCLI(t, "session", "list"); err == nil || !strings.Contains(err.Error(), "account_id") {
		t.Fatalf("missing account_id: %v", err)
	}
	profile := file.Profiles["incomplete"]
	profile.AccountID = "123456789012"
	file.Profiles["incomplete"] = profile
	if err := config.SaveProfiles(file); err != nil {
		t.Fatal(err)
	}
	if _, err := runTestCLI(t, "session", "list"); err == nil || !strings.Contains(err.Error(), "aws_region") {
		t.Fatalf("missing region: %v", err)
	}
	if _, err := runTestCLI(t, "config", "init", "--name", "bad", "--auto-discover=false", "--account-id", "123456789012", "--region", "us-east-1", "--keycloak-url", "https://auth.example.com", "--lambda-function-name", "create", "--invoker-role-arn", "arn:aws:iam::210987654321:role/invoker", "--sre-role-arn", "arn:aws:iam::123456789012:role/sre", "--ecs-cluster", "ecs", "--efs-filesystem-id", "fs-example"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("cross-account manual init: %v", err)
	}
	file, err := config.LoadProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := file.Profiles["bad"]; ok {
		t.Fatal("failed init saved cross-account profile")
	}
}

func TestCLIDiscoveryCannotSwitchIssuerOrRegion(t *testing.T) {
	seed := config.Profile{AWSRegion: "us-east-1", KeycloakURL: "https://auth.example.com", KeycloakRealm: "EmployeeIDP", OIDCClientID: "rosa-boundary-sre"}
	for _, response := range []lambda.ConfigResponse{
		{AWSRegion: "us-west-2"}, {KeycloakURL: "https://other.example.com"},
		{KeycloakRealm: "other"}, {OIDCClientID: "other-client"},
	} {
		if err := checkDiscoveryIdentity(seed, &response); err == nil {
			t.Errorf("accepted mismatched discovery %+v", response)
		}
	}
	if err := checkDiscoveryIdentity(seed, &lambda.ConfigResponse{AWSRegion: seed.AWSRegion, KeycloakURL: seed.KeycloakURL, KeycloakRealm: seed.KeycloakRealm, OIDCClientID: seed.OIDCClientID}); err != nil {
		t.Fatal(err)
	}
}

package aws

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSessionManagerPluginEnvUsesAssumedCredentials(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
	t.Setenv("AWS_SESSION_TOKEN", "ambient-token")
	t.Setenv("AWS_SECURITY_TOKEN", "legacy-ambient-token")
	t.Setenv("AWS_PROFILE", "ambient-profile")
	t.Setenv("AWS_DEFAULT_PROFILE", "ambient-default-profile")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/tmp/credentials")
	t.Setenv("AWS_CONFIG_FILE", "/tmp/config")
	t.Setenv("ROSA_BOUNDARY_TEST_PRESERVE", "preserved-value")

	env, err := sessionManagerPluginEnv(&TemporaryCredentials{
		AccessKeyID:     "assumed-access-key",
		SecretAccessKey: "assumed-secret",
		SessionToken:    "assumed-token",
	})
	if err != nil {
		t.Fatalf("sessionManagerPluginEnv returned an error: %v", err)
	}

	gotEnv := environmentMap(t, env)

	for key, want := range map[string]string{
		"AWS_ACCESS_KEY_ID":           "assumed-access-key",
		"AWS_SECRET_ACCESS_KEY":       "assumed-secret",
		"AWS_SESSION_TOKEN":           "assumed-token",
		"ROSA_BOUNDARY_TEST_PRESERVE": "preserved-value",
	} {
		if got := gotEnv[key]; got != want {
			t.Errorf("environment %s = %q, want %q", key, got, want)
		}
	}
	for _, key := range []string{
		"AWS_SECURITY_TOKEN",
		"AWS_PROFILE",
		"AWS_DEFAULT_PROFILE",
		"AWS_SHARED_CREDENTIALS_FILE",
		"AWS_CONFIG_FILE",
	} {
		if _, exists := gotEnv[key]; exists {
			t.Errorf("environment retains credential source %q", key)
		}
	}
}

func TestSessionManagerPluginEnvRejectsMissingCredentials(t *testing.T) {
	tests := []struct {
		name  string
		creds *TemporaryCredentials
	}{
		{name: "nil"},
		{name: "access key", creds: &TemporaryCredentials{SecretAccessKey: "secret", SessionToken: "token"}},
		{name: "secret access key", creds: &TemporaryCredentials{AccessKeyID: "key", SessionToken: "token"}},
		{name: "session token", creds: &TemporaryCredentials{AccessKeyID: "key", SecretAccessKey: "secret"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := sessionManagerPluginEnv(tt.creds); err == nil {
				t.Error("sessionManagerPluginEnv accepted incomplete credentials")
			}
		})
	}
}

func TestRunSessionManagerPluginUsesAssumedCredentials(t *testing.T) {
	pluginDir := t.TempDir()
	outputPath := filepath.Join(pluginDir, "plugin-output")
	writePlugin(t, pluginDir, "printf '%s\\n' \"$@\" > \"$ROSA_BOUNDARY_TEST_OUTPUT\"\nprintf '%s\\n' --ENV-- >> \"$ROSA_BOUNDARY_TEST_OUTPUT\"\nenv | sort >> \"$ROSA_BOUNDARY_TEST_OUTPUT\"")
	t.Setenv("PATH", pluginDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ROSA_BOUNDARY_TEST_OUTPUT", outputPath)
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-access-key")
	t.Setenv("AWS_PROFILE", "ambient-profile")

	err := RunSessionManagerPlugin(context.Background(), "us-east-1", &ExecuteCommandSession{
		RawSession: []byte(`{"sessionId":"session-id"}`),
		Target:     "ecs:cluster_task_runtime",
	}, &TemporaryCredentials{
		AccessKeyID:     "assumed-access-key",
		SecretAccessKey: "assumed-secret",
		SessionToken:    "assumed-token",
	})
	if err != nil {
		t.Fatalf("RunSessionManagerPlugin returned an error: %v", err)
	}

	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read plugin output: %v", err)
	}
	outputParts := strings.SplitN(string(output), "--ENV--\n", 2)
	if len(outputParts) != 2 {
		t.Fatalf("plugin output has no environment separator: %s", output)
	}
	gotEnv := environmentMap(t, strings.Split(outputParts[1], "\n"))
	for key, want := range map[string]string{
		"AWS_ACCESS_KEY_ID":     "assumed-access-key",
		"AWS_SECRET_ACCESS_KEY": "assumed-secret",
		"AWS_SESSION_TOKEN":     "assumed-token",
	} {
		if got := gotEnv[key]; got != want {
			t.Errorf("plugin environment %s = %q, want %q", key, got, want)
		}
	}
	if _, exists := gotEnv["AWS_PROFILE"]; exists {
		t.Error("plugin environment retains AWS_PROFILE")
	}
	if !strings.Contains(outputParts[0], `{"Target":"ecs:cluster_task_runtime"}`) {
		t.Errorf("plugin arguments do not contain the ECS Exec target: %s", output)
	}
}

func TestStartSessionManagerPluginUsesAssumedCredentials(t *testing.T) {
	pluginDir := t.TempDir()
	writePlugin(t, pluginDir, "exit 0")
	t.Setenv("PATH", pluginDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-access-key")
	t.Setenv("AWS_PROFILE", "ambient-profile")

	originalExec := execSessionManagerPlugin
	var gotArgs, gotEnv []string
	execSessionManagerPlugin = func(_ string, args, env []string) error {
		gotArgs = args
		gotEnv = env
		return nil
	}
	t.Cleanup(func() { execSessionManagerPlugin = originalExec })

	if err := StartSessionManagerPlugin("us-east-1", &ExecuteCommandSession{
		RawSession: []byte(`{"sessionId":"session-id"}`),
		Target:     "ecs:cluster_task_runtime",
	}, &TemporaryCredentials{
		AccessKeyID:     "assumed-access-key",
		SecretAccessKey: "assumed-secret",
		SessionToken:    "assumed-token",
	}); err != nil {
		t.Fatalf("StartSessionManagerPlugin returned an error: %v", err)
	}

	gotEnvironment := environmentMap(t, gotEnv)
	if got := gotEnvironment["AWS_ACCESS_KEY_ID"]; got != "assumed-access-key" {
		t.Errorf("plugin environment AWS_ACCESS_KEY_ID = %q, want assumed credentials", got)
	}
	if _, exists := gotEnvironment["AWS_PROFILE"]; exists {
		t.Error("plugin environment retains AWS_PROFILE")
	}
	if !strings.Contains(strings.Join(gotArgs, "\n"), `{"Target":"ecs:cluster_task_runtime"}`) {
		t.Errorf("plugin arguments do not contain the ECS Exec target: %v", gotArgs)
	}
}

func TestRunSessionManagerPluginStopsWhenContextIsCanceled(t *testing.T) {
	pluginDir := t.TempDir()
	writePlugin(t, pluginDir, "exec sleep 10")
	t.Setenv("PATH", pluginDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := RunSessionManagerPlugin(ctx, "us-east-1", &ExecuteCommandSession{}, &TemporaryCredentials{
		AccessKeyID:     "key",
		SecretAccessKey: "secret",
		SessionToken:    "token",
	})
	if err == nil {
		t.Error("RunSessionManagerPlugin succeeded after context cancellation")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("RunSessionManagerPlugin ignored context cancellation for %s", elapsed)
	}
}

func TestRunSessionManagerPluginRequiresPlugin(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	err := RunSessionManagerPlugin(context.Background(), "us-east-1", &ExecuteCommandSession{}, &TemporaryCredentials{
		AccessKeyID:     "key",
		SecretAccessKey: "secret",
		SessionToken:    "token",
	})
	if err == nil {
		t.Fatal("RunSessionManagerPlugin succeeded without session-manager-plugin in PATH")
	}
}

func environmentMap(t *testing.T, env []string) map[string]string {
	t.Helper()
	got := make(map[string]string, len(env))
	for _, entry := range env {
		if entry == "" {
			continue
		}
		key, value, found := strings.Cut(entry, "=")
		if !found {
			t.Errorf("environment entry %q has no value", entry)
			continue
		}
		if _, exists := got[key]; exists {
			t.Errorf("environment contains duplicate key %q", key)
		}
		got[key] = value
	}
	return got
}

func writePlugin(t *testing.T, directory, body string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("plugin test requires a POSIX shell")
	}
	plugin := filepath.Join(directory, sessionManagerPlugin)
	if err := os.WriteFile(plugin, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write test plugin: %v", err)
	}
}

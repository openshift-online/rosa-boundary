package aws

import (
	"strings"
	"testing"
)

func TestSessionManagerPluginEnvUsesAssumedCredentials(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
	t.Setenv("AWS_SESSION_TOKEN", "ambient-token")
	t.Setenv("AWS_SECURITY_TOKEN", "legacy-ambient-token")
	t.Setenv("ROSA_BOUNDARY_TEST_PRESERVE", "preserved-value")

	env, err := sessionManagerPluginEnv(&TemporaryCredentials{
		AccessKeyID:     "assumed-access-key",
		SecretAccessKey: "assumed-secret",
		SessionToken:    "assumed-token",
	})
	if err != nil {
		t.Fatalf("sessionManagerPluginEnv returned an error: %v", err)
	}

	gotEnv := make(map[string]string, len(env))
	for _, entry := range env {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			t.Errorf("environment entry %q has no value", entry)
			continue
		}
		if _, exists := gotEnv[key]; exists {
			t.Errorf("environment contains duplicate key %q", key)
		}
		gotEnv[key] = value
	}

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
	if _, exists := gotEnv["AWS_SECURITY_TOKEN"]; exists {
		t.Error("environment retains legacy AWS_SECURITY_TOKEN")
	}
}

func TestSessionManagerPluginEnvRejectsMissingCredentials(t *testing.T) {
	if _, err := sessionManagerPluginEnv(nil); err == nil {
		t.Error("sessionManagerPluginEnv accepted nil credentials")
	}
}

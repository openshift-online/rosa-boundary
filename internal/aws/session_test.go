package aws

import (
	"strings"
	"testing"
)

func TestSessionManagerPluginEnvUsesAssumedCredentials(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
	t.Setenv("AWS_SESSION_TOKEN", "ambient-token")

	env, err := sessionManagerPluginEnv(&TemporaryCredentials{
		AccessKeyID:     "assumed-access-key",
		SecretAccessKey: "assumed-secret",
		SessionToken:    "assumed-token",
	})
	if err != nil {
		t.Fatalf("sessionManagerPluginEnv returned an error: %v", err)
	}

	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"AWS_ACCESS_KEY_ID=assumed-access-key",
		"AWS_SECRET_ACCESS_KEY=assumed-secret",
		"AWS_SESSION_TOKEN=assumed-token",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("environment does not contain %q", want)
		}
	}
	for _, unwanted := range []string{"ambient-access-key", "ambient-secret", "ambient-token"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("environment retains ambient credential %q", unwanted)
		}
	}
}

func TestSessionManagerPluginEnvRejectsMissingCredentials(t *testing.T) {
	if _, err := sessionManagerPluginEnv(nil); err == nil {
		t.Error("sessionManagerPluginEnv accepted nil credentials")
	}
}

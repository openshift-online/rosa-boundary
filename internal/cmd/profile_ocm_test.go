package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/openshift-online/rosa-boundary/internal/config"
	ocmcredentials "github.com/openshift-online/rosa-boundary/internal/credentials/ocm"
)

func TestConfigInitSavesOCMURL(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	args := []string{"config", "init", "--name", "dev", "--auto-discover=false",
		"--account-id", "123456789012", "--region", "us-east-1", "--keycloak-url", "https://auth.example.test",
		"--lambda-function-name", "create", "--invoker-role-arn", "arn:aws:iam::123456789012:role/invoker",
		"--sre-role-arn", "arn:aws:iam::123456789012:role/sre", "--ecs-cluster", "ecs", "--efs-filesystem-id", "fs-example"}
	if _, err := runTestCLI(t, append(args, "--ocm-url", "staging")...); err != nil {
		t.Fatal(err)
	}
	got, err := runTestCLI(t, "--profile", "dev", "config", "get", "ocm_url")
	if err != nil || strings.TrimSpace(got) != ocmcredentials.StagingURL {
		t.Fatalf("saved URL = %q, %v", got, err)
	}
	args[3] = "invalid"
	if _, err := runTestCLI(t, append(args, "--ocm-url", "https://untrusted.example.test")...); err == nil {
		t.Fatal("unapproved URL accepted")
	}
	file, err := config.LoadProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := file.Profiles["invalid"]; ok {
		t.Fatal("invalid destination persisted")
	}
}

// Both credential entrypoints must use the selected profile, not the active
// profile or workstation OCM config. Stop before any AWS/session operation.
func TestOCMCommandsResolveSelectedProfile(t *testing.T) {
	setupCredentialGuidance(t, "current-user")
	file, err := config.LoadProfiles()
	if err != nil {
		t.Fatal(err)
	}
	p := file.Profiles["stage"]
	p.OCMURL = "staging"
	p.InvokerRoleARN = p.SRERoleARN
	p.LambdaFunctionName = "create"
	file.Profiles["dev"] = p
	if err := config.SaveProfiles(file); err != nil {
		t.Fatal(err)
	}
	for _, path := range [][]string{{"session", "create"}, {"session", "credentials", "configure", "ocm"}} {
		for _, override := range []string{"", "integration"} {
			command := commandAtPath(t, buildRootCommand(), path...)
			selectedProfile = "dev"
			if override != "" {
				if err := command.Flags().Set("ocm-url", override); err != nil {
					t.Fatal(err)
				}
			}
			command.SetContext(context.Background())
			if err := commandPreRun(command, nil); err != nil {
				t.Fatal(err)
			}
			want := "staging"
			if override != "" {
				want = override
			}
			if cachedAuthResult.Config.OCMURL != want {
				t.Fatalf("%v: URL = %q", path, cachedAuthResult.Config.OCMURL)
			}
			if commandCancel != nil {
				commandCancel()
				commandCancel = nil
			}
		}
	}
	selectedProfile = ""
}

func TestStartRejectsInvalidProfileOCMURLBeforeLaunch(t *testing.T) {
	previous := cachedAuthResult
	previousURL, previousCredentials, previousNoWait, previousOutput := startOCMURL, startCredentials, startNoWait, startOutputFormat
	t.Cleanup(func() {
		cachedAuthResult = previous
		startOCMURL, startCredentials, startNoWait, startOutputFormat = previousURL, previousCredentials, previousNoWait, previousOutput
	})
	cachedAuthResult = &AuthResult{Config: &config.Config{OCMURL: "https://untrusted.example.test"}}
	command := commandAtPath(t, buildRootCommand(), "session", "create")
	startOutputFormat = "text"
	startCredentials = "ocm"
	startNoWait = false
	err := runStartSession(command, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported OCM environment") {
		t.Fatalf("invalid profile destination = %v", err)
	}
	configure := commandAtPath(t, buildRootCommand(), "session", "credentials", "configure", "ocm")
	if err := runCredentialsConfigureOCM(configure, []string{"task-a"}); err == nil || !strings.Contains(err.Error(), "unsupported OCM environment") {
		t.Fatalf("credential configure accepted invalid profile URL: %v", err)
	}
}

package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/config"
)

func TestJoinJSONOnlyAfterSuccessfulShellExit(t *testing.T) {
	previousOpen, previousAuth, previousProfile := openInteractiveSession, cachedAuthResult, selectedProfile
	t.Cleanup(func() {
		openInteractiveSession, cachedAuthResult, selectedProfile = previousOpen, previousAuth, previousProfile
	})
	selectedProfile = "stage"
	cachedAuthResult = &AuthResult{Config: testJoinConfig(), Credentials: &awsclient.TemporaryCredentials{}}
	joinContainer, joinCommand, joinNoWait = "rosa-boundary", defaultExecCommand, false
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"success", nil}, {"plugin failure", errors.New("plugin exited 1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := commandAtPath(t, buildRootCommand(), "session", "join")
			selectedProfile = "stage"
			if err := cmd.Flags().Set("output", "json"); err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			cmd.SetOut(&stdout)
			openInteractiveSession = func(context.Context, *awsclient.ECSClient, string, *awsclient.TemporaryCredentials, string, string, string, bool) error {
				if stdout.Len() != 0 {
					t.Fatal("JSON emitted before shell exit")
				}
				return tc.err
			}
			err := runJoinSession(cmd, []string{"task-1"})
			if tc.err != nil {
				if err == nil || !strings.Contains(err.Error(), tc.err.Error()) || stdout.Len() != 0 {
					t.Fatalf("error=%v stdout=%q", err, stdout.String())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertOneJSON(t, stdout.String(), map[string]any{"profile": "stage", "session_id": "task-1", "status": "disconnected", "task_closed": false, "investigation_closed": false})
		})
	}
}

func testJoinConfig() *config.Config {
	return &config.Config{AWSRegion: "us-east-1", ClusterName: "ecs"}
}

func TestCredentialActionJSONResults(t *testing.T) {
	previous := selectedProfile
	selectedProfile = "stage"
	t.Cleanup(func() { selectedProfile = previous })
	for _, tc := range []struct{ action, environment string }{{"configured", "staging"}, {"cleared", ""}} {
		t.Run(tc.action, func(t *testing.T) {
			var stdout bytes.Buffer
			cmd := commandAtPath(t, buildRootCommand(), "session", "credentials", "configure", "ocm")
			selectedProfile = "stage"
			cmd.SetOut(&stdout)
			if err := cmd.Flags().Set("output", "json"); err != nil {
				t.Fatal(err)
			}
			if err := credentialActionResult(cmd, tc.action, "task-1", tc.environment); err != nil {
				t.Fatal(err)
			}
			assertOneJSON(t, stdout.String(), map[string]any{"profile": "stage", "provider": "ocm", "action": tc.action, "session_id": "task-1"})
			if tc.environment != "" && !strings.Contains(stdout.String(), `"environment": "staging"`) {
				t.Fatal(stdout.String())
			}
		})
	}
}

func TestStartJSONStatusDistinguishesLaunchAndDisconnect(t *testing.T) {
	for _, tc := range []struct {
		name, status      string
		noWait, connected bool
	}{
		{"ready", "RUNNING", false, false}, {"no wait", "launched", true, false}, {"connected", "disconnected", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := startSessionJSONResult("cluster", "inv", "task-1", "ecs", "arn", "4.20", 3600, "fsap", "role", false, tc.noWait, tc.connected)
			if result["status"] != tc.status || result["session_id"] != "task-1" {
				t.Fatal(result)
			}
			if tc.connected && (result["task_closed"] != false || result["investigation_closed"] != false) {
				t.Fatal(result)
			}
		})
	}
}

func TestCreatedSessionExecFailureIncludesCleanupWithoutSuccessJSON(t *testing.T) {
	selectedProfile = "stage"
	t.Cleanup(func() { selectedProfile = "" })
	cause := errors.New("ECS Exec plugin failed")
	err := sessionCreationError(cause, "task-1", "cluster", "inv", "us-west-2", "ecs-override")
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), `session close "task-1" --yes --region "us-west-2" --ecs-cluster "ecs-override"`) || !strings.Contains(err.Error(), "session task-1 created") {
		t.Fatal(err)
	}
}

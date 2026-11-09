package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/config"
)

func credentialGuidanceToken(subject string) string {
	payload := fmt.Sprintf(`{"exp":%d,"sub":%q}`, time.Now().Add(time.Hour).Unix(), subject)
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}

func TestCredentialGuidanceJSONSelectionOnly(t *testing.T) {
	setupCredentialGuidance(t, "current-user")
	previousList, previousToken, previousTransfer := listCredentialSessions, newOCMTokenAcquirer, newOCMCredentialTransfer
	t.Cleanup(func() {
		listCredentialSessions, newOCMTokenAcquirer, newOCMCredentialTransfer = previousList, previousToken, previousTransfer
	})
	newOCMTokenAcquirer = func() ocmTokenAcquirer { t.Fatal("unexpected OCM token acquisition"); return nil }
	newOCMCredentialTransfer = func() ocmCredentialTransfer { t.Fatal("unexpected transfer"); return nil }
	for _, tc := range []struct {
		name, action string
		tasks        []awsclient.TaskSummary
		count        float64
	}{
		{"none", "configure", []awsclient.TaskSummary{guidanceTask("other-secret", "other-user", "RUNNING")}, 0},
		{"one", "configure", []awsclient.TaskSummary{guidanceTask("task-a", "current-user", "RUNNING")}, 1},
		{"multiple", "clear", []awsclient.TaskSummary{guidanceTask("task-a", "current-user", "RUNNING"), guidanceTask("task-b", "current-user", "RUNNING")}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listCredentialSessions = func(context.Context, *AuthResult, string) ([]awsclient.TaskSummary, error) { return tc.tasks, nil }
			args := []string{"session", "credentials", tc.action, "ocm", "-o", "json"}
			if tc.count == 1 {
				args = append(args, "--ocm-url", "staging")
			}
			stdout, err := runTestCLI(t, args...)
			if err != nil || strings.Contains(stdout, "other-secret") {
				t.Fatalf("stdout=%q err=%v", stdout, err)
			}
			assertOneJSON(t, stdout, map[string]any{"profile": "stage", "provider": "ocm", "action": tc.action, "status": "selection_required", "eligible_count": tc.count, "credentials_changed": false})
			var result map[string]any
			if err := json.Unmarshal([]byte(stdout), &result); err != nil {
				t.Fatal(err)
			}
			if tc.count == 1 {
				if result["session_id"] != "task-a" || !strings.Contains(result["suggested_command"].(string), "--ocm-url 'staging'") {
					t.Fatalf("missing suggestion: %v", result)
				}
			} else if result["session_id"] != nil || result["suggested_command"] != nil {
				t.Fatalf("ambiguous discovery exposed session: %v", result)
			}
		})
	}
}

func setupCredentialGuidance(t *testing.T, subject string) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	cfg := config.Config{AccountID: "123456789012", AWSRegion: "us-east-1", KeycloakURL: "https://auth.example.test", ClusterName: "ecs", SRERoleARN: "arn:aws:iam::123456789012:role/sre"}
	if err := saveTestProfile("stage", cfg, true, false); err != nil {
		t.Fatal(err)
	}
	if err := auth.SaveTokenForConfig(credentialGuidanceToken(subject), auth.PKCEConfig{KeycloakURL: cfg.KeycloakURL, Realm: "EmployeeIDP", ClientID: "rosa-boundary-sre"}); err != nil {
		t.Fatal(err)
	}
	previous := assumeWebIdentity
	assumeWebIdentity = func(_ context.Context, _, role, _, _ string) (*awsclient.TemporaryCredentials, error) {
		if role != cfg.SRERoleARN {
			t.Errorf("wrong role: %q", role)
		}
		return &awsclient.TemporaryCredentials{}, nil
	}
	t.Cleanup(func() { assumeWebIdentity = previous })
}

func guidanceTask(id, owner, status string) awsclient.TaskSummary {
	return awsclient.TaskSummary{TaskID: id, Status: status, Tags: map[string]string{"oidc_sub": owner, "cluster_id": "cluster-a", "investigation_id": "INV-1"}}
}

func TestCredentialGuidanceOnlyOwnedRunningSessions(t *testing.T) {
	setupCredentialGuidance(t, "current-user")
	previousList, previousToken, previousTransfer := listCredentialSessions, newOCMTokenAcquirer, newOCMCredentialTransfer
	t.Cleanup(func() {
		listCredentialSessions, newOCMTokenAcquirer, newOCMCredentialTransfer = previousList, previousToken, previousTransfer
	})
	newOCMTokenAcquirer = func() ocmTokenAcquirer { t.Fatal("unexpected OCM token acquisition"); return nil }
	newOCMCredentialTransfer = func() ocmCredentialTransfer { t.Fatal("unexpected ECS Exec transfer"); return nil }
	for _, tc := range []struct {
		name, action string
		tasks        []awsclient.TaskSummary
		flags        []string
		want         []string
		absent       []string
	}{
		{"none", "configure", []awsclient.TaskSummary{guidanceTask("other-secret", "other-user", "RUNNING"), guidanceTask("stopped", "current-user", "STOPPED")}, []string{"--region", "us-west-2", "--ecs-cluster", "override-ecs"}, []string{"No eligible RUNNING sessions", "--profile 'stage' session credentials configure ocm <session-id> --region 'us-west-2' --ecs-cluster 'override-ecs'"}, []string{"other-secret", "stopped", "cluster-a", "INV-1"}},
		{"one configure default URL", "configure", []awsclient.TaskSummary{guidanceTask("other-secret", "other-user", "RUNNING"), guidanceTask("task-a", "current-user", "RUNNING")}, nil, []string{"Session ID: \"task-a\"", "Cluster: \"cluster-a\"", "Investigation: \"INV-1\"", "Status: RUNNING", "--profile 'stage' session credentials configure ocm 'task-a'"}, []string{"other-secret", "--ocm-url", "--auth-flow"}},
		{"one configure overrides", "configure", []awsclient.TaskSummary{guidanceTask("task-a", "current-user", "RUNNING")}, []string{"--ocm-url", "staging", "--auth-flow", "device", "--region", "us-west-2", "--ecs-cluster", "override-ecs"}, []string{"--profile 'stage' session credentials configure ocm 'task-a'", "--ocm-url 'staging'", "--auth-flow 'device'", "--region 'us-west-2'", "--ecs-cluster 'override-ecs'"}, nil},
		{"one clear overrides", "clear", []awsclient.TaskSummary{guidanceTask("task-a", "current-user", "RUNNING")}, []string{"--region", "us-west-2", "--ecs-cluster", "override-ecs", "--use-device-code=false"}, []string{"--profile 'stage' session credentials clear ocm 'task-a'", "--region 'us-west-2'", "--ecs-cluster 'override-ecs'", "--use-device-code=false"}, []string{"--ocm-url"}},
		{"multiple", "clear", []awsclient.TaskSummary{guidanceTask("task-a", "current-user", "RUNNING"), guidanceTask("task-b", "current-user", "RUNNING"), guidanceTask("other-secret", "other-user", "RUNNING")}, nil, []string{"2 eligible RUNNING sessions", "specify the correct session ID explicitly"}, []string{"other-secret", "task-a", "task-b", "cluster-a", "INV-1"}},
		{"multiple with overrides", "clear", []awsclient.TaskSummary{guidanceTask("task-a", "current-user", "RUNNING"), guidanceTask("task-b", "current-user", "RUNNING")}, []string{"--region", "us-west-2", "--ecs-cluster", "override-ecs"}, []string{"2 eligible RUNNING sessions", "--profile 'stage' session list --status RUNNING --region 'us-west-2' --ecs-cluster 'override-ecs'"}, []string{"task-a", "task-b", "cluster-a", "INV-1"}},
		{"pending despite desired running", "configure", []awsclient.TaskSummary{guidanceTask("pending", "current-user", "PENDING")}, nil, []string{"No eligible RUNNING sessions"}, []string{"pending"}},
		{"missing and malformed ownership", "configure", []awsclient.TaskSummary{guidanceTask("missing", "", "RUNNING"), guidanceTask("newline", "current-user\n", "RUNNING"), guidanceTask("stopping", "current-user", "RUNNING"), guidanceTask("legacy", "", "RUNNING")}, nil, []string{"No eligible RUNNING sessions"}, []string{"missing", "newline", "stopping", "legacy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tasks := tc.tasks
			if tc.name == "missing and malformed ownership" {
				tasks[2].DesiredStatus = "STOPPED"
				tasks[3].Tags = map[string]string{"username": "current-user", "cluster_id": "other-cluster"}
			}
			listCredentialSessions = func(_ context.Context, result *AuthResult, subject string) ([]awsclient.TaskSummary, error) {
				if subject != "current-user" {
					t.Errorf("wrong subject: %q", subject)
				}
				if result.Config.ClusterName != "override-ecs" && result.Config.ClusterName != "ecs" {
					t.Errorf("unexpected target cluster: %q", result.Config.ClusterName)
				}
				return tasks, nil
			}
			args := append([]string{"--profile", "stage", "session", "credentials", tc.action, "ocm"}, tc.flags...)
			stdout, err := runTestCLI(t, args...)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(stdout, want) {
					t.Errorf("output missing %q: %q", want, stdout)
				}
			}
			for _, forbidden := range tc.absent {
				if strings.Contains(stdout, forbidden) {
					t.Errorf("output exposed %q: %q", forbidden, stdout)
				}
			}
		})
	}
}

func TestCredentialGuidanceFailsClosedOnMissingSubjectAndDiscoveryError(t *testing.T) {
	for _, subject := range []string{"", "current-user"} {
		t.Run(subject, func(t *testing.T) {
			setupCredentialGuidance(t, subject)
			previous := listCredentialSessions
			t.Cleanup(func() { listCredentialSessions = previous })
			called := false
			listCredentialSessions = func(context.Context, *AuthResult, string) ([]awsclient.TaskSummary, error) {
				called = true
				return nil, errors.New("other-user-secret-task-arn")
			}
			stdout, err := runTestCLI(t, "session", "credentials", "clear", "ocm")
			if err == nil || stdout != "" || strings.Contains(err.Error(), "other-user-secret-task-arn") {
				t.Fatalf("unsafe discovery failure: stdout=%q err=%v", stdout, err)
			}
			if called != (subject != "") {
				t.Fatalf("discovery called=%v with subject %q", called, subject)
			}
		})
	}
}

func TestCredentialGuidancePreservesEffectiveDeployment(t *testing.T) {
	for _, tc := range []struct {
		name, action, environmentRegion, environmentCluster string
		flags, want, absent                                 []string
		tasks                                               []awsclient.TaskSummary
	}{
		{"saved target", "clear", "", "", nil, []string{"session credentials clear ocm 'task-a'"}, []string{"--region", "--ecs-cluster"}, []awsclient.TaskSummary{guidanceTask("task-a", "current-user", "RUNNING")}},
		{"environment target one", "configure", "eu-central-1", "environment-ecs", nil, []string{"session credentials configure ocm 'task-a' --region 'eu-central-1' --ecs-cluster 'environment-ecs'"}, nil, []awsclient.TaskSummary{guidanceTask("task-a", "current-user", "RUNNING")}},
		{"environment target none configure URL", "configure", "eu-central-1", "environment-ecs", []string{"--ocm-url", "staging"}, []string{"session credentials configure ocm <session-id> --region 'eu-central-1' --ecs-cluster 'environment-ecs' --ocm-url 'staging'"}, nil, nil},
		{"environment target none clear", "clear", "eu-central-1", "environment-ecs", nil, []string{"session credentials clear ocm <session-id> --region 'eu-central-1' --ecs-cluster 'environment-ecs'"}, []string{"--ocm-url"}, nil},
		{"environment target multiple", "clear", "eu-central-1", "environment-ecs", nil, []string{"session list --status RUNNING --region 'eu-central-1' --ecs-cluster 'environment-ecs'"}, nil, []awsclient.TaskSummary{guidanceTask("task-a", "current-user", "RUNNING"), guidanceTask("task-b", "current-user", "RUNNING")}},
		{"explicit flags override environment", "configure", "eu-central-1", "environment-ecs", []string{"--region", "us-west-2", "--ecs-cluster", "flag-ecs"}, []string{"session credentials configure ocm 'task-a' --region 'us-west-2' --ecs-cluster 'flag-ecs'"}, []string{"eu-central-1", "environment-ecs"}, []awsclient.TaskSummary{guidanceTask("task-a", "current-user", "RUNNING")}},
		{"explicit saved values override environment", "clear", "eu-central-1", "environment-ecs", []string{"--region", "us-east-1", "--ecs-cluster", "ecs"}, []string{"session credentials clear ocm 'task-a' --region 'us-east-1' --ecs-cluster 'ecs'"}, []string{"eu-central-1", "environment-ecs"}, []awsclient.TaskSummary{guidanceTask("task-a", "current-user", "RUNNING")}},
		{"redundant explicit saved values", "clear", "", "", []string{"--region", "us-east-1", "--ecs-cluster", "ecs"}, []string{"session credentials clear ocm 'task-a'"}, []string{"--region", "--ecs-cluster"}, []awsclient.TaskSummary{guidanceTask("task-a", "current-user", "RUNNING")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupCredentialGuidance(t, "current-user")
			if tc.environmentRegion != "" {
				t.Setenv("ROSA_BOUNDARY_AWS_REGION", tc.environmentRegion)
				t.Setenv("ROSA_BOUNDARY_ECS_CLUSTER_NAME", tc.environmentCluster)
			}
			previousList, previousToken, previousTransfer := listCredentialSessions, newOCMTokenAcquirer, newOCMCredentialTransfer
			t.Cleanup(func() {
				listCredentialSessions, newOCMTokenAcquirer, newOCMCredentialTransfer = previousList, previousToken, previousTransfer
			})
			newOCMTokenAcquirer = func() ocmTokenAcquirer { t.Fatal("unexpected token acquisition"); return nil }
			newOCMCredentialTransfer = func() ocmCredentialTransfer { t.Fatal("unexpected transfer"); return nil }
			listCredentialSessions = func(_ context.Context, result *AuthResult, subject string) ([]awsclient.TaskSummary, error) {
				region, cluster := "us-east-1", "ecs"
				if tc.environmentRegion != "" {
					region, cluster = tc.environmentRegion, tc.environmentCluster
				}
				for i, flag := range tc.flags {
					if flag == "--region" {
						region = tc.flags[i+1]
					} else if flag == "--ecs-cluster" {
						cluster = tc.flags[i+1]
					}
				}
				if subject != "current-user" || result.Config.AWSRegion != region || result.Config.ClusterName != cluster {
					t.Errorf("unexpected discovery target or subject: region=%q cluster=%q subject=%q", result.Config.AWSRegion, result.Config.ClusterName, subject)
				}
				return tc.tasks, nil
			}
			args := append([]string{"session", "credentials", tc.action, "ocm"}, tc.flags...)
			stdout, err := runTestCLI(t, args...)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(stdout, want) {
					t.Errorf("output missing %q: %q", want, stdout)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(stdout, absent) {
					t.Errorf("output contains %q: %q", absent, stdout)
				}
			}
		})
	}
}

func TestCredentialGuidanceExplicitOCMURLIsValidatedBeforeAuth(t *testing.T) {
	// Invalid input must not resolve a profile or touch AWS/OCM.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, args := range [][]string{
		{"session", "credentials", "configure", "ocm", "--ocm-url", "invalid"},
		{"session", "credentials", "configure", "ocm", "--auth-flow", "invalid"},
	} {
		_, err := runTestCLI(t, args...)
		if err == nil || strings.Contains(err.Error(), "no active profile") {
			t.Fatalf("validation after auth/profile resolution: %v", err)
		}
	}
}

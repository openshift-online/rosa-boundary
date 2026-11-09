package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/config"
	"github.com/openshift-online/rosa-boundary/internal/lambda"
)

func captureStartSummary(t *testing.T, ecsCluster, clusterID, investigationID, sessionID, region string, noWait bool) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = old
		_ = r.Close()
	}()
	if err := printStartSessionSummary(ecsCluster, clusterID, investigationID, sessionID, region, noWait, false); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func savedStartProfile(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	previous := selectedProfile
	selectedProfile = "stage-east"
	t.Cleanup(func() { selectedProfile = previous })
	if err := saveTestProfile(selectedProfile, config.Config{AWSRegion: "us-east-1", ClusterName: "rosa-boundary-dev"}, true, false); err != nil {
		t.Fatal(err)
	}
}

func TestPrintStartSessionSummary_UsesECSClusterNotROSAClusterID(t *testing.T) {
	savedStartProfile(t)
	output := captureStartSummary(t, "rosa-boundary-dev", "e2e-test", "INV-001", "abc123def456", "us-east-1", false)
	want := "\nSession created and RUNNING.\nCluster: e2e-test\nInvestigation: INV-001\nSession ID: abc123def456\n\nTo join this session, run:\n  rosa-boundary --profile \"stage-east\" session join \"abc123def456\"\n"
	if output != want {
		t.Errorf("summary = %q, want %q", output, want)
	}
	if strings.Contains(output, "--ecs-cluster") || strings.Contains(output, "--region") {
		t.Errorf("saved profile values should not be repeated in join suggestion: %s", output)
	}
}

func TestPrintStartSessionSummary_ECSClusterNotConfusedWithClusterID(t *testing.T) {
	savedStartProfile(t)
	tests := []struct {
		name       string
		ecsCluster string
		clusterID  string
	}{
		{"different names", "rosa-boundary-dev", "shawn-e2e-rosa-boundary"},
		{"same names", "rosa-boundary-dev", "rosa-boundary-dev"},
		{"production-like override", "rosa-boundary-prod", "rosa-prod-abc-12345"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStartSummary(t, tt.ecsCluster, tt.clusterID, "INV-001", "task-123", "us-east-1", false)
			if !strings.Contains(output, "Cluster: "+tt.clusterID+"\nInvestigation: INV-001\nSession ID: task-123\n") {
				t.Errorf("missing identifiers: %s", output)
			}
			if strings.Contains(output, "--ecs-cluster \""+tt.clusterID+"\"") && tt.ecsCluster != tt.clusterID {
				t.Errorf("join uses ROSA cluster rather than ECS cluster: %s", output)
			}
			if tt.ecsCluster != "rosa-boundary-dev" && !strings.Contains(output, "session join \"task-123\" --ecs-cluster \""+tt.ecsCluster+"\"") {
				t.Errorf("join did not preserve ECS override: %s", output)
			}
		})
	}
}

func TestPrintStartSessionSummary_OverridesAndNoWait(t *testing.T) {
	savedStartProfile(t)
	t.Run("unsaved overrides", func(t *testing.T) {
		output := captureStartSummary(t, "other-ecs", "rosa", "investigation", "task-123", "us-west-2", false)
		if !strings.Contains(output, "session join \"task-123\" --region \"us-west-2\" --ecs-cluster \"other-ecs\"\n") {
			t.Errorf("join did not preserve unsaved overrides: %s", output)
		}
	})
	t.Run("environment precedence", func(t *testing.T) {
		t.Setenv("ROSA_BOUNDARY_AWS_REGION", "eu-west-1")
		t.Setenv("ROSA_BOUNDARY_ECS_CLUSTER_NAME", "env-ecs")
		output := captureStartSummary(t, "rosa-boundary-dev", "rosa", "investigation", "task-123", "us-east-1", false)
		if !strings.Contains(output, "session join \"task-123\" --region \"us-east-1\" --ecs-cluster \"rosa-boundary-dev\"\n") {
			t.Errorf("join must pin target against environment overrides: %s", output)
		}
	})
	t.Run("no wait", func(t *testing.T) {
		output := captureStartSummary(t, "rosa-boundary-dev", "rosa", "investigation", "task-123", "us-east-1", true)
		if !strings.Contains(output, "\nSession launched; RUNNING has not been confirmed.\nCluster: rosa\nInvestigation: investigation\nSession ID: task-123\n\nOnce this session is RUNNING, to join it, run:\n") || strings.Contains(output, "Session created and RUNNING.") || strings.Contains(output, "To join this session, run:") {
			t.Errorf("no-wait summary implies readiness or lacks pending status: %s", output)
		}
	})
}

func TestFinishStartSessionConnectReportsOnlyAfterShellExit(t *testing.T) {
	savedStartProfile(t)
	previousOpen, previousConnect, previousNoWait, previousFormat := openInteractiveSession, startConnect, startNoWait, startOutputFormat
	t.Cleanup(func() {
		openInteractiveSession, startConnect, startNoWait, startOutputFormat = previousOpen, previousConnect, previousNoWait, previousFormat
	})
	startConnect, startNoWait = true, false
	failure := errors.New("ECS Exec plugin failed")
	for _, format := range []string{"text", "json"} {
		for _, outcome := range []struct {
			name string
			err  error
		}{{"success", nil}, {"failure", failure}} {
			t.Run(format+"/"+outcome.name, func(t *testing.T) {
				startOutputFormat = format
				old := os.Stdout
				stdoutFile, err := os.CreateTemp(t.TempDir(), "session-create-stdout-")
				if err != nil {
					t.Fatal(err)
				}
				os.Stdout = stdoutFile
				defer func() {
					os.Stdout = old
					_ = stdoutFile.Close()
				}()
				openInteractiveSession = func(_ context.Context, _ *awsclient.ECSClient, _ string, _ *awsclient.TemporaryCredentials, sessionID, _, _ string, _ bool) error {
					if sessionID != "task-123" {
						t.Errorf("session ID = %q", sessionID)
					}
					if pending, readErr := os.ReadFile(stdoutFile.Name()); readErr != nil || len(pending) != 0 {
						t.Fatalf("output before shell exit: %q (%v)", pending, readErr)
					}
					return outcome.err
				}
				cmd := commandAtPath(t, buildRootCommand(), "session", "create")
				selectedProfile = "stage-east" // Normally resolved by commandPreRun.
				err = finishStartSession(cmd, nil, nil, "rosa-boundary-dev", "rosa", "inv", "task-123", "us-east-1",
					&lambda.InvestigationResponse{TaskARN: "arn:aws:ecs:us-east-1:123:task/task-123"}, "role", false)
				stdout, readErr := os.ReadFile(stdoutFile.Name())
				if readErr != nil {
					t.Fatal(readErr)
				}
				if outcome.err != nil {
					if !errors.Is(err, failure) || len(stdout) != 0 {
						t.Fatalf("error = %v, stdout = %q", err, stdout)
					}
					wrapped := sessionCreationError(err, "task-123", "rosa", "inv", "us-east-1", "rosa-boundary-dev")
					if !strings.Contains(wrapped.Error(), `session close "task-123"`) {
						t.Fatalf("missing cleanup guidance: %v", wrapped)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if format == "text" {
					want := "\nSession created; interactive shell disconnected.\nCluster: rosa\nInvestigation: inv\nSession ID: task-123\nThe task and investigation remain open. Stop the task with session close when finished.\n\nTo join this session, run:\n  rosa-boundary --profile \"stage-east\" session join \"task-123\"\n"
					if string(stdout) != want {
						t.Fatalf("post-disconnect summary = %q, want %q", stdout, want)
					}
				} else {
					assertOneJSON(t, string(stdout), map[string]any{"session_id": "task-123", "status": "disconnected", "task_closed": false, "investigation_closed": false})
				}
			})
		}
	}
}

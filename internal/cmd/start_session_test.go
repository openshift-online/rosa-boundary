package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/openshift-online/rosa-boundary/internal/config"
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
	if err := printStartSessionSummary(ecsCluster, clusterID, investigationID, sessionID, region, noWait); err != nil {
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

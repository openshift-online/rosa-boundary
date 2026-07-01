package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestPrintStartSummary_UsesECSClusterNotROSAClusterID(t *testing.T) {
	ecsCluster := "rosa-boundary-dev"
	rosaClusterID := "e2e-test"
	investigationID := "INV-001"
	taskID := "abc123def456"
	ocVersion := "4.20"
	timeout := 3600
	accessPointID := "fsap-0123456789"
	roleARN := "arn:aws:iam::123456789012:role/test-role"
	region := "us-east-1"

	// Capture stderr output
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	printStartSummary(ecsCluster, rosaClusterID, investigationID, taskID, ocVersion, timeout, accessPointID, roleARN, region)

	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	os.Stderr = old

	output := buf.String()

	// ECS Cluster line must show the actual ECS cluster name
	if !strings.Contains(output, "ECS Cluster:    rosa-boundary-dev") {
		t.Errorf("expected ECS Cluster to show %q, got output:\n%s", ecsCluster, output)
	}

	// ROSA Cluster line must show the ROSA cluster ID
	if !strings.Contains(output, "ROSA Cluster:   e2e-test") {
		t.Errorf("expected ROSA Cluster to show %q, got output:\n%s", rosaClusterID, output)
	}

	// The join-task command must use --ecs-cluster with the ECS cluster name
	expectedJoinCmd := "--ecs-cluster rosa-boundary-dev --region us-east-1 join-task abc123def456"
	if !strings.Contains(output, expectedJoinCmd) {
		t.Errorf("expected join-task command with ECS cluster %q, got output:\n%s", ecsCluster, output)
	}

	// The join-task command must NOT use the ROSA cluster ID as the ECS cluster
	badJoinCmd := "--ecs-cluster e2e-test"
	if strings.Contains(output, badJoinCmd) {
		t.Errorf("join-task command incorrectly uses ROSA cluster ID %q as ECS cluster:\n%s", rosaClusterID, output)
	}
}

func TestPrintStartSummary_ECSClusterNotConfusedWithClusterID(t *testing.T) {
	tests := []struct {
		name       string
		ecsCluster string
		clusterID  string
	}{
		{
			name:       "different names",
			ecsCluster: "rosa-boundary-dev",
			clusterID:  "shawn-e2e-rosa-boundary",
		},
		{
			name:       "same names",
			ecsCluster: "rosa-boundary-dev",
			clusterID:  "rosa-boundary-dev",
		},
		{
			name:       "production-like",
			ecsCluster: "rosa-boundary-prod",
			clusterID:  "rosa-prod-abc-12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			printStartSummary(tt.ecsCluster, tt.clusterID, "INV-001", "task-123", "4.20", 3600, "fsap-123", "arn:aws:iam::123:role/r", "us-east-2")

			w.Close()
			var buf bytes.Buffer
			buf.ReadFrom(r)
			os.Stderr = old

			output := buf.String()

			// ECS Cluster must always show the ECS cluster name
			if !strings.Contains(output, "ECS Cluster:    "+tt.ecsCluster) {
				t.Errorf("ECS Cluster line should show %q, got:\n%s", tt.ecsCluster, output)
			}

			// ROSA Cluster must always show the ROSA cluster ID
			if !strings.Contains(output, "ROSA Cluster:   "+tt.clusterID) {
				t.Errorf("ROSA Cluster line should show %q, got:\n%s", tt.clusterID, output)
			}

			// join-task command must use ECS cluster
			if !strings.Contains(output, "--ecs-cluster "+tt.ecsCluster) {
				t.Errorf("join-task command should use --ecs-cluster %q, got:\n%s", tt.ecsCluster, output)
			}
		})
	}
}

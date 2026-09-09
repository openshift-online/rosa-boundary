package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestPrintCloseInvestigationSummary(t *testing.T) {
	cluster := "test-cluster-1"
	investigationID := "inv-test-123"
	accessPointID := "fsap-12345"
	tasksStopped := 2
	taskDefsRemoved := 1

	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	printCloseInvestigationSummary(cluster, investigationID, accessPointID, tasksStopped, taskDefsRemoved)

	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	os.Stderr = old

	output := buf.String()

	if !strings.Contains(output, "Cluster:           test-cluster-1") {
		t.Errorf("expected Cluster to show %q, got output:\n%s", cluster, output)
	}
	if !strings.Contains(output, "Investigation:     inv-test-123") {
		t.Errorf("expected Investigation to show %q, got output:\n%s", investigationID, output)
	}
	if !strings.Contains(output, "Tasks Stopped:     2") {
		t.Errorf("expected Tasks Stopped to show 2, got output:\n%s", output)
	}
}

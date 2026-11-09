package cmd

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
)

func captureStopSessionOutput(t *testing.T, format string, waited bool) (string, string) {
	t.Helper()
	stdout, err := os.CreateTemp(t.TempDir(), "stdout-")
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderr, err := os.CreateTemp(t.TempDir(), "stderr-")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdout, stderr
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()

	task := &awsclient.TaskSummary{Tags: map[string]string{
		"cluster_id": "rosa-cluster", "investigation_id": "INV-123", "username": "owner@example.test",
	}}
	printStopSessionTarget("stage", "123456789012", "us-east-1", "task-123", task)
	if err := printStopSessionResult(format, "stage", "task-123", task, waited); err != nil {
		t.Fatal(err)
	}
	if _, err := stdout.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := stderr.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	diagnostics, err := io.ReadAll(stderr)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), string(diagnostics)
}

func TestStopSessionConfirmationTarget(t *testing.T) {
	stdout, stderr := captureStopSessionOutput(t, "text", false)
	want := "Profile: stage\n" +
		"Account: 123456789012\n" +
		"Region: us-east-1\n" +
		"Session ID: task-123\n" +
		"Cluster: rosa-cluster\n" +
		"Investigation: INV-123\n" +
		"Owner: owner@example.test\n" +
		"Closing this session stops its task and leaves the investigation open.\n"
	if stderr != want {
		t.Errorf("confirmation = %q, want %q", stderr, want)
	}
	if stdout != "Session task-123 stop requested (profile stage). Audit sync must be verified separately.\n" {
		t.Errorf("text result changed: %q", stdout)
	}
}

func TestStopSessionJSONResultOnStdout(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		waited       bool
	}{
		{"no wait", "STOPPING", false},
		{"wait", "STOPPED", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr := captureStopSessionOutput(t, "json", tc.waited)
			if !strings.Contains(stderr, "Session ID: task-123\n") || !strings.Contains(stderr, "leaves the investigation open") {
				t.Errorf("missing confirmation on stderr: %q", stderr)
			}
			decoder := json.NewDecoder(strings.NewReader(stdout))
			var result map[string]any
			if err := decoder.Decode(&result); err != nil {
				t.Fatalf("stdout is not JSON: %q: %v", stdout, err)
			}
			want := map[string]any{"profile": "stage", "cluster_id": "rosa-cluster", "investigation_id": "INV-123", "session_id": "task-123", "status": tc.status, "waited": tc.waited}
			if len(result) != len(want) {
				t.Errorf("JSON fields = %v, want %v", result, want)
			}
			for key, value := range want {
				if result[key] != value {
					t.Errorf("JSON %s = %v, want %v", key, result[key], value)
				}
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				t.Errorf("stdout contains more than one JSON result: %q: %v", stdout, err)
			}
			if strings.Contains(stdout, "Closing this session") || strings.Contains(stdout, "owner@example.test") || strings.Contains(stdout, "Account:") {
				t.Errorf("confirmation leaked into JSON stdout: %q", stdout)
			}
		})
	}
}

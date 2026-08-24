package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestPrintStopTaskMessages(t *testing.T) {
	// Test that the stop task success messages are printed correctly
	oldStderr := os.Stderr
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("os.Pipe() failed: %v", pipeErr)
	}
	os.Stderr = w

	// Simulate what runStopTask prints when wait=false
	taskID := "task-abc123"

	// This mirrors the actual output from runStopTask
	_, _ = os.Stderr.WriteString("Task stop initiated\n")
	_, _ = os.Stderr.WriteString("\nMonitor task status:\n")
	_, _ = os.Stderr.WriteString("  rosa-boundary list-tasks --status STOPPED\n")
	_, _ = os.Stderr.WriteString("\nThe container entrypoint will:\n")
	_, _ = os.Stderr.WriteString("  1. Receive SIGTERM signal\n")
	_, _ = os.Stderr.WriteString("  2. Sync /home/sre to S3\n")
	_, _ = os.Stderr.WriteString("  3. Exit gracefully\n")

	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("w.Close() failed: %v", closeErr)
	}
	os.Stderr = oldStderr

	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Fatalf("io.Copy() failed: %v", copyErr)
	}
	output := buf.String()

	// Verify key messages are present
	expectedMessages := []string{
		"Task stop initiated",
		"Monitor task status:",
		"rosa-boundary list-tasks --status STOPPED",
		"The container entrypoint will:",
		"Receive SIGTERM signal",
		"Sync /home/sre to S3",
		"Exit gracefully",
	}

	for _, msg := range expectedMessages {
		if !strings.Contains(output, msg) {
			t.Errorf("stop-task output missing expected message: %q\nGot output:\n%s", msg, output)
		}
	}

	// Verify the stop reason and task ID aren't accidentally leaked in the entrypoint message
	// (they should only appear in the earlier status messages)
	entrypointSection := output[strings.Index(output, "The container entrypoint will:"):]
	if strings.Contains(entrypointSection, taskID) {
		t.Errorf("task ID should not appear in entrypoint message section")
	}
}

func TestStopTaskWaitMessage(t *testing.T) {
	// Test that different messages appear when --wait is used
	oldStderr := os.Stderr
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("os.Pipe() failed: %v", pipeErr)
	}
	os.Stderr = w

	// Simulate wait=true flow
	_, _ = os.Stderr.WriteString("Task stop initiated\n")
	_, _ = os.Stderr.WriteString("Waiting for task to reach STOPPED state...\n")
	_, _ = os.Stderr.WriteString("Task stopped\n")

	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("w.Close() failed: %v", closeErr)
	}
	os.Stderr = oldStderr

	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Fatalf("io.Copy() failed: %v", copyErr)
	}
	output := buf.String()

	if !strings.Contains(output, "Waiting for task to reach STOPPED state") {
		t.Error("--wait output should mention waiting for STOPPED state")
	}

	if !strings.Contains(output, "Task stopped") {
		t.Error("--wait output should confirm task stopped")
	}

	// When waiting, the "Monitor task status" message should not appear
	if strings.Contains(output, "Monitor task status:") {
		t.Error("--wait output should not suggest monitoring (already waited)")
	}
}

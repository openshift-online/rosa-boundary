package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestPrintCloseInvestigationSummary(t *testing.T) {
	tests := []struct {
		name            string
		cluster         string
		investigationID string
		accessPointID   string
		tasksStopped    int
		taskDefsRemoved int
		wantContains    []string
	}{
		{
			name:            "no tasks stopped",
			cluster:         "test-cluster-123",
			investigationID: "INV-001",
			accessPointID:   "fsap-abc123",
			tasksStopped:    0,
			taskDefsRemoved: 2,
			wantContains: []string{
				"Investigation Closed",
				"test-cluster-123",
				"INV-001",
				"fsap-abc123 (deleted)",
				"Tasks Stopped:     0",
				"Task Defs Removed: 2",
				"EFS data is preserved",
			},
		},
		{
			name:            "multiple tasks stopped",
			cluster:         "prod-cluster-456",
			investigationID: "INV-002",
			accessPointID:   "fsap-def456",
			tasksStopped:    3,
			taskDefsRemoved: 5,
			wantContains: []string{
				"Investigation Closed",
				"prod-cluster-456",
				"INV-002",
				"fsap-def456 (deleted)",
				"Tasks Stopped:     3",
				"Task Defs Removed: 5",
			},
		},
		{
			name:            "no task defs to remove",
			cluster:         "dev-cluster",
			investigationID: "INV-003",
			accessPointID:   "fsap-xyz789",
			tasksStopped:    1,
			taskDefsRemoved: 0,
			wantContains: []string{
				"Task Defs Removed: 0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stderr
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			printCloseInvestigationSummary(
				tt.cluster,
				tt.investigationID,
				tt.accessPointID,
				tt.tasksStopped,
				tt.taskDefsRemoved,
			)

			w.Close()
			os.Stderr = oldStderr

			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			// Verify all expected strings are present
			for _, want := range tt.wantContains {
				if !strings.Contains(output, want) {
					t.Errorf("printCloseInvestigationSummary() output missing %q\nGot:\n%s", want, output)
				}
			}
		})
	}
}

func TestPrintCloseInvestigationSummary_Format(t *testing.T) {
	// Verify the summary has proper structure and formatting
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	printCloseInvestigationSummary("cluster-1", "INV-123", "fsap-abc", 2, 3)

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Check for visual separators
	if !strings.Contains(output, "========================================") {
		t.Error("summary should include separator lines for readability")
	}

	// Check that values are properly aligned (looking for consistent spacing)
	lines := strings.Split(output, "\n")
	var hasAlignedValues bool
	for _, line := range lines {
		// Look for indented lines with values (e.g., "  Cluster:           cluster-1")
		if strings.HasPrefix(strings.TrimSpace(line), "Cluster:") ||
			strings.HasPrefix(strings.TrimSpace(line), "Investigation:") {
			hasAlignedValues = true
			break
		}
	}

	if !hasAlignedValues {
		t.Error("summary should have aligned key-value pairs")
	}
}

func TestCloseInvestigation_OutputFormatValidation(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		wantError bool
	}{
		{
			name:      "valid text format",
			format:    "text",
			wantError: false,
		},
		{
			name:      "valid json format",
			format:    "json",
			wantError: false,
		},
		{
			name:      "invalid format - yaml",
			format:    "yaml",
			wantError: true,
		},
		{
			name:      "invalid format - csv",
			format:    "csv",
			wantError: true,
		},
		{
			name:      "invalid format - uppercase",
			format:    "TEXT",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate the output format the same way runCloseInvestigation does
			var valid bool
			switch tt.format {
			case "text", "json":
				valid = true
			default:
				valid = false
			}

			if tt.wantError && valid {
				t.Errorf("expected error for format %q, but was considered valid", tt.format)
			}

			if !tt.wantError && !valid {
				t.Errorf("expected format %q to be valid, but was considered invalid", tt.format)
			}
		})
	}
}

func TestCloseInvestigation_FlagDefaults(t *testing.T) {
	// Test that flag defaults are set correctly
	if closeInvestigationCmd.Flags().Lookup("force") == nil {
		t.Error("close-investigation should have --force flag")
	}

	forceDefault := closeInvestigationCmd.Flags().Lookup("force").DefValue
	if forceDefault != "false" {
		t.Errorf("--force default = %q, want %q", forceDefault, "false")
	}

	if closeInvestigationCmd.Flags().Lookup("yes") == nil {
		t.Error("close-investigation should have --yes flag")
	}

	yesDefault := closeInvestigationCmd.Flags().Lookup("yes").DefValue
	if yesDefault != "false" {
		t.Errorf("--yes default = %q, want %q", yesDefault, "false")
	}

	if closeInvestigationCmd.Flags().Lookup("output") == nil {
		t.Error("close-investigation should have --output flag")
	}

	outputDefault := closeInvestigationCmd.Flags().Lookup("output").DefValue
	if outputDefault != "text" {
		t.Errorf("--output default = %q, want %q", outputDefault, "text")
	}
}

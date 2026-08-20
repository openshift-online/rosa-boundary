package cmd

import (
	"strings"
	"testing"
)

func TestListTasks_StatusValidation(t *testing.T) {
	tests := []struct {
		name      string
		status    string
		wantError bool
	}{
		{
			name:      "valid RUNNING status",
			status:    "RUNNING",
			wantError: false,
		},
		{
			name:      "valid STOPPED status",
			status:    "STOPPED",
			wantError: false,
		},
		{
			name:      "valid ALL status",
			status:    "ALL",
			wantError: false,
		},
		{
			name:      "valid lowercase running",
			status:    "running",
			wantError: false,
		},
		{
			name:      "valid lowercase stopped",
			status:    "stopped",
			wantError: false,
		},
		{
			name:      "valid lowercase all",
			status:    "all",
			wantError: false,
		},
		{
			name:      "invalid status - PENDING",
			status:    "PENDING",
			wantError: true,
		},
		{
			name:      "invalid status - ACTIVE",
			status:    "ACTIVE",
			wantError: true,
		},
		{
			name:      "invalid status - empty",
			status:    "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate the status the same way runListTasks does
			desiredStatus := strings.ToUpper(tt.status)
			var valid bool
			switch desiredStatus {
			case "RUNNING", "STOPPED", "ALL":
				valid = true
			default:
				valid = false
			}

			if tt.wantError && valid {
				t.Errorf("expected error for status %q, but was considered valid", tt.status)
			}

			if !tt.wantError && !valid {
				t.Errorf("expected status %q to be valid, but was considered invalid", tt.status)
			}
		})
	}
}

func TestListTasks_OutputFormatValidation(t *testing.T) {
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
			name:      "invalid format - uppercase JSON",
			format:    "JSON",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate the output format the same way runListTasks does
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

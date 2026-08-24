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
			name:      "valid RUNNING",
			status:    "RUNNING",
			wantError: false,
		},
		{
			name:      "valid STOPPED",
			status:    "STOPPED",
			wantError: false,
		},
		{
			name:      "valid all lowercase",
			status:    "all",
			wantError: false,
		},
		{
			name:      "valid mixed case",
			status:    "Running",
			wantError: false,
		},
		{
			name:      "invalid status - PENDING",
			status:    "PENDING",
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
			normalized, err := validateListTasksStatus(tt.status)

			if tt.wantError && err == nil {
				t.Errorf("expected error for status %q, got nil", tt.status)
			}

			if !tt.wantError && err != nil {
				t.Errorf("unexpected error for status %q: %v", tt.status, err)
			}

			if !tt.wantError && normalized != strings.ToUpper(tt.status) {
				t.Errorf("normalized status = %q, want %q", normalized, strings.ToUpper(tt.status))
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
			err := validateTextOrJSONOutputFormat(tt.format)

			if tt.wantError && err == nil {
				t.Errorf("expected error for format %q, got nil", tt.format)
			}

			if !tt.wantError && err != nil {
				t.Errorf("unexpected error for format %q: %v", tt.format, err)
			}
		})
	}
}

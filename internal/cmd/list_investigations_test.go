package cmd

import (
	"testing"
)

func TestListInvestigations_OutputFormatValidation(t *testing.T) {
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
			name:      "invalid format - xml",
			format:    "xml",
			wantError: true,
		},
		{
			name:      "invalid format - yaml",
			format:    "yaml",
			wantError: true,
		},
		{
			name:      "invalid format - empty",
			format:    "",
			wantError: true,
		},
		{
			name:      "invalid format - uppercase",
			format:    "JSON",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateListInvestigationsOutputFormat(tt.format)

			if tt.wantError && err == nil {
				t.Errorf("expected error for format %q, got nil", tt.format)
			}

			if !tt.wantError && err != nil {
				t.Errorf("unexpected error for format %q: %v", tt.format, err)
			}

			if tt.wantError && err != nil {
				if _, ok := err.(*invalidOutputFormatError); !ok {
					t.Errorf("expected *invalidOutputFormatError for format %q, got %T", tt.format, err)
				}
			}
		})
	}
}

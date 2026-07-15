package cmd

import (
	"testing"
)

func TestDeriveInvokerRoleARN(t *testing.T) {
	tests := []struct {
		name      string
		accountID string
		project   string
		stage     string
		expected  string
	}{
		{
			name:      "default dev",
			accountID: "123456789012",
			project:   "rosa-boundary",
			stage:     "dev",
			expected:  "arn:aws:iam::123456789012:role/rosa-boundary-dev-lambda-invoker",
		},
		{
			name:      "production",
			accountID: "933409759055",
			project:   "rosa-boundary",
			stage:     "prod",
			expected:  "arn:aws:iam::933409759055:role/rosa-boundary-prod-lambda-invoker",
		},
		{
			name:      "custom project",
			accountID: "111222333444",
			project:   "my-project",
			stage:     "staging",
			expected:  "arn:aws:iam::111222333444:role/my-project-staging-lambda-invoker",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveInvokerRoleARN(tt.accountID, tt.project, tt.stage)
			if got != tt.expected {
				t.Errorf("DeriveInvokerRoleARN(%q, %q, %q) = %q, want %q",
					tt.accountID, tt.project, tt.stage, got, tt.expected)
			}
		})
	}
}

func TestDeriveLambdaFunctionName(t *testing.T) {
	tests := []struct {
		name     string
		project  string
		stage    string
		expected string
	}{
		{
			name:     "default dev",
			project:  "rosa-boundary",
			stage:    "dev",
			expected: "rosa-boundary-dev-create-investigation",
		},
		{
			name:     "production",
			project:  "rosa-boundary",
			stage:    "prod",
			expected: "rosa-boundary-prod-create-investigation",
		},
		{
			name:     "custom project",
			project:  "my-project",
			stage:    "staging",
			expected: "my-project-staging-create-investigation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveLambdaFunctionName(tt.project, tt.stage)
			if got != tt.expected {
				t.Errorf("DeriveLambdaFunctionName(%q, %q) = %q, want %q",
					tt.project, tt.stage, got, tt.expected)
			}
		})
	}
}

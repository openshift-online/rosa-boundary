package cmd

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/term"
)

func TestNewTerminalPromptHandlesBackspace(t *testing.T) {
	terminalInput := strings.NewReader("1928912\x7f\x7f\r")
	terminalOutput := &bytes.Buffer{}
	terminal := term.NewTerminal(readWriter{Reader: terminalInput, Writer: terminalOutput}, "")

	prompt := newTerminalPrompt(terminal)
	got, err := prompt("AWS Account ID", "", "")
	if err != nil {
		t.Fatalf("prompt returned an unexpected error: %v", err)
	}

	if got != "19289" {
		t.Fatalf("prompt returned %q, want %q", got, "19289")
	}
	if !strings.Contains(terminalOutput.String(), "AWS Account ID: 1928912") {
		t.Fatalf("prompt output does not contain the entered value: %q", terminalOutput.String())
	}
}

func TestNewTerminalPromptReturnsEOF(t *testing.T) {
	terminal := term.NewTerminal(readWriter{
		Reader: strings.NewReader(""),
		Writer: &bytes.Buffer{},
	}, "")

	got, err := newTerminalPrompt(terminal)("AWS Account ID", "fallback", "")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("prompt error = %v, want %v", err, io.EOF)
	}
	if got != "" {
		t.Fatalf("prompt value = %q, want empty value on EOF", got)
	}
}

func TestNewTerminalPromptPropagatesError(t *testing.T) {
	sentinel := errors.New("terminal input failed")
	terminal := term.NewTerminal(readWriter{
		Reader: promptErrorReader{err: sentinel},
		Writer: &bytes.Buffer{},
	}, "")

	_, err := newTerminalPrompt(terminal)("AWS Account ID", "", "")
	if !errors.Is(err, sentinel) {
		t.Fatalf("prompt error = %v, want %v", err, sentinel)
	}
}

func TestNewPromptReturnsEOF(t *testing.T) {
	prompt := newPrompt(bufio.NewScanner(strings.NewReader("")))

	got, err := prompt("AWS Account ID", "fallback", "")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("prompt error = %v, want %v", err, io.EOF)
	}
	if got != "" {
		t.Fatalf("prompt value = %q, want empty value on EOF", got)
	}
}

func TestNewPromptPropagatesScannerError(t *testing.T) {
	sentinel := errors.New("input failed")
	prompt := newPrompt(bufio.NewScanner(promptErrorReader{err: sentinel}))

	_, err := prompt("AWS Account ID", "", "")
	if !errors.Is(err, sentinel) {
		t.Fatalf("prompt error = %v, want %v", err, sentinel)
	}
}

type promptErrorReader struct {
	err error
}

func (r promptErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}

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

// ---------------------------------------------------------------------------
// Contract test helpers
//
// The helpers below locate and parse Terraform .tf files to extract resource
// naming patterns. They assume the Terraform files live at
// deploy/regional/ relative to the repository root.
//
// If the Terraform files are moved or reorganised, these helpers (and the
// contract tests that use them) will need to be updated to reflect the new
// paths. A test failure pointing at readTerraformFile is a likely indicator.
// ---------------------------------------------------------------------------

// repoRoot returns the repository root by walking up from the test file's
// directory until it finds go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	dir := filepath.Dir(testFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot find repo root (go.mod not found in any parent)")
		}
		dir = parent
	}
}

// readTerraformFile reads a Terraform file relative to deploy/regional/.
// If the Terraform directory is relocated, update the path here.
func readTerraformFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "deploy", "regional", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	return string(data)
}

// extractTerraformPattern finds a line like:
//
//	function_name = "${var.project}-${var.stage}-create-investigation"
//
// and returns the interpolation expression (e.g. "${var.project}-${var.stage}-create-investigation").
// The attribute parameter matches the HCL attribute name (e.g. "function_name" or "name").
func extractTerraformPattern(t *testing.T, content, attribute string) string {
	t.Helper()
	// Match:  attribute  =  "...${var.project}...${var.stage}..."
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(attribute) + `\s*=\s*"(\$\{var\.project\}[^"]*)"`)
	matches := re.FindStringSubmatch(content)
	if matches == nil {
		t.Fatalf("cannot find %s = \"${var.project}...\" pattern in Terraform content", attribute)
	}
	return matches[1]
}

// expandTerraformVars replaces ${var.project} and ${var.stage} with the given values.
func expandTerraformVars(pattern, project, stage string) string {
	result := strings.ReplaceAll(pattern, "${var.project}", project)
	result = strings.ReplaceAll(result, "${var.stage}", stage)
	return result
}

// Contract: TestContractDeriveLambdaFunctionName_MatchesTerraform verifies
// that the Go derivation function produces the same name as the Terraform
// resource definition in deploy/regional/lambda-create-investigation.tf.
//
// If the Terraform naming convention changes, this test will fail — alerting
// developers that the CLI must be updated to match (or vice versa).
//
// NOTE: This test reads Terraform files from deploy/regional/. Moving or
// renaming those files will break this test.
func TestContractDeriveLambdaFunctionName_MatchesTerraform(t *testing.T) {
	content := readTerraformFile(t, "lambda-create-investigation.tf")
	pattern := extractTerraformPattern(t, content, "function_name")

	for _, tt := range []struct {
		project string
		stage   string
	}{
		{"rosa-boundary", "dev"},
		{"rosa-boundary", "prod"},
		{"custom-project", "staging"},
	} {
		expected := expandTerraformVars(pattern, tt.project, tt.stage)
		got := DeriveLambdaFunctionName(tt.project, tt.stage)
		if got != expected {
			t.Errorf("DeriveLambdaFunctionName(%q, %q) = %q, want %q (from Terraform pattern %q)",
				tt.project, tt.stage, got, expected, pattern)
		}
	}
}

// Contract: TestContractDeriveInvokerRoleARN_MatchesTerraform verifies that
// the role name suffix produced by the Go derivation function matches the
// Terraform resource naming in deploy/regional/lambda-invoker.tf.
//
// The ARN prefix (arn:aws:iam::<account>:role/) is added by the Go function
// but not present in Terraform's name attribute, so we compare only the role
// name portion.
//
// NOTE: This test reads Terraform files from deploy/regional/. Moving or
// renaming those files will break this test.
func TestContractDeriveInvokerRoleARN_MatchesTerraform(t *testing.T) {
	content := readTerraformFile(t, "lambda-invoker.tf")
	pattern := extractTerraformPattern(t, content, "name")

	for _, tt := range []struct {
		accountID string
		project   string
		stage     string
	}{
		{"123456789012", "rosa-boundary", "dev"},
		{"933409759055", "rosa-boundary", "prod"},
		{"111222333444", "custom-project", "staging"},
	} {
		expectedRoleName := expandTerraformVars(pattern, tt.project, tt.stage)
		expectedARN := "arn:aws:iam::" + tt.accountID + ":role/" + expectedRoleName

		got := DeriveInvokerRoleARN(tt.accountID, tt.project, tt.stage)
		if got != expectedARN {
			t.Errorf("DeriveInvokerRoleARN(%q, %q, %q) = %q, want %q (from Terraform pattern %q)",
				tt.accountID, tt.project, tt.stage, got, expectedARN, pattern)
		}
	}
}

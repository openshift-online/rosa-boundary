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
	"gopkg.in/yaml.v3"
)

func TestConfigInitDoesNotInheritIssuerFromExistingProfileOrEnvironment(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, err := runTestCLI(t, "config", "init", "--name", "first", "--auto-discover=false",
		"--account-id", "123456789012", "--region", "us-east-1", "--keycloak-url", "https://first.example.test",
		"--lambda-function-name", "create", "--invoker-role-arn", "arn:aws:iam::123456789012:role/invoker",
		"--sre-role-arn", "arn:aws:iam::123456789012:role/sre", "--ecs-cluster", "ecs", "--efs-filesystem-id", "fs-example")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYCLOAK_URL", "https://legacy.example.test")
	t.Setenv("ROSA_BOUNDARY_KEYCLOAK_URL", "https://env.example.test")
	_, err = runTestCLI(t, "config", "init", "--name", "second", "--auto-discover=false",
		"--account-id", "123456789012", "--region", "us-east-1",
		"--lambda-function-name", "create", "--invoker-role-arn", "arn:aws:iam::123456789012:role/invoker",
		"--sre-role-arn", "arn:aws:iam::123456789012:role/sre", "--ecs-cluster", "ecs", "--efs-filesystem-id", "fs-example")
	if err == nil || !strings.Contains(err.Error(), "--keycloak-url") {
		t.Fatalf("manual init inherited issuer: %v", err)
	}
}

func TestConfigInitManualPersistsExplicitYAMLBoolean(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE", "true") // bootstrap ignores the environment preference
	for _, tc := range []struct {
		name  string
		value string
		want  bool
	}{{"device", "true", true}, {"browser", "false", false}} {
		_, err := runTestCLI(t, "--use-device-code="+tc.value, "config", "init", "--name", tc.name,
			"--auto-discover=false", "--account-id", "123456789012", "--region", "us-east-1",
			"--keycloak-url", "https://auth.example.test", "--lambda-function-name", "create",
			"--invoker-role-arn", "arn:aws:iam::123456789012:role/invoker",
			"--sre-role-arn", "arn:aws:iam::123456789012:role/sre", "--ecs-cluster", "ecs", "--efs-filesystem-id", "fs-example")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "rosa-boundary", "config.yaml")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		found := false
		root := doc.Content[0].Content
		for i := 0; i+1 < len(root); i += 2 {
			if root[i].Value != "profiles" {
				continue
			}
			profiles := root[i+1].Content
			for j := 0; j+1 < len(profiles); j += 2 {
				if profiles[j].Value != tc.name {
					continue
				}
				fields := profiles[j+1].Content
				for k := 0; k+1 < len(fields); k += 2 {
					if fields[k].Value == "oidc_use_device_code" {
						value := fields[k+1]
						if value.Tag != "!!bool" || value.Value != tc.value {
							t.Fatalf("device key = %q %s; want YAML bool %s", value.Value, value.Tag, tc.value)
						}
						found = true
					}
				}
			}
		}
		if !found {
			t.Fatal("device preference omitted")
		}
	}
}

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
		name        string
		accountID   string
		project     string
		environment string
		expected    string
	}{
		{
			name:        "default dev",
			accountID:   "123456789012",
			project:     "rosa-boundary",
			environment: "dev",
			expected:    "arn:aws:iam::123456789012:role/rosa-boundary-dev-lambda-invoker",
		},
		{
			name:        "production",
			accountID:   "933409759055",
			project:     "rosa-boundary",
			environment: "prod",
			expected:    "arn:aws:iam::933409759055:role/rosa-boundary-prod-lambda-invoker",
		},
		{
			name:        "custom project",
			accountID:   "111222333444",
			project:     "my-project",
			environment: "staging",
			expected:    "arn:aws:iam::111222333444:role/my-project-staging-lambda-invoker",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveInvokerRoleARN(tt.accountID, tt.project, tt.environment)
			if got != tt.expected {
				t.Errorf("DeriveInvokerRoleARN(%q, %q, %q) = %q, want %q",
					tt.accountID, tt.project, tt.environment, got, tt.expected)
			}
		})
	}
}

func TestDeriveLambdaFunctionName(t *testing.T) {
	tests := []struct {
		name        string
		project     string
		environment string
		expected    string
	}{
		{
			name:        "default dev",
			project:     "rosa-boundary",
			environment: "dev",
			expected:    "rosa-boundary-dev-create-investigation",
		},
		{
			name:        "production",
			project:     "rosa-boundary",
			environment: "prod",
			expected:    "rosa-boundary-prod-create-investigation",
		},
		{
			name:        "custom project",
			project:     "my-project",
			environment: "staging",
			expected:    "my-project-staging-create-investigation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveLambdaFunctionName(tt.project, tt.environment)
			if got != tt.expected {
				t.Errorf("DeriveLambdaFunctionName(%q, %q) = %q, want %q",
					tt.project, tt.environment, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Contract test helpers
//
// These helpers locate and parse Terraform .tf files to extract resource
// naming patterns. Related resources can live in different modules, so each
// contract test passes the repository-root-relative path of the file it
// validates. A failure in readTerraformFile usually means a .tf file moved.
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

// readTerraformFile reads a Terraform file whose path segments are given
// relative to the repository root (e.g. "deploy", "regional", "foo.tf").
func readTerraformFile(t *testing.T, relPath ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{repoRoot(t)}, relPath...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	return string(data)
}

// extractTerraformPattern returns the quoted value of the given HCL attribute
// (e.g. "function_name" or "name"), which must begin with a ${var.<name>}
// interpolation such as "${var.role_name_prefix}-lambda-invoker".
func extractTerraformPattern(t *testing.T, content, attribute string) string {
	t.Helper()
	// Match:  attribute  =  "${var.<name>}..."
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(attribute) + `\s*=\s*"(\$\{var\.[A-Za-z_][A-Za-z0-9_]*\}[^"]*)"`)
	matches := re.FindStringSubmatch(content)
	if matches == nil {
		t.Fatalf("cannot find %s = \"${var....}...\" pattern in Terraform content", attribute)
	}
	return matches[1]
}

// expandTerraformVars replaces the Terraform ${var.project} and ${var.stage}
// tokens with the given project and environment values. The Go parameter is
// named environment even though Terraform calls the same value stage.
func expandTerraformVars(pattern, project, environment string) string {
	result := strings.ReplaceAll(pattern, "${var.project}", project)
	result = strings.ReplaceAll(result, "${var.stage}", environment)
	return result
}

// Contract: TestContractDeriveLambdaFunctionName_MatchesTerraform verifies
// that the Go derivation function produces the same name as the Terraform
// resource definition in deploy/regional/lambda-create-investigation.tf.
//
// If the Terraform naming convention changes, this test will fail — alerting
// developers that the CLI must be updated to match (or vice versa).
//
// NOTE: This test reads Terraform from deploy/regional/. Moving or renaming
// that file will break this test.
func TestContractDeriveLambdaFunctionName_MatchesTerraform(t *testing.T) {
	content := readTerraformFile(t, "deploy", "regional", "lambda-create-investigation.tf")
	pattern := extractTerraformPattern(t, content, "function_name")

	for _, tt := range []struct {
		project     string
		environment string
	}{
		{"rosa-boundary", "dev"},
		{"rosa-boundary", "prod"},
		{"custom-project", "staging"},
	} {
		expected := expandTerraformVars(pattern, tt.project, tt.environment)
		got := DeriveLambdaFunctionName(tt.project, tt.environment)
		if got != expected {
			t.Errorf("DeriveLambdaFunctionName(%q, %q) = %q, want %q (from Terraform pattern %q)",
				tt.project, tt.environment, got, expected, pattern)
		}
	}
}

// roleNamePrefixDefault returns the fallback prefix the account root module
// uses when var.role_name_prefix is unset. Resolving it from Terraform rather
// than hardcoding project-stage keeps the contract honest if that default ever
// changes.
func roleNamePrefixDefault(t *testing.T) string {
	t.Helper()
	content := readTerraformFile(t, "deploy", "account", "main.tf")
	// Match: role_name_prefix = var.role_name_prefix != "" ? var.role_name_prefix : "<default>"
	re := regexp.MustCompile(`role_name_prefix\s*=\s*var\.role_name_prefix\s*!=\s*""\s*\?\s*var\.role_name_prefix\s*:\s*"([^"]*)"`)
	matches := re.FindStringSubmatch(content)
	if matches == nil {
		t.Fatal("cannot find role_name_prefix default resolution in deploy/account/main.tf")
	}
	return matches[1]
}

// Contract: TestContractDeriveInvokerRoleARN_MatchesTerraform verifies that
// the role name suffix produced by the Go derivation function matches the
// Terraform resource naming in deploy/account/modules/shared-iam/lambda-invoker.tf.
//
// The ARN prefix (arn:aws:iam::<account>:role/) is added by the Go function
// but not present in Terraform's name attribute, so we compare only the role
// name portion.
//
// NOTE: This test reads Terraform files from deploy/account/modules/shared-iam/.
// Moving or renaming those files will break this test.
func TestContractDeriveInvokerRoleARN_MatchesTerraform(t *testing.T) {
	path := filepath.Join(repoRoot(t), "deploy", "account", "modules", "shared-iam", "lambda-invoker.tf")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	content := string(data)

	// Account-layer uses ${var.role_name_prefix} which defaults to ${var.project}-${var.stage}
	// Extract the name pattern and expand role_name_prefix
	re := regexp.MustCompile(`(?m)^\s*name\s*=\s*"(\$\{var\.role_name_prefix\}[^"]*)"`)
	matches := re.FindStringSubmatch(content)
	if matches == nil {
		t.Fatalf("cannot find name = \"${var.role_name_prefix}...\" pattern in Terraform content")
	}
	pattern := matches[1]
	// Expand ${var.role_name_prefix} to ${var.project}-${var.stage}
	pattern = strings.ReplaceAll(pattern, "${var.role_name_prefix}", "${var.project}-${var.stage}")

	// Resolve ${var.role_name_prefix} to its default so the effective pattern is
	// expressed in terms of ${var.project}/${var.stage}, which the CLI derives.
	effectivePattern := strings.ReplaceAll(pattern, "${var.role_name_prefix}", roleNamePrefixDefault(t))

	for _, tt := range []struct {
		accountID   string
		project     string
		environment string
	}{
		{"123456789012", "rosa-boundary", "dev"},
		{"933409759055", "rosa-boundary", "prod"},
		{"111222333444", "custom-project", "staging"},
	} {
		expectedRoleName := expandTerraformVars(effectivePattern, tt.project, tt.environment)
		expectedARN := "arn:aws:iam::" + tt.accountID + ":role/" + expectedRoleName

		got := DeriveInvokerRoleARN(tt.accountID, tt.project, tt.environment)
		if got != expectedARN {
			t.Errorf("DeriveInvokerRoleARN(%q, %q, %q) = %q, want %q (from Terraform pattern %q)",
				tt.accountID, tt.project, tt.environment, got, expectedARN, effectivePattern)
		}
	}
}

package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/openshift-online/rosa-boundary/internal/output"
	"github.com/spf13/cobra"
)

// Run the real root error/exit path in a child so stdout, stderr, and status
// can be checked independently. The late failures use only local test doubles.
func TestFailureJSONProcess(t *testing.T) {
	if os.Getenv("BOUNDARY_FAILURE_JSON_HELPER") != "1" {
		return
	}
	root := buildRootCommand()
	args := os.Args
	for i, arg := range args {
		if arg == "--" {
			args = args[i+1:]
			break
		}
	}
	if len(args) > 0 && args[0] == "mock-late" {
		args = args[1:]
		root.PersistentPreRunE = func(*cobra.Command, []string) error { return nil }
		for _, name := range []string{"join", "create"} {
			leaf := commandAtPath(t, root, "session", name)
			leaf.Args = commandArgs(nonEmptyArgs(1)) // Simulate a terminal in this child.
			if name == "join" {
				leaf.RunE = func(*cobra.Command, []string) error { return errors.New("mock ECS Exec connection failed; retry join") }
			} else {
				leaf.RunE = func(*cobra.Command, []string) error {
					return sessionCreationError(errors.New("mock ECS Exec connection failed"), "task-1", "cluster", "inv", "us-east-1", "ecs")
				}
			}
		}
	}
	os.Exit(executeRoot(root, args...))
}

func assertJSONFailure(t *testing.T, stdout, message string) {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(stdout))
	var got map[string]json.RawMessage
	if err := decoder.Decode(&got); err != nil {
		t.Fatalf("stdout is not failure JSON: %q: %v", stdout, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("stdout has extra data: %q: %v", stdout, err)
	}
	var failure map[string]string
	if len(got) != 1 || json.Unmarshal(got["error"], &failure) != nil || len(failure) != 2 || failure["code"] != "command_failed" || !strings.Contains(failure["message"], message) {
		t.Fatalf("unexpected failure result: %q, want message containing %q", stdout, message)
	}
}

func TestFailureJSONSubprocessContract(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		args       []string
		json       bool
	}{
		{"missing args", "missing required argument <cluster-id>", []string{"session", "create", "-o", "json"}, true},
		{"unknown flag", "unknown flag", []string{"session", "list", "--output=json", "--not-a-flag"}, true},
		{"unknown flag before format", "unknown flag", []string{"session", "list", "--not-a-flag", "-o", "json"}, true},
		{"unknown flag before shorthand equals", "unknown flag", []string{"session", "list", "--not-a-flag", "-o=json"}, true},
		{"shorthand equals before unknown flag", "unknown flag", []string{"session", "list", "-o=json", "--not-a-flag"}, true},
		{"shorthand equals after terminator", "unknown flag", []string{"session", "list", "--not-a-flag", "--", "-o=json"}, false},
		{"no profile before auth", "no active profile", []string{"session", "list", "-o", "json"}, true},
		{"invalid output", "invalid --output", []string{"session", "list", "--output=xml"}, false},
		{"invalid shorthand output", "invalid --output", []string{"session", "list", "-o=xml"}, false},
		{"text error unchanged", "missing required argument", []string{"session", "create"}, false},
		{"late join failure", "mock ECS Exec connection failed", []string{"mock-late", "session", "join", "task-id", "-o", "json"}, true},
		{"late connect failure", "session task-1 created", []string{"mock-late", "session", "create", "cluster", "--connect", "-o", "json"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-test.run=^TestFailureJSONProcess$", "--"}, tc.args...)
			process := exec.Command(os.Args[0], args...)
			process.Env = append(os.Environ(), "BOUNDARY_FAILURE_JSON_HELPER=1", "XDG_CONFIG_HOME="+t.TempDir())
			var stderr strings.Builder
			process.Stderr = &stderr
			stdout, err := process.Output()
			if err == nil {
				t.Fatalf("expected nonzero exit; stdout=%q stderr=%q", stdout, stderr.String())
			}
			if !strings.Contains(stderr.String(), "Error:") || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stderr=%q does not explain %q", stderr.String(), tc.want)
			}
			if tc.json {
				assertJSONFailure(t, string(stdout), tc.want)
				if tc.name == "late connect failure" {
					if !strings.Contains(string(stdout), "session close") || !strings.Contains(stderr.String(), "session close") {
						t.Fatalf("created session cleanup guidance missing: stdout=%q stderr=%q", stdout, stderr.String())
					}
				}
			} else if len(stdout) != 0 {
				t.Fatalf("invalid format unexpectedly produced stdout: %q", stdout)
			}
		})
	}
}

type brokenWriter struct{ writes int }

func (w *brokenWriter) Write([]byte) (int, error) {
	w.writes++
	return 0, errors.New("output unavailable")
}

func TestFailedJSONResultWriteDoesNotEmitFailureJSON(t *testing.T) {
	root := buildRootCommand()
	root.SetArgs([]string{"login", "-o", "json"})
	root.PersistentPreRunE = func(*cobra.Command, []string) error { return nil }
	login := commandAtPath(t, root, "login")
	w := &brokenWriter{}
	login.SetOut(w)
	login.RunE = func(cmd *cobra.Command, _ []string) error {
		return output.JSONTo(cmd.OutOrStdout(), map[string]string{"authenticated": "true"})
	}
	if status := executeRoot(root); status == 0 || w.writes != 1 {
		t.Fatalf("failed JSON write was swallowed or retried: status=%d writes=%d", status, w.writes)
	}
}

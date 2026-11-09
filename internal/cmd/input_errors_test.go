package cmd

import (
	"strings"
	"testing"
)

func TestCLIInputErrorsAreActionableBeforeAuthentication(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, tc := range []struct {
		name                    string
		args                    []string
		command, syntax, detail string
	}{
		{"root unknown", []string{"unknown"}, "rosa-boundary", "rosa-boundary", "unknown"},
		{"config unknown", []string{"config", "unknown"}, "rosa-boundary config", "rosa-boundary config", "unknown"},
		{"investigation unknown", []string{"investigation", "unknown"}, "rosa-boundary investigation", "rosa-boundary investigation", "unknown"},
		{"session unknown", []string{"session", "unknown"}, "rosa-boundary session", "rosa-boundary session", "unknown"},
		{"credentials unknown", []string{"session", "credentials", "unknown"}, "rosa-boundary session credentials", "rosa-boundary session credentials", "unknown"},
		{"configure unknown", []string{"session", "credentials", "configure", "unknown"}, "rosa-boundary session credentials configure", "rosa-boundary session credentials configure", "unknown"},
		{"clear unknown", []string{"session", "credentials", "clear", "unknown"}, "rosa-boundary session credentials clear", "rosa-boundary session credentials clear", "unknown"},
		{"config use-profile missing", []string{"config", "use-profile"}, "rosa-boundary config use-profile", "use-profile <name>", "missing required argument <name>"},
		{"investigation create missing", []string{"investigation", "create"}, "rosa-boundary investigation create", "create <cluster-id>", "missing required argument <cluster-id>"},
		{"investigation close first missing", []string{"investigation", "close"}, "rosa-boundary investigation close", "close <cluster-id> <investigation-id>", "missing required argument <cluster-id>"},
		{"investigation close second missing", []string{"investigation", "close", "cluster"}, "rosa-boundary investigation close", "close <cluster-id> <investigation-id>", "missing required argument <investigation-id>"},
		{"session create missing", []string{"session", "create"}, "rosa-boundary session create", "create <cluster-id>", "missing required argument <cluster-id>"},
		{"session join missing", []string{"session", "join"}, "rosa-boundary session join", "join <session-id>", "missing required argument <session-id>"},
		{"session close missing", []string{"session", "close"}, "rosa-boundary session close", "close <session-id>", "missing required argument <session-id>"},
		{"configure ocm empty ID", []string{"session", "credentials", "configure", "ocm", ""}, "rosa-boundary session credentials configure ocm", "ocm [session-id]", "<session-id> must not be empty"},
		{"clear ocm empty ID", []string{"session", "credentials", "clear", "ocm", ""}, "rosa-boundary session credentials clear ocm", "ocm [session-id]", "<session-id> must not be empty"},
		{"root extra", []string{"version", "extra"}, "rosa-boundary version", "rosa-boundary version", "unknown"},
		{"config extra", []string{"config", "init", "extra"}, "rosa-boundary config init", "rosa-boundary config init", "unknown"},
		{"config list-profiles extra", []string{"config", "list-profiles", "extra"}, "rosa-boundary config list-profiles", "rosa-boundary config list-profiles", "unknown"},
		{"config get extra", []string{"config", "get", "key", "extra"}, "rosa-boundary config get", "get [key]", "at most 1"},
		{"config use-profile extra", []string{"config", "use-profile", "profile", "extra"}, "rosa-boundary config use-profile", "use-profile <name>", "unexpected argument"},
		{"config use-profile empty", []string{"config", "use-profile", ""}, "rosa-boundary config use-profile", "use-profile <name>", "arguments must not be empty"},
		{"investigation create extra", []string{"investigation", "create", "cluster", "extra"}, "rosa-boundary investigation create", "create <cluster-id>", "unexpected argument"},
		{"investigation list extra", []string{"investigation", "list", "extra"}, "rosa-boundary investigation list", "rosa-boundary investigation list", "unknown"},
		{"investigation close extra", []string{"investigation", "close", "cluster", "inv", "extra"}, "rosa-boundary investigation close", "close <cluster-id> <investigation-id>", "unexpected argument"},
		{"session create extra", []string{"session", "create", "cluster", "extra"}, "rosa-boundary session create", "create <cluster-id>", "unexpected argument"},
		{"session list extra", []string{"session", "list", "extra"}, "rosa-boundary session list", "rosa-boundary session list", "unknown"},
		{"session join extra", []string{"session", "join", "task", "extra"}, "rosa-boundary session join", "join <session-id>", "unexpected argument"},
		{"session close extra", []string{"session", "close", "task", "extra"}, "rosa-boundary session close", "close <session-id>", "unexpected argument"},
		{"configure ocm extra", []string{"session", "credentials", "configure", "ocm", "task", "extra"}, "rosa-boundary session credentials configure ocm", "ocm [session-id]", "unexpected argument"},
		{"clear ocm extra", []string{"session", "credentials", "clear", "ocm", "task", "extra"}, "rosa-boundary session credentials clear ocm", "ocm [session-id]", "unexpected argument"},
		{"unknown flag", []string{"session", "create", "cluster", "--bad-flag"}, "rosa-boundary session create", "create <cluster-id>", "unknown flag"},
		{"missing flag value", []string{"investigation", "list", "--cluster-id"}, "rosa-boundary investigation list", "rosa-boundary investigation list", "flag needs an argument"},
		{"invalid duration", []string{"session", "create", "cluster", "--session-timeout=invalid"}, "rosa-boundary session create", "create <cluster-id>", "must be a duration"},
		{"invalid bool", []string{"login", "--use-device-code=invalid"}, "rosa-boundary login", "rosa-boundary login", "invalid"},
		{"invalid output", []string{"session", "list", "-o", "xml"}, "rosa-boundary session list", "rosa-boundary session list", "invalid --output"},
		{"invalid status", []string{"session", "list", "--status", "bad"}, "rosa-boundary session list", "rosa-boundary session list", "invalid --status"},
		{"invalid auth flow", []string{"session", "credentials", "configure", "ocm", "task", "--auth-flow", "bad"}, "rosa-boundary session credentials configure ocm", "ocm [session-id]", "invalid --auth-flow"},
		{"invalid auth flow without ID", []string{"session", "credentials", "configure", "ocm", "--auth-flow", "bad"}, "rosa-boundary session credentials configure ocm", "ocm [session-id]", "invalid --auth-flow"},
		{"empty auth flow without ID", []string{"session", "credentials", "configure", "ocm", "--auth-flow="}, "rosa-boundary session credentials configure ocm", "ocm [session-id]", "invalid --auth-flow"},
		{"invalid OCM URL without ID", []string{"session", "credentials", "configure", "ocm", "--ocm-url", "not-an-environment"}, "rosa-boundary session credentials configure ocm", "ocm [session-id]", "not-an-environment"},
		{"invalid credentials", []string{"session", "create", "cluster", "--with-credentials", "bad"}, "rosa-boundary session create", "create <cluster-id>", "unsupported credential provider"},
		{"invalid timeout", []string{"login", "--timeout", "0s"}, "rosa-boundary login", "rosa-boundary login", "--timeout must be greater than zero"},
		{"config init invalid account", []string{"config", "init", "--auto-discover=false", "--name", "test", "--account-id", "invalid", "--region", "us-east-1", "--keycloak-url", "https://auth.example.com", "--lambda-function-name", "create", "--invoker-role-arn", "arn:aws:iam::123456789012:role/invoker", "--sre-role-arn", "arn:aws:iam::123456789012:role/sre", "--ecs-cluster", "ecs", "--efs-filesystem-id", "fs-test"}, "rosa-boundary config init", "rosa-boundary config init", "--account-id must be a 12-digit"},
		{"config init conflicting flags", []string{"config", "init", "--yes"}, "rosa-boundary config init", "rosa-boundary config init", "--yes requires --overwrite"},
		{"config init unknown flag", []string{"config", "init", "--unknown"}, "rosa-boundary config init", "rosa-boundary config init", "unknown flag"},
		{"invalid ocm url", []string{"session", "create", "cluster", "--with-credentials", "ocm", "--ocm-url", "not-an-environment"}, "rosa-boundary session create", "create <cluster-id>", "not-an-environment"},
		{"empty cluster", []string{"investigation", "create", ""}, "rosa-boundary investigation create", "create <cluster-id>", "arguments must not be empty"},
		{"old start", []string{"session", "start", "cluster"}, "rosa-boundary session", "rosa-boundary session", "session create <cluster-id>"},
		{"old stop", []string{"session", "stop", "task"}, "rosa-boundary session", "rosa-boundary session", "session close <session-id>"},
		{"old config list", []string{"config", "list"}, "rosa-boundary config", "rosa-boundary config", "config list-profiles"},
		{"old config use", []string{"config", "use", "profile"}, "rosa-boundary config", "rosa-boundary config", "config use-profile <name>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, err := runTestCLI(t, tc.args...)
			if err == nil {
				t.Fatalf("%v succeeded: stdout %q", tc.args, stdout)
			}
			for _, want := range []string{tc.detail, "Usage: " + tc.command, tc.syntax, "Run '" + tc.command + " --help'"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%v: error %q missing %q", tc.args, err, want)
				}
			}
			if strings.Contains(err.Error(), "no active profile") || strings.Contains(err.Error(), "authentication failed") {
				t.Errorf("input error reached authentication/profile resolution: %v", err)
			}
			if stdout != "" || strings.Contains(err.Error(), "Available Commands:") || strings.Contains(err.Error(), "Flags:") {
				t.Errorf("input error dumped help instead of a concise hint: stdout %q, error %v", stdout, err)
			}
		})
	}
}

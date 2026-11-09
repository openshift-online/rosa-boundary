package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/openshift-online/rosa-boundary/internal/config"
)

func TestConfigListNoProfiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{name: "missing file"},
		{name: "empty profiles", data: "profiles: {}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", dir)
			if tc.data != "" {
				path := filepath.Join(dir, "rosa-boundary", "config.yaml")
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := runTestCLI(t, "config", "list-profiles")
			if err != nil {
				t.Fatal(err)
			}
			if got != "No profiles found. Run 'rosa-boundary config init --help' to create one.\n" {
				t.Fatalf("config list-profiles = %q", got)
			}
		})
	}
}

func TestConfigListMalformedConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	path := filepath.Join(dir, "rosa-boundary", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("profiles: [not-a-mapping]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := runTestCLI(t, "config", "list-profiles")
	if err == nil || !strings.Contains(err.Error(), "profiles must be a mapping") {
		t.Fatalf("config list-profiles error = %v", err)
	}
	if got != "" {
		t.Fatalf("malformed config produced stdout: %q", got)
	}
}

func TestConfigListSavedProfilesOffline(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// These profiles have no issuer, roles or credentials: listing must not authenticate.
	for _, tc := range []struct {
		name    string
		profile config.Config
		active  bool
	}{
		{"zeta", config.Config{AccountID: "123456789012", Environment: "prod", AWSRegion: "us-east-1"}, true},
		{"alpha", config.Config{AccountID: "210987654321", Environment: "stage", AWSRegion: "eu-west-1"}, false},
	} {
		if err := saveTestProfile(tc.name, tc.profile, tc.active, false); err != nil {
			t.Fatal(err)
		}
	}
	// Runtime overrides must not replace saved values shown in the table.
	t.Setenv("ROSA_BOUNDARY_ACCOUNT_ID", "999999999999")
	t.Setenv("ROSA_BOUNDARY_ENVIRONMENT", "override")
	t.Setenv("ROSA_BOUNDARY_AWS_REGION", "override")
	got, err := runTestCLI(t, "config", "list-profiles")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	want := [][]string{
		{"ACTIVE", "PROFILE", "ACCOUNT", "ID", "ENVIRONMENT", "REGION"},
		{"------", "-------", "----------", "-----------", "------"},
		{"alpha", "210987654321", "stage", "eu-west-1"},
		{"*", "zeta", "123456789012", "prod", "us-east-1"},
	}
	if len(lines) != len(want) {
		t.Fatalf("config list-profiles lines = %q", got)
	}
	for i, line := range lines {
		if fields := strings.Fields(line); !reflect.DeepEqual(fields, want[i]) {
			t.Errorf("line %d fields = %q, want %q", i, fields, want[i])
		}
	}
}

func TestConfigUseProfileOfflineSavedConfirmation(t *testing.T) {
	// No OIDC issuer or roles are saved; a successful selection must not authenticate.
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	for _, tc := range []struct {
		name    string
		profile config.Config
	}{
		{"first", config.Config{AccountID: "123456789012", AWSRegion: "us-east-1"}},
		{"second", config.Config{AccountID: "210987654321", AWSRegion: "eu-west-1"}},
	} {
		if err := saveTestProfile(tc.name, tc.profile, false, false); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("ROSA_BOUNDARY_ACCOUNT_ID", "999999999999")
	t.Setenv("ROSA_BOUNDARY_AWS_REGION", "override")
	got, err := runTestCLI(t, "config", "use-profile", "second")
	if err != nil || got != "Active profile: second\nAWS account ID: 210987654321\nAWS region: eu-west-1\n" {
		t.Fatalf("selection confirmation = %q, error = %v", got, err)
	}
	file, err := config.LoadProfiles()
	if err != nil || file.ActiveProfile != "second" {
		t.Fatalf("saved selection = %+v, error = %v", file, err)
	}
	info, err := os.Stat(filepath.Join(dir, "rosa-boundary", "config.yaml"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config file mode = %v, error = %v", info, err)
	}

	for _, args := range [][]string{{"config", "use-profile", "missing"}, {"--profile", "first", "config", "use-profile", "second"}} {
		got, err := runTestCLI(t, args...)
		if err == nil || got != "" {
			t.Fatalf("%v: stdout = %q, error = %v", args, got, err)
		}
		if args[0] == "config" && (!strings.Contains(err.Error(), "config list-profiles") || !strings.Contains(err.Error(), "config use-profile")) {
			t.Errorf("unknown profile recovery = %v", err)
		}
		file, err := config.LoadProfiles()
		if err != nil || file.ActiveProfile != "second" {
			t.Fatalf("failed selection changed active profile: %+v, %v", file, err)
		}
	}
}

func TestConfigUseProfileMissingAndMalformed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	for _, data := range []string{"", "profiles: {}\n"} {
		path := filepath.Join(dir, "rosa-boundary", "config.yaml")
		if data != "" {
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		got, err := runTestCLI(t, "config", "use-profile", "missing")
		if err == nil || !strings.Contains(err.Error(), "unknown profile") || got != "" {
			t.Fatalf("empty config %q selection = %q, %v", data, got, err)
		}
	}
	path := filepath.Join(dir, "rosa-boundary", "config.yaml")
	data := []byte("profiles: [not-a-mapping]\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := runTestCLI(t, "config", "use-profile", "missing")
	if err == nil || !strings.Contains(err.Error(), "profiles must be a mapping") || got != "" {
		t.Fatalf("malformed selection = %q, %v", got, err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != string(data) {
		t.Fatalf("malformed config modified: %q, %v", actual, err)
	}
}

func TestConfigProfileHelpAndOldVerbMigration(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, tc := range []struct{ old, replacement string }{
		{"list", "list-profiles"},
		{"use", "use-profile <name>"},
	} {
		got, err := runTestCLI(t, "config", tc.old)
		if err == nil || got != "" || !strings.Contains(err.Error(), "no longer supported") || !strings.Contains(err.Error(), "config "+tc.replacement) {
			t.Errorf("config %s: stdout %q, error %v", tc.old, got, err)
		}
	}
	for _, tc := range []struct{ verb, syntax string }{
		{"list-profiles", "list-profiles"},
		{"use-profile", "use-profile <name>"},
	} {
		got, err := runTestCLI(t, "config", tc.verb, "--help")
		if err != nil || !strings.Contains(got, tc.syntax) || strings.Contains(got, "config list\n") || strings.Contains(got, "config use <name>") {
			t.Errorf("config %s help = %q, error %v", tc.verb, got, err)
		}
	}
}

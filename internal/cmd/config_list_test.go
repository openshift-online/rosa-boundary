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
			got, err := runTestCLI(t, "config", "list")
			if err != nil {
				t.Fatal(err)
			}
			if got != "No profiles found. Run 'rosa-boundary config init --help' to create one.\n" {
				t.Fatalf("config list = %q", got)
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
	got, err := runTestCLI(t, "config", "list")
	if err == nil || !strings.Contains(err.Error(), "profiles must be a mapping") {
		t.Fatalf("config list error = %v", err)
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
	got, err := runTestCLI(t, "config", "list")
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
		t.Fatalf("config list lines = %q", got)
	}
	for i, line := range lines {
		if fields := strings.Fields(line); !reflect.DeepEqual(fields, want[i]) {
			t.Errorf("line %d fields = %q, want %q", i, fields, want[i])
		}
	}
}

package config

import (
	"path/filepath"
	"testing"
)

func TestProfileOCMURLRoundTripAndPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	file := &ProfilesFile{ActiveProfile: "prod", Profiles: map[string]Profile{
		"prod": {OCMURL: "production"}, "dev": {OCMURL: "staging"}, "legacy": {},
	}}
	if err := WriteProfiles(path, file); err != nil {
		t.Fatal(err)
	}
	file, err := ReadProfiles(path)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := file.SavedValue("dev", "ocm_url"); err != nil || value != "staging" {
		t.Fatalf("saved = %v, %v", value, err)
	}
	for _, tc := range []struct{ name, profile, env, flag, want string }{
		{"selected", "dev", "", "", "staging"},
		{"active", "", "", "", "production"},
		{"legacy", "legacy", "", "", ""},
		{"environment", "dev", "integration", "", "integration"},
		{"flag", "dev", "integration", "production", "production"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := map[string]string{}
			if tc.flag != "" {
				flags["ocm_url"] = tc.flag
			}
			_, cfg, err := file.ResolveProfile(tc.profile, flags, func(key string) (string, bool) { return tc.env, key == "ROSA_BOUNDARY_OCM_URL" && tc.env != "" })
			if err != nil || cfg.OCMURL != tc.want {
				t.Fatalf("resolved = %+v, %v", cfg, err)
			}
		})
	}
}

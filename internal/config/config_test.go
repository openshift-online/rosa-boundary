package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOIDCUseDeviceCodePrecedence(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		env      string
		envSet   bool
		flag     string
		expected bool
		errText  string
	}{
		{name: "profile without preference", expected: false},
		{name: "file without key", file: "oidc_client_id: old-client\n", expected: false},
		{name: "file true", file: "oidc_use_device_code: true\n", expected: true},
		{name: "file false", file: "oidc_use_device_code: false\n", expected: false},
		{name: "env true over file false", file: "oidc_use_device_code: false\n", env: "true", expected: true},
		{name: "env false over file true", file: "oidc_use_device_code: true\n", env: "false", expected: false},
		{name: "explicit flag false over env true", file: "oidc_use_device_code: true\n", env: "true", flag: "false", expected: false},
		{name: "explicit flag true over env false", file: "oidc_use_device_code: false\n", env: "false", flag: "true", expected: true},
		{name: "invalid env", env: "not-a-bool", errText: "ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE"},
		{name: "empty env", envSet: true, file: "oidc_use_device_code: true\n", errText: "ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE"},
		{name: "invalid env over file", file: "oidc_use_device_code: true\n", env: "not-a-bool", errText: "ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE"},
		{name: "invalid file", file: "oidc_use_device_code: unexpected\n", errText: "oidc_use_device_code"},
		{name: "quoted boolean rejected", file: "oidc_use_device_code: 'true'\n", errText: "YAML boolean"},
		{name: "integer rejected", file: "oidc_use_device_code: 1\n", errText: "oidc_use_device_code"},
		{name: "null rejected", file: "oidc_use_device_code: null\n", errText: "oidc_use_device_code"},
		{name: "invalid file not overridden by env", file: "oidc_use_device_code: unexpected\n", env: "true", errText: "oidc_use_device_code"},
		{name: "invalid env overridden by explicit flag", env: "not-a-bool", flag: "false", expected: false},
		{name: "empty env overridden by explicit flag", envSet: true, flag: "false", expected: false},
		{name: "null file not overridden by explicit flag", file: "oidc_use_device_code: null\n", flag: "true", errText: "oidc_use_device_code"},
		{name: "invalid file not overridden by explicit flag", file: "oidc_use_device_code: unexpected\n", flag: "false", errText: "oidc_use_device_code"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := tt.file
			if file == "" {
				file = "oidc_client_id: client\n"
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			file = "active_profile: stage\nprofiles:\n  stage:\n    " + strings.ReplaceAll(strings.TrimSuffix(file, "\n"), "\n", "\n    ") + "\n"
			if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
				t.Fatal(err)
			}
			profiles, err := ReadProfiles(path)
			if err != nil {
				if tt.errText != "" && strings.Contains(err.Error(), tt.errText) {
					return
				}
				t.Fatal(err)
			}
			if tt.env != "" || tt.envSet {
				t.Setenv("ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE", tt.env)
			}
			flags := map[string]string{}
			if tt.flag != "" {
				flags["oidc_use_device_code"] = tt.flag
			}
			_, cfg, err := profiles.ResolveProfile("stage", flags, nil)
			if tt.errText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errText) {
					t.Fatalf("ResolveProfile() error = %v, want substring %q", err, tt.errText)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.OIDCUseDeviceCode != tt.expected {
				t.Fatalf("OIDCUseDeviceCode = %t, want %t", cfg.OIDCUseDeviceCode, tt.expected)
			}
		})
	}
}

func TestWriteProfilesTypedBoolean(t *testing.T) {
	for _, value := range []bool{false, true} {
		t.Run(map[bool]string{false: "false", true: "true"}[value], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			profiles := &ProfilesFile{ActiveProfile: "stage", Profiles: map[string]Profile{
				"stage": {KeycloakURL: "https://example.test", OIDCUseDeviceCode: &value, OIDCClientID: "false"},
			}}
			if err := WriteProfiles(path, profiles); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "aws_region:") || !strings.Contains(string(data), "profiles:") {
				t.Fatalf("unexpected config content: %s", data)
			}
			var doc yaml.Node
			if err := yaml.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			var fields []*yaml.Node
			root := doc.Content[0].Content
			for i := 0; i < len(root); i += 2 {
				if root[i].Value == "profiles" {
					fields = root[i+1].Content[1].Content
				}
			}
			if fields == nil {
				t.Fatal("missing stage profile")
			}
			foundBool, foundString := false, false
			for i := 0; i < len(fields); i += 2 {
				switch fields[i].Value {
				case "oidc_use_device_code":
					foundBool = true
					if fields[i+1].Tag != "!!bool" || fields[i+1].Value != map[bool]string{false: "false", true: "true"}[value] {
						t.Fatalf("boolean node = %s %q", fields[i+1].Tag, fields[i+1].Value)
					}
				case "oidc_client_id":
					foundString = true
					if fields[i+1].Tag != "!!str" {
						t.Fatalf("string node tag = %s, want !!str", fields[i+1].Tag)
					}
				}
			}
			if !foundBool || !foundString {
				t.Fatalf("expected saved boolean and string nodes: %s", data)
			}
		})
	}
}

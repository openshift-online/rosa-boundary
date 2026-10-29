package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
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
		{name: "missing old config", expected: false},
		{name: "old config without key", file: "oidc_client_id: old-client\n", expected: false},
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
		{name: "invalid file overridden by env", file: "oidc_use_device_code: unexpected\n", env: "true", expected: true},
		{name: "invalid env overridden by explicit flag", env: "not-a-bool", flag: "false", expected: false},
		{name: "empty env overridden by explicit flag", envSet: true, flag: "false", expected: false},
		{name: "null file overridden by explicit flag", file: "oidc_use_device_code: null\n", flag: "true", expected: true},
		{name: "invalid file overridden by explicit flag", file: "oidc_use_device_code: unexpected\n", flag: "false", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			if tt.file != "" {
				path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "rosa-boundary")
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "config.yaml"), []byte(tt.file), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tt.env != "" || tt.envSet {
				t.Setenv("ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE", tt.env)
			}
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			flags.Bool("use-device-code", false, "")
			if tt.flag != "" {
				if err := flags.Set("use-device-code", tt.flag); err != nil {
					t.Fatal(err)
				}
			}
			if err := viper.BindPFlag("oidc_use_device_code", flags.Lookup("use-device-code")); err != nil {
				t.Fatal(err)
			}
			if err := Load(); err != nil {
				t.Fatal(err)
			}
			cfg, err := Get(flags.Lookup("use-device-code").Changed)
			if tt.errText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errText) {
					t.Fatalf("Get() error = %v, want substring %q", err, tt.errText)
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

func TestWriteConfigFileTypedBoolean(t *testing.T) {
	for _, value := range []bool{false, true} {
		t.Run(map[bool]string{false: "false", true: "true"}[value], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			entries := []ConfigEntry{
				{Key: "keycloak_url", Value: "https://example.test", Comment: "OIDC URL"},
				{Key: "oidc_use_device_code", BoolValue: &value, Comment: "Device approval"},
				{Key: "empty", Value: ""},
				{Key: "string_false", Value: "false"},
			}
			if err := WriteConfigFile(path, entries); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "empty:") || !strings.Contains(string(data), "# Device approval") {
				t.Fatalf("unexpected config content: %s", data)
			}
			var doc yaml.Node
			if err := yaml.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			fields := doc.Content[0].Content
			for i := 0; i < len(fields); i += 2 {
				switch fields[i].Value {
				case "oidc_use_device_code":
					if fields[i+1].Tag != "!!bool" || fields[i+1].Value != map[bool]string{false: "false", true: "true"}[value] {
						t.Fatalf("boolean node = %s %q", fields[i+1].Tag, fields[i+1].Value)
					}
				case "string_false":
					if fields[i+1].Tag != "!!str" {
						t.Fatalf("string node tag = %s, want !!str", fields[i+1].Tag)
					}
				}
			}
		})
	}
}

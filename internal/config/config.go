package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config holds all configuration values for the CLI.
type Config struct {
	AccountID          string `mapstructure:"account_id"`
	Environment        string `mapstructure:"environment"`
	Project            string `mapstructure:"project"`
	LambdaFunctionName string `mapstructure:"lambda_function_name"`
	KeycloakURL        string `mapstructure:"keycloak_url"`
	KeycloakRealm      string `mapstructure:"keycloak_realm"`
	OIDCClientID       string `mapstructure:"oidc_client_id"`
	OIDCUseDeviceCode  bool   `mapstructure:"oidc_use_device_code"`
	AWSRegion          string `mapstructure:"aws_region"`
	ClusterName        string `mapstructure:"ecs_cluster_name"`
	SRERoleARN         string `mapstructure:"sre_role_arn"`
	InvokerRoleARN     string `mapstructure:"invoker_role_arn"`
	EFSFilesystemID    string `mapstructure:"efs_filesystem_id"`
}

// ConfigDir returns the XDG config directory for rosa-boundary,
// creating it if it does not exist.
func ConfigDir() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		base = filepath.Join(home, ".config")
	}
	dir := filepath.Join(base, "rosa-boundary")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("cannot create config directory %s: %w", dir, err)
	}
	return dir, nil
}

// CacheDir returns the XDG cache directory for rosa-boundary,
// creating it if it does not exist.
func CacheDir() (string, error) {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		base = filepath.Join(home, ".cache")
	}
	dir := filepath.Join(base, "rosa-boundary")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("cannot create cache directory %s: %w", dir, err)
	}
	return dir, nil
}

// Load validates the profile file without resolving environment values or defaults.
func Load() error {
	_, err := LoadProfiles()
	return err
}

// Get resolves the active saved profile. The optional flagChanged argument
// forwards the current viper-bound --use-device-code flag, if explicitly set.
// New command handlers should use ResolveProfile with their explicit flags.
func Get(flagChanged ...bool) (*Config, error) {
	flags := map[string]string{}
	if len(flagChanged) != 0 && flagChanged[0] {
		flags["oidc_use_device_code"] = strconv.FormatBool(viper.GetBool("oidc_use_device_code"))
	}
	_, cfg, err := ResolveWithFlags("", flags)
	return cfg, err
}

// ConfigEntry represents a configuration key-value pair with an optional comment.
type ConfigEntry struct {
	Key       string
	Value     string
	BoolValue *bool  // If set, writes a YAML boolean (including false) instead of Value
	Comment   string // Written as a YAML comment above the key
}

// WriteConfigFile writes configuration entries to a YAML config file.
// Each entry may include a comment that is written above the key.
// Values are properly quoted/escaped by the YAML encoder.
// Empty string values are omitted; BoolValue entries are always written.
func WriteConfigFile(path string, entries []ConfigEntry) error {
	doc := &yaml.Node{Kind: yaml.DocumentNode}
	mapping := &yaml.Node{Kind: yaml.MappingNode}
	doc.Content = append(doc.Content, mapping)

	wroteEntry := false
	for _, e := range entries {
		if e.BoolValue == nil && e.Value == "" {
			continue
		}

		keyNode := &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: e.Key,
		}
		if e.Comment != "" {
			comment := e.Comment
			if wroteEntry {
				// Add a blank line before this comment block by prefixing with newline
				comment = "\n" + comment
			}
			keyNode.HeadComment = comment
		}

		valNode := &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: e.Value,
		}
		if e.BoolValue != nil {
			valNode.Tag = "!!bool"
			valNode.Value = strconv.FormatBool(*e.BoolValue)
		}

		mapping.Content = append(mapping.Content, keyNode, valNode)
		wroteEntry = true
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("cannot encode config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("cannot encode config: %w", err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("cannot write config file: %w", err)
	}
	return nil
}

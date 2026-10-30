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

// Load reads configuration from file, env vars, and applies defaults.
// Flag values are not applied here — callers bind pflags to viper before calling Get().
func Load() error {
	// Compiled defaults
	viper.SetDefault("keycloak_url", "https://auth.redhat.com/auth")
	viper.SetDefault("keycloak_realm", "EmployeeIDP")
	viper.SetDefault("oidc_client_id", "rosa-boundary-sre")
	viper.SetDefault("oidc_use_device_code", false)
	viper.SetDefault("aws_region", "us-east-2")
	viper.SetDefault("ecs_cluster_name", "rosa-boundary-dev")

	// Config file
	configDir, err := ConfigDir()
	if err != nil {
		return err
	}
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configDir)
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("error reading config file: %w", err)
		}
	}

	// Environment variables — ROSA_BOUNDARY_* prefix (canonical)
	viper.SetEnvPrefix("ROSA_BOUNDARY")
	viper.AutomaticEnv()

	// Legacy env var aliases (without prefix) for backward compat
	bindEnvAlias("lambda_function_name", "LAMBDA_FUNCTION_NAME")
	bindEnvAlias("keycloak_url", "KEYCLOAK_URL")
	bindEnvAlias("keycloak_realm", "KEYCLOAK_REALM")
	bindEnvAlias("oidc_client_id", "OIDC_CLIENT_ID")
	bindEnvAlias("aws_region", "AWS_REGION")
	bindEnvAlias("sre_role_arn", "SRE_ROLE_ARN")
	bindEnvAlias("invoker_role_arn", "INVOKER_ROLE_ARN")
	bindEnvAlias("efs_filesystem_id", "EFS_FILESYSTEM_ID")

	return nil
}

// bindEnvAlias binds a legacy environment variable name as a fallback for a viper key.
// Viper AutomaticEnv handles ROSA_BOUNDARY_<KEY>; this adds the un-prefixed legacy name.
func bindEnvAlias(key, envVar string) {
	// Only bind if the prefixed version is not already set
	if val := os.Getenv(envVar); val != "" {
		if !viper.IsSet(key) {
			viper.SetDefault(key, val)
		}
	}
}

// Get returns the current configuration. The optional flagChanged argument
// indicates an explicit CLI override, which takes precedence even over an
// invalid lower-priority environment or config-file preference.
func Get(flagChanged ...bool) (*Config, error) {
	flagOverrides := len(flagChanged) != 0 && flagChanged[0]
	if env, set := os.LookupEnv("ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE"); set && env == "" && !flagOverrides {
		return nil, fmt.Errorf("ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE must be a boolean (true or false)")
	}

	// Viper treats an explicit YAML null as an absent setting and silently
	// substitutes the default. An explicit but empty preference is invalid.
	_, envOverridesFile := os.LookupEnv("ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE")
	if path := viper.ConfigFileUsed(); path != "" && !envOverridesFile && !flagOverrides {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("cannot read config file: %w", err)
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("cannot decode config file: %w", err)
		}
		if len(doc.Content) != 0 && doc.Content[0].Kind == yaml.MappingNode {
			fields := doc.Content[0].Content
			for i := 0; i+1 < len(fields); i += 2 {
				if fields[i].Value == "oidc_use_device_code" && fields[i+1].Tag == "!!null" {
					return nil, fmt.Errorf("oidc_use_device_code must be a YAML boolean (true or false)")
				}
			}
		}
	}

	// Viper's default weak decoding can silently coerce malformed boolean
	// values. Check the effective source before unmarshalling so an invalid
	// preference never accidentally selects the browser login flow.
	value := viper.Get("oidc_use_device_code")
	var useDeviceCode bool
	switch v := value.(type) {
	case bool:
		useDeviceCode = v
	case string:
		// Environment variables are strings; YAML config values must instead
		// be real booleans, not quoted strings or numbers.
		if _, set := os.LookupEnv("ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE"); !set {
			return nil, fmt.Errorf("oidc_use_device_code must be a YAML boolean (true or false)")
		}
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE must be a boolean (true or false): %w", err)
		}
		useDeviceCode = parsed
	default:
		return nil, fmt.Errorf("oidc_use_device_code must be a boolean (true or false), got %T", value)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("cannot decode config: %w", err)
	}
	cfg.OIDCUseDeviceCode = useDeviceCode
	return &cfg, nil
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

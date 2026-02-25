package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config holds all configuration values for the CLI.
type Config struct {
	LambdaURL          string `mapstructure:"lambda_url"`
	LambdaFunctionName string `mapstructure:"lambda_function_name"`
	KeycloakURL        string `mapstructure:"keycloak_url"`
	KeycloakRealm      string `mapstructure:"keycloak_realm"`
	OIDCClientID       string `mapstructure:"oidc_client_id"`
	AWSRegion          string `mapstructure:"aws_region"`
	ClusterName        string `mapstructure:"cluster_name"`
	SRERoleARN         string `mapstructure:"sre_role_arn"`
	InvokerRoleARN     string `mapstructure:"invoker_role_arn"`
}

// Load reads configuration from file, env vars, and applies defaults.
// Flag values are not applied here — callers bind pflags to viper before calling Get().
func Load() error {
	// Compiled defaults
	viper.SetDefault("keycloak_realm", "sre-ops")
	viper.SetDefault("oidc_client_id", "aws-sre-access")
	viper.SetDefault("aws_region", "us-east-2")
	viper.SetDefault("cluster_name", "rosa-boundary-dev")

	// Config file
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	configDir := filepath.Join(home, ".rosa-boundary")
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
	bindEnvAlias("lambda_url", "LAMBDA_URL")
	bindEnvAlias("lambda_function_name", "LAMBDA_FUNCTION_NAME")
	bindEnvAlias("keycloak_url", "KEYCLOAK_URL")
	bindEnvAlias("keycloak_realm", "KEYCLOAK_REALM")
	bindEnvAlias("oidc_client_id", "OIDC_CLIENT_ID")
	bindEnvAlias("aws_region", "AWS_REGION")
	bindEnvAlias("sre_role_arn", "SRE_ROLE_ARN")
	bindEnvAlias("invoker_role_arn", "INVOKER_ROLE_ARN")

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

// Get returns the current configuration.
func Get() (*Config, error) {
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("cannot decode config: %w", err)
	}
	return &cfg, nil
}

// CacheDir returns the path to the rosa-boundary cache/config directory,
// creating it if it does not exist.
func CacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".rosa-boundary")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("cannot create cache directory %s: %w", dir, err)
	}
	return dir, nil
}

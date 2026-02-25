package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/openshift/rosa-boundary/internal/config"
)

var (
	// Version is set at build time via -ldflags.
	Version = "dev"

	verbose bool
)

// rootCmd is the base command.
var rootCmd = &cobra.Command{
	Use:   "rosa-boundary",
	Short: "CLI for managing ROSA/AWS SRE investigations",
	Long: `rosa-boundary is a CLI tool for managing ephemeral SRE investigations
on AWS Fargate with OIDC-authenticated access control.`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose/debug output")
	rootCmd.PersistentFlags().String("lambda-url", "", "Lambda function URL")
	rootCmd.PersistentFlags().String("keycloak-url", "", "Keycloak base URL")
	rootCmd.PersistentFlags().String("realm", "", "Keycloak realm (default: sre-ops)")
	rootCmd.PersistentFlags().String("client-id", "", "OIDC client ID (default: aws-sre-access)")
	rootCmd.PersistentFlags().String("region", "", "AWS region (default: us-east-2)")
	rootCmd.PersistentFlags().String("cluster", "", "ECS cluster name (default: rosa-boundary-dev)")
	rootCmd.PersistentFlags().String("role-arn", "", "SRE role ARN (overrides Lambda response)")
	rootCmd.PersistentFlags().String("invoker-role-arn", "", "Lambda invoker role ARN for direct SDK invocation")
	rootCmd.PersistentFlags().String("lambda-function-name", "", "Lambda function name or ARN for direct invocation")

	// Bind flags to viper keys
	_ = viper.BindPFlag("lambda_url", rootCmd.PersistentFlags().Lookup("lambda-url"))
	_ = viper.BindPFlag("keycloak_url", rootCmd.PersistentFlags().Lookup("keycloak-url"))
	_ = viper.BindPFlag("keycloak_realm", rootCmd.PersistentFlags().Lookup("realm"))
	_ = viper.BindPFlag("oidc_client_id", rootCmd.PersistentFlags().Lookup("client-id"))
	_ = viper.BindPFlag("aws_region", rootCmd.PersistentFlags().Lookup("region"))
	_ = viper.BindPFlag("cluster_name", rootCmd.PersistentFlags().Lookup("cluster"))
	_ = viper.BindPFlag("sre_role_arn", rootCmd.PersistentFlags().Lookup("role-arn"))
	_ = viper.BindPFlag("invoker_role_arn", rootCmd.PersistentFlags().Lookup("invoker-role-arn"))
	_ = viper.BindPFlag("lambda_function_name", rootCmd.PersistentFlags().Lookup("lambda-function-name"))
}

func initConfig() {
	if err := config.Load(); err != nil {
		fmt.Fprintln(os.Stderr, "Warning: config error:", err)
	}
}

// getConfig is a helper that loads and validates config, printing a useful error if required fields are missing.
func getConfig(requireLambdaURL, requireKeycloakURL bool) (*config.Config, error) {
	cfg, err := config.Get()
	if err != nil {
		return nil, err
	}

	if requireLambdaURL && cfg.LambdaURL == "" {
		return nil, fmt.Errorf("lambda URL is required; set --lambda-url, ROSA_BOUNDARY_LAMBDA_URL, or LAMBDA_URL")
	}
	if requireKeycloakURL && cfg.KeycloakURL == "" {
		return nil, fmt.Errorf("keycloak URL is required; set --keycloak-url, ROSA_BOUNDARY_KEYCLOAK_URL, or KEYCLOAK_URL")
	}

	return cfg, nil
}

// debugf prints a debug message if verbose mode is enabled.
func debugf(format string, args ...any) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	}
}

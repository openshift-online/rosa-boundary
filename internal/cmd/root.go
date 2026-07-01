package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/openshift/rosa-boundary/internal/config"
)

const (
	// defaultExecCommand is the ECS Exec command used by join-task and start-task --connect.
	// Uses runuser to switch from root (SSM Agent) to the sre user with a login shell.
	defaultExecCommand = "runuser -u sre -- sh -c 'cd ~ && exec bash --login'"
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
	rootCmd.PersistentFlags().String("oidc-issuer-url", "", "OIDC issuer URL")
	rootCmd.PersistentFlags().String("client-id", "", "OIDC client ID (default: aws-sre-access)")
	rootCmd.PersistentFlags().String("region", "", "AWS region (default: us-east-2)")
	rootCmd.PersistentFlags().String("ecs-cluster", "", "ECS cluster name (default: rosa-boundary-dev)")
	rootCmd.PersistentFlags().String("role-arn", "", "SRE role ARN (overrides Lambda response)")
	rootCmd.PersistentFlags().String("invoker-role-arn", "", "Lambda invoker role ARN for direct SDK invocation")
	rootCmd.PersistentFlags().String("lambda-function-name", "", "Lambda function name or ARN for direct invocation")
	rootCmd.PersistentFlags().String("efs-filesystem-id", "", "EFS filesystem ID for investigation access points")

	// Bind flags to viper keys
	_ = viper.BindPFlag("oidc_issuer_url", rootCmd.PersistentFlags().Lookup("oidc-issuer-url"))
	_ = viper.BindPFlag("oidc_client_id", rootCmd.PersistentFlags().Lookup("client-id"))
	_ = viper.BindPFlag("aws_region", rootCmd.PersistentFlags().Lookup("region"))
	_ = viper.BindPFlag("ecs_cluster_name", rootCmd.PersistentFlags().Lookup("ecs-cluster"))
	_ = viper.BindPFlag("sre_role_arn", rootCmd.PersistentFlags().Lookup("role-arn"))
	_ = viper.BindPFlag("invoker_role_arn", rootCmd.PersistentFlags().Lookup("invoker-role-arn"))
	_ = viper.BindPFlag("lambda_function_name", rootCmd.PersistentFlags().Lookup("lambda-function-name"))
	_ = viper.BindPFlag("efs_filesystem_id", rootCmd.PersistentFlags().Lookup("efs-filesystem-id"))
}

func initConfig() {
	if err := config.Load(); err != nil {
		fmt.Fprintln(os.Stderr, "Warning: config error:", err)
	}
}

// getConfig is a helper that loads and validates config, printing a useful error if required fields are missing.
func getConfig(requireOIDCIssuerURL bool) (*config.Config, error) {
	cfg, err := config.Get()
	if err != nil {
		return nil, err
	}

	if requireOIDCIssuerURL && cfg.OIDCIssuerURL == "" {
		return nil, fmt.Errorf("OIDC issuer URL is required; set --oidc-issuer-url, ROSA_BOUNDARY_OIDC_ISSUER_URL, or OIDC_ISSUER_URL")
	}

	return cfg, nil
}

// debugf prints a debug message if verbose mode is enabled.
func debugf(format string, args ...any) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	}
}

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/openshift/rosa-boundary/internal/config"
)

var configureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Interactively configure rosa-boundary",
	Long: `Prompt for configuration values and write them to
~/.config/rosa-boundary/config.yaml (respects XDG_CONFIG_HOME).

Current values are shown in brackets. Press Enter to keep them.

Configuration fields:

  keycloak_url          Base URL of your Keycloak instance (e.g.,
                        https://keycloak.example.com). Used for OIDC
                        authentication via the browser-based PKCE flow.

  keycloak_realm        Keycloak realm name. Default: sre-ops.

  oidc_client_id        OIDC client ID registered in Keycloak for this
                        application. Default: aws-sre-access.

  lambda_function_name  Name of the AWS Lambda function that creates
                        investigation tasks. Must match the function
                        deployed in your AWS account.
                        Example: rosa-boundary-dev-create-investigation.

  invoker_role_arn      ARN of the IAM role assumed by the CLI before
                        invoking the Lambda function. Must match the
                        role deployed in your AWS account.

  sre_role_arn          ARN of the shared ABAC IAM role assumed for
                        join-task. Scoped at runtime so you can only
                        exec into tasks tagged with your identity.

  aws_region            AWS region where the infrastructure is deployed.
                        Default: us-east-2.

  cluster_name          Name of the ECS cluster running investigation
                        tasks. Default: rosa-boundary-dev.

All values can also be set via environment variables (ROSA_BOUNDARY_<KEY>),
CLI flags, or the config file. Resolution order: flags > env > config > defaults.`,
	Args: cobra.NoArgs,
	RunE: runConfigure,
}

func init() {
	rootCmd.AddCommand(configureCmd)
}

func runConfigure(cmd *cobra.Command, args []string) error {
	// Load existing config so we can show current values as defaults
	cfg, _ := config.Get()
	if cfg == nil {
		cfg = &config.Config{}
	}

	scanner := bufio.NewScanner(os.Stdin)

	prompt := func(label, current, def string) string {
		display := current
		if display == "" {
			display = def
		}
		if display != "" {
			fmt.Fprintf(os.Stderr, "%s [%s]: ", label, display)
		} else {
			fmt.Fprintf(os.Stderr, "%s: ", label)
		}
		if !scanner.Scan() {
			return display
		}
		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			return display
		}
		return input
	}

	fmt.Fprintln(os.Stderr, "Run 'rosa-boundary configure --help' for details on each configuration field.")
	fmt.Fprintln(os.Stderr)

	keycloakURL := prompt("Keycloak URL (required)", cfg.KeycloakURL, "")
	keycloakRealm := prompt("Keycloak realm", cfg.KeycloakRealm, "sre-ops")
	oidcClientID := prompt("OIDC client ID", cfg.OIDCClientID, "aws-sre-access")
	lambdaFunctionName := prompt("Lambda function name (required)", cfg.LambdaFunctionName, "")
	invokerRoleARN := prompt("Invoker role ARN (required)", cfg.InvokerRoleARN, "")
	sreRoleARN := prompt("SRE role ARN", cfg.SRERoleARN, "")
	awsRegion := prompt("AWS region", cfg.AWSRegion, "us-east-2")
	clusterName := prompt("ECS cluster name", cfg.ClusterName, "rosa-boundary-dev")
	efsFilesystemID := prompt("EFS filesystem ID", cfg.EFSFilesystemID, "")

	configDir, err := config.ConfigDir()
	if err != nil {
		return err
	}
	configPath := filepath.Join(configDir, "config.yaml")

	entries := []config.ConfigEntry{
		{
			Key:     "keycloak_url",
			Value:   keycloakURL,
			Comment: "Base URL of the Keycloak instance for OIDC authentication.",
		},
		{
			Key:     "keycloak_realm",
			Value:   keycloakRealm,
			Comment: "Keycloak realm name. Default: sre-ops",
		},
		{
			Key:     "oidc_client_id",
			Value:   oidcClientID,
			Comment: "OIDC client ID registered in Keycloak. Default: aws-sre-access",
		},
		{
			Key:     "lambda_function_name",
			Value:   lambdaFunctionName,
			Comment: "Name of the AWS Lambda function that creates investigation tasks.\nMust match the function deployed in your AWS account.",
		},
		{
			Key:     "invoker_role_arn",
			Value:   invokerRoleARN,
			Comment: "ARN of the IAM role assumed by the CLI before invoking the Lambda.",
		},
		{
			Key:     "sre_role_arn",
			Value:   sreRoleARN,
			Comment: "ARN of the shared ABAC IAM role assumed for join-task.\nScoped at runtime so you can only exec into tasks tagged with your identity.",
		},
		{
			Key:     "aws_region",
			Value:   awsRegion,
			Comment: "AWS region where the infrastructure is deployed. Default: us-east-2",
		},
		{
			Key:     "cluster_name",
			Value:   clusterName,
			Comment: "Name of the ECS cluster running investigation tasks. Default: rosa-boundary-dev",
		},
		{
			Key:     "efs_filesystem_id",
			Value:   efsFilesystemID,
			Comment: "EFS filesystem ID. Required for list-investigations and close-investigation.",
		},
	}

	if err := config.WriteConfigFile(configPath, entries); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nConfiguration saved to %s\n", configPath)
	return nil
}

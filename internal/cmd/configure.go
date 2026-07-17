package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/openshift/rosa-boundary/internal/auth"
	awsclient "github.com/openshift/rosa-boundary/internal/aws"
	"github.com/openshift/rosa-boundary/internal/config"
	"github.com/openshift/rosa-boundary/internal/lambda"
	"github.com/openshift/rosa-boundary/internal/output"
)

var (
	configAutoDiscover bool
	configAccountID    string
	configRegion       string
	configProject      string
	configStage        string
)

var configureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure rosa-boundary",
	Long: `Configure rosa-boundary interactively or via auto-discovery.

By default, auto-discovery is enabled: the CLI authenticates via OIDC,
assumes the Lambda invoker role, and fetches all configuration values
from the Lambda. You only need to provide an AWS account ID and region.

Use --auto-discover=false for interactive prompting.

Auto-discovery flags:

  --account-id    AWS account ID (prompted if not provided)
  --region        AWS region (prompted if not provided; default: us-east-2)
  --project       Project name for naming convention (default: rosa-boundary)
  --stage         Deployment stage for naming convention (default: prod)

Configuration is written to ~/.config/rosa-boundary/config.yaml
(respects XDG_CONFIG_HOME).

Configuration fields:

  keycloak_url          Base URL of your Keycloak instance.
                        Default: https://auth.redhat.com/auth.
                        Used for OIDC authentication via the browser-based
                        PKCE flow.

  keycloak_realm        Keycloak realm name. Default: EmployeeIDP.

  oidc_client_id        OIDC client ID registered in Keycloak for this
                        application. Default: rosa-boundary-sre.

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

  ecs_cluster_name      Name of the ECS cluster running investigation
                        tasks. Default: rosa-boundary-dev.

All values can also be set via environment variables (ROSA_BOUNDARY_<KEY>),
CLI flags, or the config file. Resolution order: flags > env > config > defaults.`,
	Args: cobra.NoArgs,
	RunE: runConfigure,
}

func init() {
	configureCmd.Flags().BoolVar(&configAutoDiscover, "auto-discover", true, "Auto-discover configuration via Lambda")
	configureCmd.Flags().StringVar(&configAccountID, "account-id", "", "AWS account ID (prompted if not provided)")
	configureCmd.Flags().StringVar(&configRegion, "region", "", "AWS region (prompted if not provided; default: us-east-2)")
	configureCmd.Flags().StringVar(&configProject, "project", "rosa-boundary", "Project name for naming convention")
	configureCmd.Flags().StringVar(&configStage, "stage", "prod", "Deployment stage for naming convention")
	rootCmd.AddCommand(configureCmd)
}

func runConfigure(cmd *cobra.Command, args []string) error {
	if configAutoDiscover {
		return runConfigureAuto(cmd)
	}
	return runConfigureInteractive(cmd)
}

// newPrompt returns a prompt function that reads from the given scanner. It
// displays the label with the current/default value, reads user input, trims
// whitespace, and falls back to the displayed value when input is empty.
func newPrompt(scanner *bufio.Scanner) func(label, current, def string) string {
	return func(label, current, def string) string {
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
}

// DeriveInvokerRoleARN constructs the invoker role ARN from naming convention.
func DeriveInvokerRoleARN(accountID, project, stage string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s-%s-lambda-invoker", accountID, project, stage)
}

// DeriveLambdaFunctionName constructs the Lambda function name from naming convention.
func DeriveLambdaFunctionName(project, stage string) string {
	return fmt.Sprintf("%s-%s-create-investigation", project, stage)
}

func runConfigureAuto(cmd *cobra.Command) error {
	// Load existing config for defaults
	cfg, _ := config.Get()
	if cfg == nil {
		cfg = &config.Config{}
	}

	prompt := newPrompt(bufio.NewScanner(os.Stdin))

	// 1. Collect seed values — skip prompts for values set via flags.
	accountID := configAccountID
	if accountID == "" {
		accountID = prompt("AWS Account ID", "", "")
	}
	if accountID == "" {
		return fmt.Errorf("AWS account ID is required")
	}

	// Region: flag > config > default, only prompt when no flag was provided.
	region := configRegion
	if region == "" {
		fallback := cfg.AWSRegion
		if fallback == "" {
			fallback = "us-east-2"
		}
		region = prompt("AWS Region", fallback, "us-east-2")
	}

	project := configProject
	if !cmd.Flags().Changed("project") {
		project = prompt("Project", project, "rosa-boundary")
	}
	stage := configStage
	if !cmd.Flags().Changed("stage") {
		stage = prompt("Stage", stage, "prod")
	}

	fmt.Fprintln(os.Stderr)

	// 2. Resolve OIDC values (compiled defaults)
	keycloakURL := cfg.KeycloakURL
	if keycloakURL == "" {
		keycloakURL = "https://auth.redhat.com/auth"
	}
	keycloakRealm := cfg.KeycloakRealm
	if keycloakRealm == "" {
		keycloakRealm = "EmployeeIDP"
	}
	oidcClientID := cfg.OIDCClientID
	if oidcClientID == "" {
		oidcClientID = "rosa-boundary-sre"
	}

	// 3. Derive bootstrap values from naming convention
	invokerRoleARN := DeriveInvokerRoleARN(accountID, project, stage)
	lambdaFunctionName := DeriveLambdaFunctionName(project, stage)

	// 4. OIDC login
	output.Status("Authenticating with Red Hat SSO...")
	pkce := auth.PKCEConfig{
		KeycloakURL: keycloakURL,
		Realm:       keycloakRealm,
		ClientID:    oidcClientID,
	}
	idToken, err := auth.GetToken(cmd.Context(), pkce, false)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	output.Status("  OIDC token obtained")
	fmt.Fprintln(os.Stderr)

	// 5. Assume invoker role
	output.Status("Assuming invoker role...")
	output.Status("  %s", invokerRoleARN)

	invokerCreds, err := awsclient.AssumeRoleWithWebIdentity(cmd.Context(), region, invokerRoleARN, idToken, "rosa-boundary-configure")
	if err != nil {
		return fmt.Errorf("invoker role assumption failed: %w\n\nVerify that:\n  - AWS account ID %q is correct\n  - Project %q and stage %q match the deployment\n  - The invoker role exists: %s", err, accountID, project, stage, invokerRoleARN)
	}
	output.Status("  Invoker role assumed")
	fmt.Fprintln(os.Stderr)

	// 6. Invoke Lambda get_config
	output.Status("Fetching configuration from Lambda...")
	invokerCredProvider := awsclient.StaticCredentialsProvider(invokerCreds)
	lambdaClient := lambda.New(lambdaFunctionName, region, invokerCredProvider)
	configResp, err := lambdaClient.GetConfig(cmd.Context())
	if err != nil {
		return fmt.Errorf("failed to fetch configuration from Lambda: %w", err)
	}
	fmt.Fprintln(os.Stderr)

	// 7. Validate derived values against Lambda response
	if configResp.InvokerRoleARN != "" && configResp.InvokerRoleARN != invokerRoleARN {
		output.Status("  Warning: derived invoker_role_arn differs from Lambda response")
		output.Status("    derived: %s", invokerRoleARN)
		output.Status("    Lambda:  %s", configResp.InvokerRoleARN)
	}
	if configResp.LambdaFunctionName != "" && configResp.LambdaFunctionName != lambdaFunctionName {
		output.Status("  Warning: derived lambda_function_name differs from Lambda response")
		output.Status("    derived: %s", lambdaFunctionName)
		output.Status("    Lambda:  %s", configResp.LambdaFunctionName)
	}

	// Use Lambda-returned values (authoritative) with fallback to derived
	finalLambdaFunctionName := configResp.LambdaFunctionName
	if finalLambdaFunctionName == "" {
		finalLambdaFunctionName = lambdaFunctionName
	}
	finalInvokerRoleARN := configResp.InvokerRoleARN
	if finalInvokerRoleARN == "" {
		finalInvokerRoleARN = invokerRoleARN
	}
	finalSRERoleARN := configResp.SRERoleARN
	finalECSClusterName := configResp.ECSClusterName
	finalEFSFilesystemID := configResp.EFSFilesystemID
	finalRegion := configResp.AWSRegion
	if finalRegion == "" {
		finalRegion = region
	}
	finalKeycloakURL := configResp.KeycloakURL
	if finalKeycloakURL == "" {
		finalKeycloakURL = keycloakURL
	}
	finalKeycloakRealm := configResp.KeycloakRealm
	if finalKeycloakRealm == "" {
		finalKeycloakRealm = keycloakRealm
	}
	finalOIDCClientID := configResp.OIDCClientID
	if finalOIDCClientID == "" {
		finalOIDCClientID = oidcClientID
	}

	// 8. Validate that Lambda returned all required infrastructure values.
	var missing []string
	if finalSRERoleARN == "" {
		missing = append(missing, "sre_role_arn")
	}
	if finalECSClusterName == "" {
		missing = append(missing, "ecs_cluster_name")
	}
	if finalEFSFilesystemID == "" {
		missing = append(missing, "efs_filesystem_id")
	}
	if len(missing) > 0 {
		return fmt.Errorf("lambda response missing required values: %s; verify that the Lambda environment variables are correctly configured in Terraform", strings.Join(missing, ", "))
	}

	// Display discovered values
	output.Status("  %-25s %s", "lambda_function_name :", finalLambdaFunctionName)
	output.Status("  %-25s %s", "invoker_role_arn :", finalInvokerRoleARN)
	output.Status("  %-25s %s", "sre_role_arn :", finalSRERoleARN)
	output.Status("  %-25s %s", "ecs_cluster_name :", finalECSClusterName)
	output.Status("  %-25s %s", "efs_filesystem_id :", finalEFSFilesystemID)
	output.Status("  %-25s %s", "aws_region :", finalRegion)
	output.Status("  %-25s %s", "keycloak_url :", finalKeycloakURL)
	output.Status("  %-25s %s", "keycloak_realm :", finalKeycloakRealm)
	output.Status("  %-25s %s", "oidc_client_id :", finalOIDCClientID)
	fmt.Fprintln(os.Stderr)

	// Build config entries and write config.yaml
	configDir, err := config.ConfigDir()
	if err != nil {
		return err
	}
	configPath := filepath.Join(configDir, "config.yaml")

	entries := []config.ConfigEntry{
		{
			Key:     "keycloak_url",
			Value:   finalKeycloakURL,
			Comment: "Base URL of the Keycloak instance for OIDC authentication.",
		},
		{
			Key:     "keycloak_realm",
			Value:   finalKeycloakRealm,
			Comment: "Keycloak realm name. Default: EmployeeIDP",
		},
		{
			Key:     "oidc_client_id",
			Value:   finalOIDCClientID,
			Comment: "OIDC client ID registered in Keycloak. Default: rosa-boundary-sre",
		},
		{
			Key:     "lambda_function_name",
			Value:   finalLambdaFunctionName,
			Comment: "Name of the AWS Lambda function that creates investigation tasks.\nMust match the function deployed in your AWS account.",
		},
		{
			Key:     "invoker_role_arn",
			Value:   finalInvokerRoleARN,
			Comment: "ARN of the IAM role assumed by the CLI before invoking the Lambda.",
		},
		{
			Key:     "sre_role_arn",
			Value:   finalSRERoleARN,
			Comment: "ARN of the shared ABAC IAM role assumed for join-task.\nScoped at runtime so you can only exec into tasks tagged with your identity.",
		},
		{
			Key:     "aws_region",
			Value:   finalRegion,
			Comment: "AWS region where the infrastructure is deployed. Default: us-east-2",
		},
		{
			Key:     "ecs_cluster_name",
			Value:   finalECSClusterName,
			Comment: "Name of the ECS cluster running investigation tasks. Default: rosa-boundary-dev",
		},
		{
			Key:     "efs_filesystem_id",
			Value:   finalEFSFilesystemID,
			Comment: "EFS filesystem ID. Required for list-investigations and close-investigation.",
		},
	}

	if err := config.WriteConfigFile(configPath, entries); err != nil {
		return err
	}

	output.Status("Configuration written to %s", configPath)
	return nil
}

func runConfigureInteractive(cmd *cobra.Command) error {
	// Load existing config so we can show current values as defaults
	cfg, _ := config.Get()
	if cfg == nil {
		cfg = &config.Config{}
	}

	prompt := newPrompt(bufio.NewScanner(os.Stdin))

	fmt.Fprintln(os.Stderr, "Run 'rosa-boundary configure --help' for details on each configuration field.")
	fmt.Fprintln(os.Stderr)

	keycloakURL := prompt("Keycloak URL", cfg.KeycloakURL, "https://auth.redhat.com/auth")
	keycloakRealm := prompt("Keycloak realm", cfg.KeycloakRealm, "EmployeeIDP")
	oidcClientID := prompt("OIDC client ID", cfg.OIDCClientID, "rosa-boundary-sre")
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
			Comment: "Keycloak realm name. Default: EmployeeIDP",
		},
		{
			Key:     "oidc_client_id",
			Value:   oidcClientID,
			Comment: "OIDC client ID registered in Keycloak. Default: rosa-boundary-sre",
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
			Key:     "ecs_cluster_name",
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

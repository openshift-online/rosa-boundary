package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/config"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

const (
	// defaultExecCommand is the ECS Exec command used by join-task and start-task --connect.
	// Uses runuser to switch from root (SSM Agent) to the sre user with a login shell.
	defaultExecCommand = "runuser -u sre -- sh -c 'cd ~ && exec bash --login'"
)

// AuthResult contains AWS credentials and configuration obtained via OIDC authentication.
type AuthResult struct {
	Config      *config.Config
	IDToken     string
	Credentials *awsclient.TemporaryCredentials
}

var (
	// Version is set at build time via -ldflags.
	Version = "dev"

	verbose    bool
	forceLogin bool

	// cachedAuthResult stores the authentication result populated by PersistentPreRunE
	cachedAuthResult *AuthResult
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
	rootCmd.PersistentFlags().BoolVar(&forceLogin, "force-login", false, "Force re-authentication with Keycloak OIDC provider")
	rootCmd.PersistentFlags().String("keycloak-url", "", "Keycloak base URL")
	rootCmd.PersistentFlags().String("realm", "", "Keycloak realm (default: EmployeeIDP)")
	rootCmd.PersistentFlags().String("client-id", "", "OIDC client ID (default: rosa-boundary-sre)")
	rootCmd.PersistentFlags().String("region", "", "AWS region (default: us-east-2)")
	rootCmd.PersistentFlags().String("ecs-cluster", "", "ECS cluster name (default: rosa-boundary-dev)")
	rootCmd.PersistentFlags().String("role-arn", "", "SRE role ARN (overrides Lambda response)")
	rootCmd.PersistentFlags().String("invoker-role-arn", "", "Lambda invoker role ARN for direct SDK invocation")
	rootCmd.PersistentFlags().String("lambda-function-name", "", "Lambda function name or ARN for direct invocation")
	rootCmd.PersistentFlags().String("efs-filesystem-id", "", "EFS filesystem ID for investigation access points")

	// Bind flags to viper keys
	_ = viper.BindPFlag("keycloak_url", rootCmd.PersistentFlags().Lookup("keycloak-url"))
	_ = viper.BindPFlag("keycloak_realm", rootCmd.PersistentFlags().Lookup("realm"))
	_ = viper.BindPFlag("oidc_client_id", rootCmd.PersistentFlags().Lookup("client-id"))
	_ = viper.BindPFlag("aws_region", rootCmd.PersistentFlags().Lookup("region"))
	_ = viper.BindPFlag("ecs_cluster_name", rootCmd.PersistentFlags().Lookup("ecs-cluster"))
	_ = viper.BindPFlag("sre_role_arn", rootCmd.PersistentFlags().Lookup("role-arn"))
	_ = viper.BindPFlag("invoker_role_arn", rootCmd.PersistentFlags().Lookup("invoker-role-arn"))
	_ = viper.BindPFlag("lambda_function_name", rootCmd.PersistentFlags().Lookup("lambda-function-name"))
	_ = viper.BindPFlag("efs_filesystem_id", rootCmd.PersistentFlags().Lookup("efs-filesystem-id"))

	// PersistentPreRunE runs before any command's RunE, handling OIDC authentication centrally
	rootCmd.PersistentPreRunE = authenticateIfNeeded
}

func initConfig() {
	output.Verbose = verbose

	if err := config.Load(); err != nil {
		fmt.Fprintln(os.Stderr, "Warning: config error:", err)
	}
}

// getConfig is a helper that loads and validates config, printing a useful error if required fields are missing.
func getConfig(requireKeycloakURL bool) (*config.Config, error) {
	cfg, err := config.Get()
	if err != nil {
		return nil, err
	}

	if requireKeycloakURL && cfg.KeycloakURL == "" {
		return nil, fmt.Errorf("keycloak URL is required; set --keycloak-url, ROSA_BOUNDARY_KEYCLOAK_URL, or KEYCLOAK_URL")
	}

	return cfg, nil
}

// debugf prints a debug message if verbose mode is enabled.
func debugf(format string, args ...any) error {
	return output.Debug(format, args...)
}

// assumeRoleWithRetry fetches an OIDC token and assumes the given role.
// If an auth error occurs with a cached token, it retries once with a fresh login.
func assumeRoleWithRetry(ctx context.Context, pkce auth.PKCEConfig, region, roleARN, sessionName string, forceLogin bool) (string, *awsclient.TemporaryCredentials, error) {
	// First attempt: use cached token if available (unless forceLogin)
	idToken, err := auth.GetToken(ctx, pkce, forceLogin)
	if err != nil {
		return "", nil, fmt.Errorf("authentication failed: %w", err)
	}

	creds, err := awsclient.AssumeRoleWithWebIdentity(ctx, region, roleARN, idToken, sessionName)

	// Auto-retry once if we got an auth error (token expired server-side)
	if err != nil && isAuthError(err) && !forceLogin {
		if debugErr := debugf("Auth failed with cached token, retrying with fresh login"); debugErr != nil {
			return "", nil, fmt.Errorf("debug output failed: %w", debugErr)
		}
		if clearErr := auth.ClearToken(); clearErr != nil {
			if debugErr := debugf("Failed to clear token cache: %v", clearErr); debugErr != nil {
				return "", nil, fmt.Errorf("debug output failed: %w", debugErr)
			}
		}

		idToken, err = auth.GetToken(ctx, pkce, true)
		if err != nil {
			return "", nil, fmt.Errorf("authentication failed on retry: %w", err)
		}

		creds, err = awsclient.AssumeRoleWithWebIdentity(ctx, region, roleARN, idToken, sessionName)
	}

	if err != nil {
		return "", nil, fmt.Errorf("failed to assume AWS role via OIDC: %w", err)
	}

	return idToken, creds, nil
}

// authenticateIfNeeded runs before any command that requires AWS/OIDC authentication.
// It performs authentication once and stores the result in the command context.
// If auth fails with an expired token error, it automatically retries once with a fresh login.
func authenticateIfNeeded(cmd *cobra.Command, args []string) error {
	// Commands that don't require authentication
	if !requiresAuth(cmd) {
		return nil
	}

	cfg, err := getConfig(true)
	if err != nil {
		return err
	}

	pkce := auth.PKCEConfig{
		KeycloakURL: cfg.KeycloakURL,
		Realm:       cfg.KeycloakRealm,
		ClientID:    cfg.OIDCClientID,
	}

	// Determine which role to assume based on the command
	var roleARN string
	var sessionName string

	switch cmd.Name() {
	case "create-investigation", "start-task":
		roleARN = cfg.InvokerRoleARN
		sessionName = "rosa-boundary-invoker"
		if roleARN == "" {
			return fmt.Errorf("invoker role ARN is required for %s; set --invoker-role-arn, ROSA_BOUNDARY_INVOKER_ROLE_ARN, or INVOKER_ROLE_ARN", cmd.Name())
		}
	default:
		roleARN = cfg.SRERoleARN
		sessionName = "rosa-boundary-session"
	}

	idToken, creds, err := assumeRoleWithRetry(cmd.Context(), pkce, cfg.AWSRegion, roleARN, sessionName, forceLogin)
	if err != nil {
		return err
	}

	// Store auth result in package-level variable for commands to access
	cachedAuthResult = &AuthResult{
		Config:      cfg,
		IDToken:     idToken,
		Credentials: creds,
	}

	return nil
}

// isAuthError returns true if the error indicates an authentication/authorization failure
// that might be resolved by refreshing the token.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// Common AWS STS auth errors that indicate the token should be refreshed.
	// Note: SignatureDoesNotMatch is NOT included - it indicates clock skew or
	// request signing issues, not token expiration, and retrying won't fix it.
	// InvalidIdentityToken is checked but excludes permanent claim/tag validation failures.
	return strings.Contains(errStr, "ExpiredToken") ||
		strings.Contains(errStr, "InvalidClientTokenId") ||
		(strings.Contains(errStr, "InvalidIdentityToken") &&
			!strings.Contains(errStr, "claim") &&
			!strings.Contains(errStr, "principal") &&
			!strings.Contains(errStr, "tag"))
}

// requiresAuth returns true if the command requires OIDC/AWS authentication.
func requiresAuth(cmd *cobra.Command) bool {
	noAuthCommands := map[string]bool{
		"version":   true,
		"configure": true,
		"login":     true,
		"help":      true, // Built-in Cobra command
	}

	// Check if this command is in the no-auth list
	if noAuthCommands[cmd.Name()] {
		return false
	}

	// Cobra completion commands should not require auth
	// Only exempt "completion" itself and its direct children
	if cmd.Name() == "completion" {
		return false
	}

	// Exempt children of completion command (e.g., "completion bash")
	if cmd.Parent() != nil && cmd.Parent().Name() == "completion" {
		return false
	}

	// Exempt hidden Cobra completion helpers
	if cmd.Name() == "__complete" || cmd.Name() == "__completeNoDesc" {
		return false
	}

	return true
}

// getAuthResult retrieves the authentication result.
// This should only be called by commands that require authentication (after PersistentPreRunE has run).
func getAuthResult(cmd *cobra.Command) *AuthResult {
	if cachedAuthResult == nil {
		// This should never happen if requiresAuth() is correct
		panic(fmt.Sprintf("command %s requires authentication but auth result not populated", cmd.Name()))
	}
	return cachedAuthResult
}

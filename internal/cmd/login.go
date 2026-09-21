package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openshift-online/rosa-boundary/internal/auth"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Keycloak and cache the OIDC token",
	Long: `Perform PKCE authentication with Keycloak.

Opens a browser window for login, starts a local callback server on port 8400,
and caches the resulting ID token for 4 minutes.

The ID token is cached locally and is never written to stdout; status messages
go to stderr.`,
	RunE: runLogin,
}

var loginForce bool

func init() {
	loginCmd.Flags().BoolVar(&loginForce, "force", false, "Force fresh authentication, ignoring cache")
	rootCmd.AddCommand(loginCmd)
}

func runLogin(cmd *cobra.Command, args []string) error {
	cfg, err := getConfig(true)
	if err != nil {
		return err
	}

	if err := debugf("Keycloak URL: %s", cfg.KeycloakURL); err != nil {
		return fmt.Errorf("debug output failed: %w", err)
	}
	if err := debugf("Realm: %s", cfg.KeycloakRealm); err != nil {
		return fmt.Errorf("debug output failed: %w", err)
	}
	if err := debugf("Client ID: %s", cfg.OIDCClientID); err != nil {
		return fmt.Errorf("debug output failed: %w", err)
	}

	pkce := auth.PKCEConfig{
		KeycloakURL: cfg.KeycloakURL,
		Realm:       cfg.KeycloakRealm,
		ClientID:    cfg.OIDCClientID,
	}

	// Always clear AWS credentials cache on login to prevent cross-user credential reuse.
	// Even without --force, the user may be authenticating as a different identity.
	if clearErr := credentialManager.ClearCredentials(); clearErr != nil {
		_ = debugf("Failed to clear credentials cache: %v", clearErr)
		return fmt.Errorf("failed to clear credentials cache during login: %w", clearErr)
	}

	// Clear OIDC token cache only when force login requested
	force := forceFreshLogin(forceLogin, loginForce)
	if force {
		if clearErr := auth.ClearToken(); clearErr != nil {
			_ = debugf("Failed to clear token cache: %v", clearErr)
			return fmt.Errorf("failed to clear token cache during force login: %w", clearErr)
		}
	}

	_, err = auth.GetToken(cmd.Context(), pkce, force)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	return nil
}

// forceFreshLogin reports whether either supported login force flag was set.
func forceFreshLogin(globalForceLogin, loginForce bool) bool {
	return globalForceLogin || loginForce
}

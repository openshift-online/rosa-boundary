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

	debugf("Keycloak URL: %s", cfg.KeycloakURL)
	debugf("Realm: %s", cfg.KeycloakRealm)
	debugf("Client ID: %s", cfg.OIDCClientID)

	pkce := auth.PKCEConfig{
		KeycloakURL: cfg.KeycloakURL,
		Realm:       cfg.KeycloakRealm,
		ClientID:    cfg.OIDCClientID,
	}

	_, err = auth.GetToken(cmd.Context(), pkce, forceFreshLogin(forceLogin, loginForce))
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	return nil
}

// forceFreshLogin reports whether either supported login force flag was set.
func forceFreshLogin(globalForceLogin, loginForce bool) bool {
	return globalForceLogin || loginForce
}

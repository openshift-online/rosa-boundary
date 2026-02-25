package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/openshift/rosa-boundary/internal/auth"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Keycloak and cache the OIDC token",
	Long: `Perform PKCE authentication with Keycloak.

Opens a browser window for login, starts a local callback server on port 8400,
and caches the resulting ID token for 4 minutes.

The token is written to stdout; status messages go to stderr.`,
	RunE: runLogin,
}

var loginForce bool

func init() {
	loginCmd.Flags().BoolVar(&loginForce, "force", false, "Force fresh authentication, ignoring cache")
	rootCmd.AddCommand(loginCmd)
}

func runLogin(cmd *cobra.Command, args []string) error {
	cfg, err := getConfig(false, true)
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

	token, err := auth.GetToken(cmd.Context(), pkce, loginForce)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Write token to stdout
	_, err = fmt.Fprintln(os.Stdout, token)
	return err
}

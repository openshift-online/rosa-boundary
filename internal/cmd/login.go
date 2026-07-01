package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/openshift/rosa-boundary/internal/auth"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate via OIDC and cache the token",
	Long: `Perform PKCE authentication with the configured OIDC provider.

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
	cfg, err := getConfig(true)
	if err != nil {
		return err
	}

	debugf("OIDC issuer: %s", cfg.OIDCIssuerURL)
	debugf("Client ID: %s", cfg.OIDCClientID)

	pkce := auth.PKCEConfig{
		IssuerURL: cfg.OIDCIssuerURL,
		ClientID:  cfg.OIDCClientID,
	}

	token, err := auth.GetToken(cmd.Context(), pkce, loginForce)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Write token to stdout
	_, err = fmt.Fprintln(os.Stdout, token)
	return err
}

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openshift-online/rosa-boundary/internal/auth"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with the OIDC provider and cache an ID token",
	Long: `Authenticate with the configured OIDC provider and cache an ID token.

By default, opens a browser and receives the login callback locally. With
device authorization, open the displayed URL on another device, enter the
code and approve the request; no browser or callback is used on this host.
Set oidc_use_device_code in config or override it with --use-device-code.
A valid cached token is reused unless --force or --force-login is set.

The ID token is cached locally and is never written to stdout; status messages
go to stderr. -o json emits prefixed auth events on stderr, not a JSON result.`,
	RunE: runLogin,
}

var loginForce bool

func init() {
	loginCmd.Flags().BoolVar(&loginForce, "force", false, "Force fresh authentication, ignoring cache")
	addOutputFlag(loginCmd, false)
	rootCmd.AddCommand(loginCmd)
}

func runLogin(cmd *cobra.Command, args []string) error {
	if _, err := commandOutput(cmd); err != nil {
		return err
	}
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

	options, err := tokenOptions(cmd, cfg)
	if err != nil {
		return err
	}
	_, err = auth.GetTokenWithOptions(cmd.Context(), pkce, forceFreshLogin(forceLogin, loginForce), options)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	return nil
}

// forceFreshLogin reports whether either supported login force flag was set.
func forceFreshLogin(globalForceLogin, loginForce bool) bool {
	return globalForceLogin || loginForce
}

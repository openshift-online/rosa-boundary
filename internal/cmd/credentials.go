package cmd

import "github.com/spf13/cobra"

// supportedCredentialProviders supplies user-facing provider enumeration.
var supportedCredentialProviders = []string{"ocm"}

var credentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "Manage task-scoped credentials",
}

var credentialsConfigureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure a credential provider in a running task",
}

var credentialsClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear a credential provider from a running task",
}

func init() {
	credentialsCmd.AddCommand(credentialsConfigureCmd, credentialsClearCmd)
	rootCmd.AddCommand(credentialsCmd)
}

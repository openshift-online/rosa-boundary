package cmd

import (
	"fmt"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	"github.com/openshift-online/rosa-boundary/internal/config"
	"github.com/spf13/cobra"
)

// addOutputFlag is local to auth-bearing leaf commands. Authentication
// guidance always goes to stderr; JSON results go to stdout.
func addOutputFlag(cmd *cobra.Command, binding ...*string) {
	help := "Output: text or json; json emits results on stdout; authentication guidance goes to stderr"
	if len(binding) != 0 {
		cmd.Flags().StringVarP(binding[0], "output", "o", "text", help)
	} else {
		cmd.Flags().StringP("output", "o", "text", help)
	}
}

func commandOutput(cmd *cobra.Command) (string, error) {
	if cmd.Flags().Lookup("output") == nil {
		return "text", nil
	}
	value, err := cmd.Flags().GetString("output")
	if err != nil {
		return "", err
	}
	if value != "text" && value != "json" {
		return "", fmt.Errorf("invalid --output %q: must be text or json", value)
	}
	return value, nil
}

func tokenOptions(cmd *cobra.Command, cfg *config.Config) (auth.Options, error) {
	if _, err := commandOutput(cmd); err != nil {
		return auth.Options{}, err
	}
	return auth.Options{UseDeviceCode: cfg.OIDCUseDeviceCode}, nil
}

// configure never inherits an existing file or environment for the flow it
// persists; an explicit true is the only way to select device bootstrap.
func configureDeviceCode(cmd *cobra.Command) bool {
	flag := cmd.Flag("use-device-code")
	return flag != nil && flag.Changed && flag.Value.String() == "true"
}

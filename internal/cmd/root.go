package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/config"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

const (
	// defaultExecCommand is the ECS Exec command used by session join and session create --connect.
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

	verbose bool

	// cachedAuthResult stores the authentication result populated by PersistentPreRunE
	cachedAuthResult  *AuthResult
	assumeWebIdentity = awsclient.AssumeRoleWithWebIdentity
)

// Execute runs the investigation/session CLI command tree.
func Execute() {
	if status := executeRoot(buildRootCommand(), os.Args[1:]...); status != 0 {
		os.Exit(status)
	}
}

func executeRoot(root *cobra.Command, args ...string) int {
	if args != nil {
		root.SetArgs(args)
	}
	cmd, err := root.ExecuteC()
	if commandCancel != nil {
		commandCancel()
		commandCancel = nil
	}
	if err != nil {
		if cmd != nil && cmd.Flags().Lookup("output") != nil && !errors.Is(err, output.ErrJSONWrite) {
			format, formatErr := commandOutput(cmd)
			// Flag parsing stops at the first invalid flag. A later explicit
			// JSON selection is still an intentional request for JSON output.
			jsonSelected := formatErr == nil && format == "json"
			if !cmd.Flags().Changed("output") && !jsonSelected {
				for i, arg := range args {
					if arg == "--" {
						break
					}
					if arg == "--output=json" || arg == "-o=json" || (arg == "-o" || arg == "--output") && i+1 < len(args) && args[i+1] == "json" {
						jsonSelected = true
					}
				}
			}
			if jsonSelected {
				// The error is the same actionable diagnostic printed on stderr;
				// never substitute a success-shaped result on failure.
				if writeErr := output.JSONTo(cmd.OutOrStdout(), map[string]any{
					"error": map[string]string{"code": "command_failed", "message": err.Error()},
				}); writeErr != nil {
					fmt.Fprintln(os.Stderr, "Error: failed to write JSON failure result:", writeErr)
				}
			}
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		var child *exec.ExitError
		if errors.As(err, &child) && child.ExitCode() > 0 {
			return child.ExitCode()
		}
		return 1
	}
	return 0
}

// debugf prints a debug message if verbose mode is enabled.
func debugf(format string, args ...any) error {
	return output.Debug(format, args...)
}

// assumeRoleWithRetryOptions fetches an OIDC token and assumes the given role.
// If STS rejects a cached token, retry once with the selected fresh-login flow.
func assumeRoleWithRetryOptions(ctx context.Context, pkce auth.PKCEConfig, region, roleARN, sessionName string, forceLogin bool, options auth.Options) (string, *awsclient.TemporaryCredentials, error) {
	// First attempt: use cached token if available (unless forceLogin)
	var cached string
	if !forceLogin {
		cached, _ = auth.CachedTokenForConfig(pkce)
	}
	idToken, err := auth.GetTokenWithOptions(ctx, pkce, forceLogin, options)
	if err != nil {
		return "", nil, fmt.Errorf("authentication failed: %w", err)
	}

	creds, err := assumeWebIdentity(ctx, region, roleARN, idToken, sessionName)

	// Auto-retry once if we got an auth error (token expired server-side)
	if err != nil && isAuthError(err) && !forceLogin && cached != "" && idToken == cached {
		if debugErr := debugf("Auth failed with cached token, retrying with fresh login"); debugErr != nil {
			return "", nil, fmt.Errorf("debug output failed: %w", debugErr)
		}
		if clearErr := auth.ClearToken(); clearErr != nil {
			if debugErr := debugf("Failed to clear token cache: %v", clearErr); debugErr != nil {
				return "", nil, fmt.Errorf("debug output failed: %w", debugErr)
			}
		}

		idToken, err = auth.GetTokenWithOptions(ctx, pkce, true, options)
		if err != nil {
			return "", nil, fmt.Errorf("authentication failed on retry: %w", err)
		}

		creds, err = assumeWebIdentity(ctx, region, roleARN, idToken, sessionName)
	}

	if err != nil {
		return "", nil, fmt.Errorf("failed to assume AWS role via OIDC; verify the selected profile's account, region, issuer, and role trust with the deployment operator: %w", err)
	}

	return idToken, creds, nil
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

// getAuthResult returns the credentials established by the command pre-run hook.
func getAuthResult(cmd *cobra.Command) *AuthResult {
	if cachedAuthResult == nil {
		panic(fmt.Sprintf("command %s requires authentication but auth result not populated", cmd.Name()))
	}
	return cachedAuthResult
}

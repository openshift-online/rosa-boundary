package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	ocm "github.com/openshift-online/rosa-boundary/internal/credentials/ocm"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

const backplaneLoginTimeout = time.Minute

func configureBackplaneCommand() *cobra.Command {
	cmd := commandLeaf("backplane [session-id]", "Configure Backplane access using fresh OCM credentials", validateBackplaneTarget, runCredentialsConfigureBackplane)
	cmd.Long = `Configure OCM access and log in to Backplane for the running session's cluster.
With --local and --cluster-id, use the installed ocm-backplane to replace a
standalone local kubeconfig instead. Local mode uses --ocm-url or the URL from
your workstation's OCM config, and does not use a Boundary profile. With
--refresh, renew in the foreground and stop with Ctrl+C. Stopping leaves the
last credentials in place.`
	cmd.Flags().String("local", "", "Write a standalone kubeconfig to this local path instead of a session")
	cmd.Flags().String("cluster-id", "", "Target cluster ID for local Backplane login")
	cmd.Flags().String("ocm-url", "", "OCM environment or approved canonical URL")
	cmd.Flags().String("auth-flow", "", "OCM-only override: auth-code or device")
	cmd.Flags().Bool("refresh", false, "Keep renewing OCM and Backplane credentials until stopped (no default deadline)")
	deploymentFlags(cmd, true, false)
	return cmd
}

func validateBackplaneTarget(cmd *cobra.Command, args []string) error {
	if err := optionalCredentialSessionID(cmd, args); err != nil {
		return err
	}
	if cmd.Flags().Changed("local") {
		if strings.TrimSpace(flagString(cmd, "local")) == "" {
			return errors.New("--local requires a non-empty kubeconfig path")
		}
		if len(args) != 0 || cmd.Flags().Changed("region") || cmd.Flags().Changed("ecs-cluster") {
			return errors.New("--local cannot be combined with a session ID, --region, or --ecs-cluster")
		}
		if strings.TrimSpace(flagString(cmd, "cluster-id")) == "" {
			return errors.New("--local requires --cluster-id")
		}
		if cmd.Flags().Changed("ocm-url") && strings.TrimSpace(flagString(cmd, "ocm-url")) == "" {
			return errors.New("--ocm-url must not be empty with --local")
		}
	} else {
		if cmd.Flags().Changed("cluster-id") {
			return errors.New("--cluster-id requires --local; remote Backplane login uses the session's cluster")
		}
		if len(args) == 0 {
			return errors.New("specify a session ID or --local <kubeconfig-path> with --cluster-id")
		}
	}
	if cmd.Flags().Changed("auth-flow") {
		if _, err := parseOCMFlow(flagString(cmd, "auth-flow")); err != nil {
			return err
		}
	}
	if cmd.Flags().Changed("ocm-url") {
		_, err := ocm.ResolveEnvironment(flagString(cmd, "ocm-url"))
		return err
	}
	return nil
}

func runCredentialsConfigureBackplane(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	refresh := flagBool(cmd, "refresh")
	if refresh {
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
	}
	url, device := flagString(cmd, "ocm-url"), flagBool(cmd, "use-device-code")
	local := cmd.Flags().Changed("local")
	if !local {
		cfg := getAuthResult(cmd).Config
		url, device = cfg.OCMURL, cfg.OIDCUseDeviceCode
	}
	environment, err := ocm.ResolveEnvironment(url)
	if err != nil {
		return err
	}
	flow := defaultOCMFlow(device)
	if cmd.Flags().Changed("auth-flow") {
		flow = ocm.Flow(flagString(cmd, "auth-flow")) // validated before authentication
	}
	result := map[string]string{"provider": "backplane", "action": "configured", "environment": environment.Name}
	if local {
		path, err := filepath.Abs(flagString(cmd, "local"))
		if err != nil {
			return err
		}
		clusterID := flagString(cmd, "cluster-id")
		if err := configureLocalBackplane(ctx, cmd, path, clusterID, environment, flow, refresh); err != nil {
			return err
		}
		result["path"], result["cluster_id"] = path, clusterID
	} else {
		clusterID, err := configureSessionBackplane(ctx, getAuthResult(cmd), args[0], ocmSetup{environment: environment, flow: flow}, refresh)
		if err != nil {
			return err
		}
		result["profile"], result["session_id"], result["cluster_id"] = selectedProfile, args[0], clusterID
	}
	if format, _ := commandOutput(cmd); format == "json" {
		return output.JSONTo(cmd.OutOrStdout(), result)
	}
	if local {
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Backplane kubeconfig: %s\n", result["path"])
	}
	return err
}

func configureSessionBackplane(ctx context.Context, authResult *AuthResult, sessionID string, setup ocmSetup, refresh bool) (string, error) {
	ecs := newCredentialECSClient(authResult)
	task, err := ecs.DescribeTask(ctx, sessionID)
	if err != nil {
		return "", err
	}
	clusterID := task.Tags["cluster_id"]
	if _, err := ocm.BackplaneLoginCommand(clusterID); err != nil {
		return "", fmt.Errorf("session %q has no usable cluster_id tag: %w", sessionID, err)
	}
	region := authResult.Config.AWSRegion
	login := func(ctx context.Context, ecs *awsclient.ECSClient, creds *awsclient.TemporaryCredentials) error {
		ctx, cancel := context.WithTimeout(ctx, backplaneLoginTimeout)
		defer cancel()
		return initializeBackplaneLogin(ctx, ecs, region, creds, sessionID, clusterID)
	}
	if refresh {
		return clusterID, maintainOCMForSession(ctx, ecs, authResult, sessionID, setup, login)
	}
	if err := configureOCMForSession(ctx, ecs, region, authResult.Credentials, sessionID, setup.environment, setup.flow); err != nil {
		return "", err
	}
	return clusterID, login(ctx, ecs, authResult.Credentials)
}

func configureLocalBackplane(ctx context.Context, cmd *cobra.Command, path, clusterID string, environment ocm.Environment, flow ocm.Flow, refresh bool) error {
	if err := checkBackplaneKubeconfigPath(path); err != nil {
		return err
	}
	binary, err := exec.LookPath("ocm-backplane")
	if err != nil {
		return errors.New("install ocm-backplane and make it available on PATH for --local")
	}
	a := ocm.NewAuthenticator(func(format string, args ...any) {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), format+"\n", args...)
	})
	a.Debug = credentialDebugf
	var token ocm.Token
	var grant *ocm.AttachmentGrant
	if refresh {
		token, grant, err = a.AcquireForAttachment(ctx, flow)
		defer grant.Release()
	} else {
		token, err = a.Acquire(ctx, flow)
	}
	if err != nil {
		return err
	}
	install := func(ctx context.Context, token ocm.Token) error {
		return writeLocalBackplane(ctx, binary, path, clusterID, environment, token.AccessToken)
	}
	if err := install(ctx, token); err != nil || !refresh {
		return err
	}
	if !grant.Available() {
		return errors.New("Backplane access was configured once, but OCM did not issue an online refresh grant")
	}
	_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Keeping the local Backplane kubeconfig refreshed; press Ctrl+C to stop renewal")
	return renewLocalBackplane(ctx, token, time.Now, waitRenewal, func(ctx context.Context) (ocm.Token, error) {
		return a.Refresh(ctx, grant)
	}, install)
}

func renewLocalBackplane(ctx context.Context, token ocm.Token, now func() time.Time, wait func(context.Context, time.Duration) bool, refresh func(context.Context) (ocm.Token, error), install func(context.Context, ocm.Token) error) error {
	const lead = ocm.RefreshTimeout + backplaneLoginTimeout + 10*time.Second
	for {
		if ctx.Err() != nil {
			break
		}
		remaining := token.Expiry.Sub(now())
		if remaining <= lead {
			return errors.New("OCM token expiry is missing or too near for Backplane renewal")
		}
		if !wait(ctx, remaining-max(lead, remaining/4)) || ctx.Err() != nil {
			break
		}
		var err error
		token, err = refresh(ctx)
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			return fmt.Errorf("OCM refresh failed; rerun the command to sign in again: %w", err)
		}
		if token.Expiry.Sub(now()) <= lead {
			return errors.New("refreshed OCM token expiry is missing or too near for Backplane renewal")
		}
		if err := install(ctx, token); err != nil {
			if ctx.Err() != nil {
				break
			}
			return err
		}
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}
	return ctx.Err()
}

func checkBackplaneKubeconfigPath(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("local kubeconfig path %q must be a regular file", path)
	}
	return nil
}

func writeLocalBackplane(ctx context.Context, binary, path, clusterID string, environment ocm.Environment, accessToken string) error {
	ctx, cancel := context.WithTimeout(ctx, backplaneLoginTimeout)
	defer cancel()
	// Use a new private directory each time: Backplane cannot merge with or
	// partially overwrite the destination, and never sees the refresh grant.
	dir, err := os.MkdirTemp(filepath.Dir(path), ".boundary-backplane-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	ocmPath, kubePath := filepath.Join(dir, "ocm.json"), filepath.Join(dir, "kubeconfig")
	config, err := json.Marshal(map[string]any{"access_token": accessToken, "url": environment.URL, "client_id": ocm.ClientID, "token_url": ocm.TokenURL, "opaque_token": true})
	if err != nil {
		return err
	}
	defer clear(config)
	if err := os.WriteFile(ocmPath, config, 0600); err != nil {
		return err
	}
	login := exec.CommandContext(ctx, binary, "login", "--", clusterID)
	// Explicit environment entries override inherited OCM_CONFIG and KUBECONFIG.
	login.Env = append(os.Environ(), "OCM_CONFIG="+ocmPath, "OCM_URL="+environment.URL, "KUBECONFIG="+kubePath)
	// Do not relay raw Backplane output: debug logs can include credentials.
	if err := login.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("local Backplane login failed; verify the cluster ID, access, and Backplane connectivity: %w", err)
	}
	info, err := os.Lstat(kubePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("Backplane did not produce a usable kubeconfig")
	}
	if err := os.Chmod(kubePath, 0600); err != nil {
		return err
	}
	if err := checkBackplaneKubeconfigPath(path); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Rename(kubePath, path)
}

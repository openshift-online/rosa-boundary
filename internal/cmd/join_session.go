package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	ocm "github.com/openshift-online/rosa-boundary/internal/credentials/ocm"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

var (
	joinContainer          string
	joinCommand            string
	joinNoWait             bool
	openInteractiveSession = connectToSession
)

func runJoinSession(cmd *cobra.Command, args []string) error {
	if _, err := commandOutput(cmd); err != nil {
		return err
	}
	sessionID := args[0]

	authRes := cachedAuthResult
	if authRes == nil {
		return fmt.Errorf("authentication required but not available; select a configured profile and run 'rosa-boundary login' before joining")
	}

	clusterName := authRes.Config.ClusterName
	credProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	ecsClient := awsclient.NewECSClient(authRes.Config.AWSRegion, clusterName, credProvider)

	output.Status("ECS Cluster: %s", clusterName)
	output.Status("Session:     %s", sessionID)

	var attachment attachOCM
	if flagBool(cmd, "renew-ocm") {
		cfg := authRes.Config
		options, err := tokenOptions(cmd, cfg)
		if err != nil {
			return err
		}
		flow := defaultOCMFlow(cfg.OIDCUseDeviceCode)
		if cmd.Flags().Changed("ocm-auth-flow") {
			flow = ocm.Flow(flagString(cmd, "ocm-auth-flow")) // validated before authentication
		}
		attachment.setup = func(ctx context.Context) *ocmRenewal {
			environment, err := ocm.ResolveEnvironment(cfg.OCMURL)
			setup := ocmSetup{environment: environment, flow: flow}
			var renewal *ocmRenewal
			if err == nil {
				authorization := newRenewalAWS(cfg, authRes.Credentials, cfg.SRERoleARN, "rosa-boundary-session", authRes.IDToken, options)
				renewal, err = prepareJoinOCM(ctx, ecsClient, authRes, sessionID, setup, authorization)
			}
			if err != nil && ctx.Err() == nil {
				output.Warning("OCM setup was not confirmed: %v. To retry without renewal, run: %s", err, setup.configureCommand(cfg.AWSRegion, cfg.ClusterName, sessionID))
			}
			return renewal
		}
	}
	// Derive the investigation from the service's own task tags rather than
	// from whatever was typed, and only when a close is actually in play.
	resolveTarget := func() (sessionCloseTarget, error) {
		return resolveSessionCloseTarget(cmd.Context(), ecsClient, sessionID)
	}
	newService := func() (closeService, error) { return newCloseService(cmd, authRes) }
	var registered *sessionCloseTarget
	var registeredWith closeService
	if autoCloseRequested {
		target, err := resolveTarget()
		if err != nil {
			return err
		}
		service, err := newService()
		if err != nil {
			return fmt.Errorf("--auto-close could not be set up, so the session was not joined: %w", err)
		}
		if err := registerAutoCloseIntent(cmd.Context(), service, target); err != nil {
			return err
		}
		registered, registeredWith = &target, service
		resolveTarget = func() (sessionCloseTarget, error) { return target, nil }
	}

	if err := openInteractiveSession(cmd.Context(), ecsClient, authRes.Config.AWSRegion, authRes.Credentials, sessionID, joinContainer, joinCommand, joinNoWait, attachment); err != nil {
		if registered != nil {
			// The SRE asked to close when their session ended, not when it
			// failed to start.
			withdrawAutoCloseIntent(cmd.Context(), registeredWith, *registered)
		}
		return err
	}

	format, _ := commandOutput(cmd)
	outcome := afterAttachedSession(cmd.Context(), newService, resolveTarget, format == "json")
	return disconnectedSessionResult(cmd, sessionID, outcome)
}

// disconnectedSessionResult is only printed after the ECS Exec shell exits
// successfully. Disconnecting does not close the task, and a recorded close
// request is not a completed close.
func disconnectedSessionResult(cmd *cobra.Command, sessionID string, outcome sessionCloseOutcome) error {
	if format, _ := commandOutput(cmd); format == "json" {
		return output.JSONTo(cmd.OutOrStdout(), applyCloseOutcome(map[string]any{
			"profile": selectedProfile, "session_id": sessionID, "status": "disconnected",
			"task_closed": false,
		}, outcome))
	}
	return nil
}

func validateJoinOCM(cmd *cobra.Command) error {
	if !flagBool(cmd, "renew-ocm") {
		if cmd.Flags().Changed("ocm-url") || cmd.Flags().Changed("ocm-auth-flow") {
			return fmt.Errorf("--ocm-url and --ocm-auth-flow require --renew-ocm on join")
		}
		return nil
	}
	if flagBool(cmd, "no-wait") || flagString(cmd, "container") != credentialContainer || flagString(cmd, "command") != defaultExecCommand {
		return fmt.Errorf("--renew-ocm requires waiting for the default rosa-boundary shell")
	}
	if cmd.Flags().Changed("ocm-auth-flow") {
		if _, err := parseOCMFlow(flagString(cmd, "ocm-auth-flow")); err != nil {
			return err
		}
	}
	if cmd.Flags().Changed("ocm-url") {
		_, err := ocm.ResolveEnvironment(flagString(cmd, "ocm-url"))
		return err
	}
	return nil
}

func prepareJoinOCM(ctx context.Context, ecs *awsclient.ECSClient, authRes *AuthResult, sessionID string, setup ocmSetup, authorization *renewalAWS) (*ocmRenewal, error) {
	cfg := authRes.Config
	a := newAttachmentOCMAuth()
	token, grant, err := acquireOCM(ctx, setup.environment, setup.flow, a)
	if err != nil {
		return nil, err
	}
	// Shell readiness has already checked this same container and task.
	return installAttachmentOCM(ctx, ecs, cfg.AWSRegion, authRes.Credentials, cfg.ClusterName, sessionID, setup, token, grant, a, authorization)
}

type attachOCM struct {
	renewal *ocmRenewal
	setup   func(context.Context) *ocmRenewal
}

func (a *attachOCM) takeWorker() func(context.Context) {
	if a.renewal == nil {
		return nil
	}
	renewal := a.renewal
	a.renewal = nil
	return func(ctx context.Context) { renewal.run(ctx, time.Now, waitRenewal) }
}

func withAttachmentRenewal(ctx context.Context, worker func(context.Context), plugin func(context.Context) error) error {
	if worker == nil {
		return plugin(ctx)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	_ = output.Debug("OCM renewal scheduled while this shell is attached")
	go func() {
		defer close(done)
		worker(workerCtx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	return plugin(ctx)
}

// connectToSession is shared by session join and session create.
func connectToSession(ctx context.Context, ecsClient *awsclient.ECSClient, region string, creds *awsclient.TemporaryCredentials, sessionID, container, command string, noWait bool, attachment attachOCM) error {
	// Own setup until the worker takes it. Readiness or Exec failures before
	// that handoff still need to discard the grant.
	defer func() {
		if attachment.renewal != nil {
			attachment.renewal.grant.Release()
		}
	}()
	// Check task status
	output.Status("Checking session status...")
	task, err := ecsClient.DescribeTask(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("cannot describe session %s; check the session ID, selected profile and ECS cluster with 'rosa-boundary session list --status all': %w", sessionID, err)
	}

	output.Status("Session status: %s", task.Status)

	if task.Status != "RUNNING" {
		if noWait {
			return fmt.Errorf("session %s is not RUNNING (status: %s); use --no-wait=false to wait", sessionID, task.Status)
		}
		output.Status("Waiting for session to reach RUNNING state...")
		if err := ecsClient.WaitForRunning(ctx, sessionID); err != nil {
			return fmt.Errorf("session did not reach RUNNING state; check 'rosa-boundary session list --status all' before retrying join: %w", err)
		}
	}

	// Poll until the container's ECS exec agent is RUNNING before opening the
	// SSM session — the data channel is closed immediately if the agent hasn't
	// registered yet. Typically ready within 1-3 s; timeout after 30 s.
	output.Status("Waiting for container exec agent...")
	if err := ecsClient.WaitForExecAgent(ctx, sessionID, container, 30*time.Second); err != nil {
		return fmt.Errorf("session exec agent not ready; check the session status and retry join once the agent is ready: %w", err)
	}

	// Get the controlling terminal before prompting for OCM approval or
	// opening an Exec session. Keep stdout reserved for the final result.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("interactive session requires a controlling terminal: %w", err)
	}
	defer func() { _ = tty.Close() }()
	if attachment.setup != nil {
		attachment.renewal = attachment.setup(ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Start ECS Exec session
	output.Status("\nConnecting to session...")
	fmt.Fprintln(os.Stderr)

	session, err := ecsClient.ExecuteCommand(ctx, sessionID, container, command)
	if err != nil {
		return fmt.Errorf("ECS ExecuteCommand failed; verify the session is RUNNING and ask the deployment operator to check ECS Exec permissions if it persists: %w", err)
	}

	if err := debugf("Session ID: %s", session.SessionID); err != nil {
		output.Warning("could not write debug output: %v", err)
	}

	err = withAttachmentRenewal(ctx, attachment.takeWorker(), func(ctx context.Context) error {
		return awsclient.RunSessionManagerPluginWithStreams(ctx, region, session, creds, tty, tty, tty)
	})
	if ctx.Err() != nil {
		return fmt.Errorf("interactive connection ended (%w); Boundary session %s may still be running and must be stopped separately", ctx.Err(), sessionID)
	}
	return err
}

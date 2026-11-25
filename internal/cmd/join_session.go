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
	return joinSession(cmd, args, resolveSessionCloseTarget, newCloseService)
}

func joinSession(cmd *cobra.Command, args []string,
	resolveTarget func(context.Context, *awsclient.ECSClient, string) (sessionCloseTarget, error),
	serviceFor func(*cobra.Command, *AuthResult) (closeService, error)) error {
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
				renewal, err = prepareJoinOCM(ctx, ecsClient, authRes, sessionID, setup, authorization, attachment.admit)
			}
			if err != nil && ctx.Err() == nil {
				output.Warning("OCM setup was not confirmed: %v. To retry without renewal, run: %s", err, setup.configureCommand(cfg.AWSRegion, cfg.ClusterName, sessionID))
			}
			return renewal
		}
	}
	// Check durable close state before registering intent or opening ECS Exec.
	target, err := resolveTarget(cmd.Context(), ecsClient, sessionID)
	if err != nil {
		return err
	}
	if err := requireSessionCreator(authRes.IDToken, target.CreatorSubject); err != nil {
		return err
	}
	newService := func() (closeService, error) { return serviceFor(cmd, authRes) }
	service, err := newService()
	if err != nil {
		return fmt.Errorf("cannot verify close status; session was not joined: %w", err)
	}
	attachment.admit = func(ctx context.Context) error {
		current, err := service.refreshIfExpired(newService)
		if err != nil {
			return fmt.Errorf("cannot verify close status before attaching: %w", err)
		}
		service = current
		return requireOpenForJoin(ctx, service, target)
	}
	if err := attachment.admit(cmd.Context()); err != nil {
		return err
	}
	if autoCloseRequested {
		if err := registerAutoCloseIntent(cmd.Context(), service, target); err != nil {
			return err
		}
	}
	if err := openInteractiveSession(cmd.Context(), ecsClient, authRes.Config.AWSRegion, authRes.Credentials, sessionID, joinContainer, joinCommand, joinNoWait, attachment); err != nil {
		if autoCloseRequested {
			withdrawAutoCloseIntent(cmd.Context(), service, target, newService)
		}
		return err
	}

	format, _ := commandOutput(cmd)
	outcome := afterAttachedSession(cmd.Context(), newService, func() (sessionCloseTarget, error) { return target, nil }, format == "json")
	return disconnectedSessionResult(cmd, sessionID, outcome)
}

// IAM still enforces ECS Exec ABAC. Check the immutable subject too: a
// display name or configurable principal tag alone is not a creator identity.
func requireSessionCreator(token, creator string) error {
	subject, err := authenticatedSubject(token)
	if err != nil || !validOwnerSubject(subject) || subject != creator {
		return fmt.Errorf("only the session creator may join; session was not joined")
	}
	return nil
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

func prepareJoinOCM(ctx context.Context, ecs *awsclient.ECSClient, authRes *AuthResult, sessionID string, setup ocmSetup, authorization *renewalAWS, admit func(context.Context) error) (*ocmRenewal, error) {
	cfg := authRes.Config
	a := newAttachmentOCMAuth()
	token, grant, err := acquireOCM(ctx, setup.environment, setup.flow, a)
	if err != nil {
		return nil, err
	}
	// Interactive authentication can outlast admission. Recheck before the helper Exec.
	if err := admit(ctx); err != nil {
		grant.Release()
		return nil, err
	}
	// Shell readiness has already checked this same container and task.
	return installAttachmentOCM(ctx, ecs, cfg.AWSRegion, authRes.Credentials, cfg.ClusterName, sessionID, setup, token, grant, a, authorization)
}

type attachOCM struct {
	admit   func(context.Context) error
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

	output.Status("ECS task status: %s", task.Status)
	if task.DesiredStatus != "RUNNING" {
		return fmt.Errorf("session %s is not intended to run (desired status: %q); session was not joined", sessionID, task.DesiredStatus)
	}

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

	// Readiness waits and interactive OCM setup can outlast the first check.
	if attachment.admit != nil {
		if err := attachment.admit(ctx); err != nil {
			return err
		}
	}

	// Start ECS Exec session
	output.Status("\nConnecting to session...")
	fmt.Fprintln(os.Stderr)

	session, err := ecsClient.ExecuteCommand(ctx, sessionID, container, command)
	if err != nil {
		return fmt.Errorf("ECS ExecuteCommand failed; verify the session is RUNNING and ask the deployment operator to check ECS Exec permissions if it persists: %w", err)
	}

	if err := debugf("SSM shell connection ID: %s", session.SessionID); err != nil {
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

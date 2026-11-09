package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
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

	if err := openInteractiveSession(cmd.Context(), ecsClient, authRes.Config.AWSRegion, authRes.Credentials, sessionID, joinContainer, joinCommand, joinNoWait); err != nil {
		return err
	}
	return disconnectedSessionResult(cmd, sessionID)
}

// disconnectedSessionResult is only printed after the ECS Exec shell exits
// successfully. Disconnecting does not close the task or investigation.
func disconnectedSessionResult(cmd *cobra.Command, sessionID string) error {
	if format, _ := commandOutput(cmd); format == "json" {
		return output.JSONTo(cmd.OutOrStdout(), map[string]any{"profile": selectedProfile, "session_id": sessionID, "status": "disconnected", "task_closed": false, "investigation_closed": false})
	}
	return nil
}

// connectToSession is shared by session join and session create --connect.
func connectToSession(ctx context.Context, ecsClient *awsclient.ECSClient, region string, creds *awsclient.TemporaryCredentials, sessionID, container, command string, noWait bool) error {
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

	// Hand off to session-manager-plugin on the controlling terminal. Keep stdout
	// reserved for the result after the interactive shell exits successfully.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("interactive session requires a controlling terminal: %w", err)
	}
	defer func() { _ = tty.Close() }()
	// Keep the CLI process alive so an explicit whole-command deadline can
	// cancel the plugin without claiming the underlying ECS task stopped.
	err = awsclient.RunSessionManagerPluginWithStreams(ctx, region, session, creds, tty, tty, tty)
	if ctx.Err() != nil {
		return fmt.Errorf("interactive connection ended (%w); Boundary session %s may still be running and must be stopped separately", ctx.Err(), sessionID)
	}
	return err
}

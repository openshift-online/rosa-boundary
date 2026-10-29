package cmd

import (
	"context"
	"fmt"
	"golang.org/x/term"
	"os"
	"time"

	"github.com/spf13/cobra"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

var joinTaskCmd = &cobra.Command{
	Use:   "join-task <task-id>",
	Short: "Connect to a running ECS task via ECS Exec",
	Long: `Connect to a running ECS Fargate task using ECS Exec and the
AWS Session Manager plugin. Requires session-manager-plugin to be installed.

The task must be in RUNNING state and have ECS Exec enabled.

-o json emits authentication events on stderr, not a JSON shell result.
The session still requires a controlling terminal; its raw I/O is sent to
that terminal rather than stdout. The plugin's exit status is preserved.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(1)(cmd, args); err != nil {
			return err
		}
		return requireInteractiveTerminal(cmd)
	},
	RunE: runJoinTask,
}

var (
	joinContainer string
	joinCommand   string
	joinNoWait    bool
)

func init() {
	joinTaskCmd.Flags().StringVar(&joinContainer, "container", "rosa-boundary", "Container name to connect to")
	joinTaskCmd.Flags().StringVar(&joinCommand, "command", defaultExecCommand, "Command to run in the container")
	joinTaskCmd.Flags().BoolVar(&joinNoWait, "no-wait", false, "Do not wait for RUNNING state before connecting")
	addOutputFlag(joinTaskCmd, false)
	rootCmd.AddCommand(joinTaskCmd)
}

func runJoinTask(cmd *cobra.Command, args []string) error {
	taskID := args[0]

	authRes := cachedAuthResult
	if authRes == nil {
		return fmt.Errorf("authentication required but not available")
	}

	clusterName := authRes.Config.ClusterName
	credProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	ecsClient := awsclient.NewECSClient(authRes.Config.AWSRegion, clusterName, credProvider)

	output.Status("ECS Cluster: %s", clusterName)
	output.Status("Task:        %s", taskID)

	return runJoinWithClientFormat(cmd.Context(), ecsClient, authRes.Config.AWSRegion, authRes.Credentials, taskID, joinContainer, joinCommand, joinNoWait, joinOutputFormat(cmd))
}

func joinOutputFormat(cmd *cobra.Command) string { format, _ := commandOutput(cmd); return format }

// A JSON result stream cannot carry arbitrary shell bytes. A controlling
// terminal is mandatory and belongs to the plugin, not command stdout/stderr.
func requireInteractiveTerminal(cmd *cobra.Command) error {
	format, err := commandOutput(cmd)
	if err != nil {
		return err
	}
	if format != "json" {
		return nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("-o json with an interactive session requires a controlling terminal: %w", err)
	}
	defer func() { _ = tty.Close() }()
	if !term.IsTerminal(int(tty.Fd())) {
		return fmt.Errorf("-o json with an interactive session requires a controlling terminal")
	}
	return nil
}

func runJoinWithClientFormat(ctx context.Context, ecsClient *awsclient.ECSClient, region string, creds *awsclient.TemporaryCredentials, taskID, container, command string, noWait bool, format string) error {
	return runJoinWithClientSession(ctx, ecsClient, region, creds, taskID, container, command, noWait, format)
}

// runJoinWithClientSession is shared by join-task and start-task --connect.
func runJoinWithClientSession(ctx context.Context, ecsClient *awsclient.ECSClient, region string, creds *awsclient.TemporaryCredentials, taskID, container, command string, noWait bool, format string) error {
	// Check task status
	output.Status("Checking task status...")
	task, err := ecsClient.DescribeTask(ctx, taskID)
	if err != nil {
		return fmt.Errorf("cannot describe task %s: %w", taskID, err)
	}

	output.Status("Task status: %s", task.Status)

	if task.Status != "RUNNING" {
		if noWait {
			return fmt.Errorf("task %s is not RUNNING (status: %s); use --no-wait=false to wait", taskID, task.Status)
		}
		output.Status("Waiting for task to reach RUNNING state...")
		if err := ecsClient.WaitForRunning(ctx, taskID); err != nil {
			return fmt.Errorf("task did not reach RUNNING state: %w", err)
		}
	}

	// Poll until the container's ECS exec agent is RUNNING before opening the
	// SSM session — the data channel is closed immediately if the agent hasn't
	// registered yet. Typically ready within 1-3 s; timeout after 30 s.
	output.Status("Waiting for container exec agent...")
	if err := ecsClient.WaitForExecAgent(ctx, taskID, container, 30*time.Second); err != nil {
		return fmt.Errorf("exec agent not ready: %w", err)
	}

	// Start ECS Exec session
	output.Status("\nConnecting to task...")
	fmt.Fprintln(os.Stderr)

	session, err := ecsClient.ExecuteCommand(ctx, taskID, container, command)
	if err != nil {
		return fmt.Errorf("ECS ExecuteCommand failed: %w", err)
	}

	if err := debugf("Session ID: %s", session.SessionID); err != nil {
		output.Warning("could not write debug output: %v", err)
	}

	// Hand off to session-manager-plugin (replaces the process)
	if format == "json" {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return fmt.Errorf("interactive session requires a controlling terminal: %w", err)
		}
		defer func() { _ = tty.Close() }()
		return awsclient.RunSessionManagerPluginWithStreams(ctx, region, session, creds, tty, tty, tty)
	}
	return awsclient.StartSessionManagerPlugin(region, session, creds)
}

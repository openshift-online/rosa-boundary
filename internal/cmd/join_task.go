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

type joinTaskOptions struct {
	forceLogin bool
	container  string
	command    string
	noWait     bool
}

func newJoinTaskCmd() *cobra.Command {
	opts := &joinTaskOptions{}

	cmd := &cobra.Command{
		Use:   "join-task <task-id>",
		Short: "Connect to a running ECS task via ECS Exec",
		Long: `Connect to a running ECS Fargate task using ECS Exec and the
AWS Session Manager plugin. Requires session-manager-plugin to be installed.

The task must be in RUNNING state and have ECS Exec enabled.
Uses OIDC authentication via cached token from 'rosa-boundary login'.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.run(cmd, args[0])
		},
	}

	AddForceLoginFlag(cmd, &opts.forceLogin)
	cmd.Flags().StringVar(&opts.container, "container", "rosa-boundary", "Container name to connect to")
	cmd.Flags().StringVar(&opts.command, "command", defaultExecCommand, "Command to run in the container")
	cmd.Flags().BoolVar(&opts.noWait, "no-wait", false, "Do not wait for RUNNING state before connecting")

	return cmd
}

func init() {
	rootCmd.AddCommand(newJoinTaskCmd())
}

func (o *joinTaskOptions) run(cmd *cobra.Command, taskID string) error {
	authRes, err := GetAWSConfigWithOIDC(cmd, o.forceLogin)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	clusterName := authRes.Config.ClusterName
	credProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	ecsClient := awsclient.NewECSClient(authRes.Config.AWSRegion, clusterName, credProvider)

	output.Status("ECS Cluster: %s", clusterName)
	output.Status("Task:        %s", taskID)

	return runJoinWithClient(cmd.Context(), ecsClient, authRes.Config.AWSRegion, taskID, o.container, o.command, o.noWait)
}

// runJoinWithClient is shared by join-task and start-task --connect.
func runJoinWithClient(ctx context.Context, ecsClient *awsclient.ECSClient, region, taskID, container, command string, noWait bool) error {
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

	debugf("Session ID: %s", session.SessionID)

	// Hand off to session-manager-plugin (replaces the process)
	return awsclient.StartSessionManagerPlugin(region, session)
}

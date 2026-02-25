package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/spf13/cobra"

	awsclient "github.com/openshift/rosa-boundary/internal/aws"
	"github.com/openshift/rosa-boundary/internal/output"
)

var joinTaskCmd = &cobra.Command{
	Use:   "join-task <task-id>",
	Short: "Connect to a running ECS task via ECS Exec",
	Long: `Connect to a running ECS Fargate task using ECS Exec and the
AWS Session Manager plugin. Requires session-manager-plugin to be installed.

The task must be in RUNNING state and have ECS Exec enabled.
AWS credentials must be configured (e.g., via environment variables or
after running start-task with --connect).`,
	Args: cobra.ExactArgs(1),
	RunE: runJoinTask,
}

var (
	joinContainer string
	joinCommand   string
	joinNoWait    bool
)

func init() {
	joinTaskCmd.Flags().StringVar(&joinContainer, "container", "rosa-boundary", "Container name to connect to")
	joinTaskCmd.Flags().StringVar(&joinCommand, "command", "/bin/bash", "Command to run in the container")
	joinTaskCmd.Flags().BoolVar(&joinNoWait, "no-wait", false, "Do not wait for RUNNING state before connecting")
	rootCmd.AddCommand(joinTaskCmd)
}

func runJoinTask(cmd *cobra.Command, args []string) error {
	taskID := args[0]

	cfg, err := getConfig(false, false)
	if err != nil {
		return err
	}

	// Load ambient AWS credentials (from environment, instance profile, etc.)
	awsCfg, err := config.LoadDefaultConfig(cmd.Context(), config.WithRegion(cfg.AWSRegion))
	if err != nil {
		return fmt.Errorf("cannot load AWS credentials: %w\nRun start-task first or configure AWS credentials", err)
	}

	// Verify we have credentials by checking the identity
	creds, credsErr := awsCfg.Credentials.Retrieve(cmd.Context())
	if credsErr != nil || creds.AccessKeyID == "" {
		return fmt.Errorf("AWS credentials not configured\nRun start-task first or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY")
	}

	clusterName := cfg.ClusterName
	ecsClient := awsclient.NewECSClient(cfg.AWSRegion, clusterName, awsCfg.Credentials)

	output.Status("Cluster: %s", clusterName)
	output.Status("Task:    %s", taskID)

	return runJoinWithClient(cmd.Context(), ecsClient, cfg.AWSRegion, taskID, joinContainer, joinCommand, joinNoWait)
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

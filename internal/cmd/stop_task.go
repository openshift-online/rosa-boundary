package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

type stopTaskOptions struct {
	forceLogin bool
	reason     string
	wait       bool
}

func newStopTaskCmd() *cobra.Command {
	opts := &stopTaskOptions{}

	cmd := &cobra.Command{
		Use:   "stop-task <task-id>",
		Short: "Stop a running ECS task",
		Long: `Stop a running ECS Fargate task. The container's entrypoint will
receive SIGTERM and sync /home/sre to S3 before exiting.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.run(cmd, args[0])
		},
	}

	AddForceLoginFlag(cmd, &opts.forceLogin)
	cmd.Flags().StringVar(&opts.reason, "reason", "Investigation complete", "Reason for stopping the task")
	cmd.Flags().BoolVar(&opts.wait, "wait", false, "Wait for the task to reach STOPPED state")

	return cmd
}

func init() {
	rootCmd.AddCommand(newStopTaskCmd())
}

func (o *stopTaskOptions) run(cmd *cobra.Command, taskID string) error {
	authRes, err := GetAWSConfigWithOIDC(cmd, o.forceLogin)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	clusterName := authRes.Config.ClusterName
	credProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	ecsClient := awsclient.NewECSClient(authRes.Config.AWSRegion, clusterName, credProvider)

	output.Status("Stopping task...")
	output.Status("  Task:    %s", taskID)
	output.Status("  ECS Cluster: %s", clusterName)
	output.Status("  Reason:  %s", o.reason)

	if err := ecsClient.StopTask(cmd.Context(), taskID, o.reason); err != nil {
		return fmt.Errorf("stop task failed: %w", err)
	}

	output.Status("Task stop initiated")

	if o.wait {
		output.Status("Waiting for task to reach STOPPED state...")
		if err := ecsClient.WaitForStopped(cmd.Context(), taskID); err != nil {
			return fmt.Errorf("task did not reach STOPPED state: %w", err)
		}
		output.Status("Task stopped")
	} else {
		output.Status("\nMonitor task status:")
		output.Status("  rosa-boundary list-tasks --status STOPPED")
	}

	output.Status("\nThe container entrypoint will:")
	output.Status("  1. Receive SIGTERM signal")
	output.Status("  2. Sync /home/sre to S3")
	output.Status("  3. Exit gracefully")

	return nil
}

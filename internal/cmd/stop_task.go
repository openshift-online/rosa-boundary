package cmd

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/spf13/cobra"

	awsclient "github.com/openshift/rosa-boundary/internal/aws"
	"github.com/openshift/rosa-boundary/internal/output"
)

var stopTaskCmd = &cobra.Command{
	Use:   "stop-task <task-id>",
	Short: "Stop a running ECS task",
	Long: `Stop a running ECS Fargate task. The container's entrypoint will
receive SIGTERM and sync /home/sre to S3 before exiting.`,
	Args: cobra.ExactArgs(1),
	RunE: runStopTask,
}

var (
	stopReason string
	stopWait   bool
)

func init() {
	stopTaskCmd.Flags().StringVar(&stopReason, "reason", "Investigation complete", "Reason for stopping the task")
	stopTaskCmd.Flags().BoolVar(&stopWait, "wait", false, "Wait for the task to reach STOPPED state")
	rootCmd.AddCommand(stopTaskCmd)
}

func runStopTask(cmd *cobra.Command, args []string) error {
	taskID := args[0]

	cfg, err := getConfig(false, false)
	if err != nil {
		return err
	}

	awsCfg, err := config.LoadDefaultConfig(cmd.Context(), config.WithRegion(cfg.AWSRegion))
	if err != nil {
		return fmt.Errorf("cannot load AWS credentials: %w", err)
	}

	clusterName := cfg.ClusterName
	ecsClient := awsclient.NewECSClient(cfg.AWSRegion, clusterName, awsCfg.Credentials)

	output.Status("Stopping task...")
	output.Status("  Task:    %s", taskID)
	output.Status("  Cluster: %s", clusterName)
	output.Status("  Reason:  %s", stopReason)

	if err := ecsClient.StopTask(cmd.Context(), taskID, stopReason); err != nil {
		return fmt.Errorf("stop task failed: %w", err)
	}

	output.Status("Task stop initiated")

	if stopWait {
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

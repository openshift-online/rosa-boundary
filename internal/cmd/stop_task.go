package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/spf13/cobra"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/output"
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
	stopYes    bool
)

func init() {
	addOutputFlag(stopTaskCmd, false)
	stopTaskCmd.Flags().StringVar(&stopReason, "reason", "Investigation complete", "Reason for stopping the task")
	stopTaskCmd.Flags().BoolVar(&stopWait, "wait", false, "Wait for the task to reach STOPPED state")
	rootCmd.AddCommand(stopTaskCmd)
}

func runStopTask(cmd *cobra.Command, args []string) error {
	taskID := args[0]

	authRes := cachedAuthResult

	clusterName := authRes.Config.ClusterName
	credProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	ecsClient := awsclient.NewECSClient(authRes.Config.AWSRegion, clusterName, credProvider)
	format, err := commandOutput(cmd)
	if err != nil {
		return err
	}
	task, err := ecsClient.DescribeTask(cmd.Context(), taskID)
	if err != nil {
		return fmt.Errorf("cannot resolve session before stopping: %w", err)
	}
	if task.Status == "STOPPED" {
		return fmt.Errorf("session %s is already STOPPED", taskID)
	}
	output.Status("Profile: %s Account: %s Region: %s", newSelectedProfile, authRes.Config.AccountID, authRes.Config.AWSRegion)
	output.Status("Session %s (cluster %s; investigation %s; owner %s)", taskID, task.Tags["cluster_id"], task.Tags["investigation_id"], task.Tags["username"])
	if !stopYes {
		if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
			return fmt.Errorf("--yes is required without a terminal")
		}
		fmt.Fprint(os.Stderr, "Stop this session? [y/N]: ")
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() || !strings.EqualFold(strings.TrimSpace(scanner.Text()), "y") {
			return fmt.Errorf("aborted")
		}
	}

	output.Status("Stopping session...")
	output.Status("  Session: %s", taskID)
	output.Status("  ECS Cluster: %s", clusterName)
	output.Status("  Reason:  %s", stopReason)

	if err := ecsClient.StopTask(cmd.Context(), taskID, stopReason); err != nil {
		return fmt.Errorf("stop task failed: %w", err)
	}

	output.Status("Session stop initiated")

	if stopWait {
		output.Status("Waiting for session to reach STOPPED state...")
		if err := ecsClient.WaitForStopped(cmd.Context(), taskID); err != nil {
			return fmt.Errorf("task did not reach STOPPED state: %w", err)
		}
		output.Status("Session stopped")
	} else {
		output.Status("\nMonitor task status:")
		output.Status("  rosa-boundary --profile %q session list --status all --region %q --ecs-cluster %q", newSelectedProfile, authRes.Config.AWSRegion, clusterName)
	}
	if format == "json" {
		status := "STOPPING"
		if stopWait {
			status = "STOPPED"
		}
		return output.JSON(map[string]any{"profile": newSelectedProfile, "cluster_id": task.Tags["cluster_id"], "investigation_id": task.Tags["investigation_id"], "session_id": taskID, "status": status, "waited": stopWait})
	}
	if _, err := fmt.Fprintf(os.Stdout, "Session %s stop requested (profile %s). Audit sync must be verified separately.\n", taskID, newSelectedProfile); err != nil {
		return err
	}

	output.Status("\nThe container entrypoint attempts to:")
	output.Status("  1. Receive SIGTERM signal")
	output.Status("  2. Sync non-credential /home/sre files to S3 (verify separately)")
	output.Status("  3. Exit gracefully")

	return nil
}

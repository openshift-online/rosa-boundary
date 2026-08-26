package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

var closeInvestigationCmd = &cobra.Command{
	Use:   "close-investigation",
	Short: "Close an investigation: stop tasks, deregister task defs, delete EFS access point",
	Long: `Close an investigation workspace by:
  1. Finding the EFS access point for the investigation
  2. Stopping any running tasks (requires --force if tasks are running)
  3. Deregistering associated task definitions
  4. Deleting the EFS access point (prompts for confirmation unless --yes)

Note: The EFS data remains on the filesystem after the access point is deleted.
Use --efs-filesystem-id or set efs_filesystem_id in your config.`,
	Args: cobra.NoArgs,
	RunE: runCloseInvestigation,
}

var (
	closeClusterID       string
	closeInvestigationID string
	closeForce           bool
	closeYes             bool
	closeOutputFormat    string
)

func init() {
	closeInvestigationCmd.Flags().StringVar(&closeClusterID, "cluster-id", "", "Cluster ID (required)")
	closeInvestigationCmd.Flags().StringVar(&closeInvestigationID, "investigation-id", "", "Investigation ID (required)")
	closeInvestigationCmd.Flags().BoolVar(&closeForce, "force", false, "Stop running tasks before deleting (default: error if tasks are running)")
	closeInvestigationCmd.Flags().BoolVar(&closeYes, "yes", false, "Skip confirmation prompt for EFS access point deletion")
	closeInvestigationCmd.Flags().StringVar(&closeOutputFormat, "output", "text", "Output format: text or json")
	_ = closeInvestigationCmd.MarkFlagRequired("cluster-id")
	_ = closeInvestigationCmd.MarkFlagRequired("investigation-id")
	rootCmd.AddCommand(closeInvestigationCmd)
}

func runCloseInvestigation(cmd *cobra.Command, args []string) error {
	if err := validateTextOrJSONOutputFormat(closeOutputFormat); err != nil {
		return err
	}

	authRes := cachedAuthResult

	if authRes.Config.EFSFilesystemID == "" {
		return fmt.Errorf("EFS filesystem ID is required; set --efs-filesystem-id, ROSA_BOUNDARY_EFS_FILESYSTEM_ID, or efs_filesystem_id in config")
	}

	credProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	efsClient := awsclient.NewEFSClient(authRes.Config.AWSRegion, authRes.Config.EFSFilesystemID, credProvider)
	ecsClient := awsclient.NewECSClient(authRes.Config.AWSRegion, authRes.Config.ClusterName, credProvider)

	// Step 1: Find EFS access point
	output.Status("=== Step 1: Finding EFS Access Point ===")
	output.Status("Cluster:        %s", closeClusterID)
	output.Status("Investigation:  %s", closeInvestigationID)

	ap, err := efsClient.FindAccessPointByTags(cmd.Context(), closeClusterID, closeInvestigationID)
	if err != nil {
		return fmt.Errorf("failed to find EFS access point: %w", err)
	}
	if ap == nil {
		return fmt.Errorf("no EFS access point found for cluster %q investigation %q", closeClusterID, closeInvestigationID)
	}
	output.Status("Found access point: %s (path: %s)", ap.AccessPointID, ap.Path)

	// Step 2: Check for running tasks
	output.Status("\n=== Step 2: Checking for Running Tasks ===")
	runningTasks, err := ecsClient.ListTasksByInvestigation(cmd.Context(), closeInvestigationID)
	if err != nil {
		return fmt.Errorf("failed to list tasks: %w", err)
	}

	if len(runningTasks) > 0 {
		output.Status("Found %d running task(s):", len(runningTasks))
		for _, t := range runningTasks {
			output.Status("  %s", t.TaskID)
		}
		if !closeForce {
			return fmt.Errorf("%d task(s) are still running; use --force to stop them first", len(runningTasks))
		}
		output.Status("Stopping running tasks (--force)...")
		for _, t := range runningTasks {
			if stopErr := ecsClient.StopTask(cmd.Context(), t.TaskID, "Investigation closed via rosa-boundary close-investigation"); stopErr != nil {
				return fmt.Errorf("failed to stop task %s: %w", t.TaskID, stopErr)
			}
			output.Status("  Stopped: %s", t.TaskID)
		}
		output.Status("Waiting for tasks to stop...")
		for _, t := range runningTasks {
			if waitErr := ecsClient.WaitForStopped(cmd.Context(), t.TaskID); waitErr != nil {
				output.Status("  Warning: task %s may not have stopped cleanly: %v", t.TaskID, waitErr)
			}
		}
	} else {
		output.Status("No running tasks found")
	}

	// Step 3: Deregister task definitions
	output.Status("\n=== Step 3: Deregistering Task Definitions ===")
	// Family prefix pattern: {clusterName}-{clusterID}-{investigationID}
	familyPrefix := fmt.Sprintf("%s-%s-%s", authRes.Config.ClusterName, closeClusterID, closeInvestigationID)
	output.Status("Family prefix: %s", familyPrefix)

	taskDefARNs, err := ecsClient.ListTaskDefinitionsByFamily(cmd.Context(), familyPrefix)
	if err != nil {
		return fmt.Errorf("failed to list task definitions: %w", err)
	}

	if len(taskDefARNs) == 0 {
		output.Status("No task definitions found (already deregistered or never created)")
	} else {
		output.Status("Found %d task definition(s)", len(taskDefARNs))
		for _, arn := range taskDefARNs {
			if deregErr := ecsClient.DeregisterTaskDefinition(cmd.Context(), arn); deregErr != nil {
				output.Status("  Warning: failed to deregister %s: %v", arn, deregErr)
			} else {
				output.Status("  Deregistered: %s", arn)
			}
		}
	}

	// Step 4: Delete EFS access point (with confirmation)
	output.Status("\n=== Step 4: Deleting EFS Access Point ===")
	output.Status("Access Point: %s", ap.AccessPointID)
	output.Status("Path:         %s", ap.Path)

	if !closeYes {
		fmt.Fprintf(os.Stderr, "\nDelete EFS access point %s? This cannot be undone. [y/N]: ", ap.AccessPointID)
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() || !strings.EqualFold(strings.TrimSpace(scanner.Text()), "y") {
			return fmt.Errorf("aborted")
		}
	}

	if err := efsClient.DeleteAccessPoint(cmd.Context(), ap.AccessPointID); err != nil {
		return fmt.Errorf("failed to delete EFS access point: %w", err)
	}

	output.Status("EFS access point deleted")

	if closeOutputFormat == "json" {
		summary := map[string]any{
			"cluster":           closeClusterID,
			"investigation_id":  closeInvestigationID,
			"access_point_id":   ap.AccessPointID,
			"tasks_stopped":     len(runningTasks),
			"task_defs_removed": len(taskDefARNs),
		}
		if err := output.JSON(summary); err != nil {
			return err
		}
	} else {
		printCloseInvestigationSummary(closeClusterID, closeInvestigationID, ap.AccessPointID, len(runningTasks), len(taskDefARNs))
	}

	return nil
}

func printCloseInvestigationSummary(cluster, investigationID, accessPointID string, tasksStopped, taskDefsRemoved int) {
	fmt.Fprintln(os.Stderr, "\n========================================")
	fmt.Fprintln(os.Stderr, "Investigation Closed")
	fmt.Fprintln(os.Stderr, "========================================")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  Cluster:           %s\n", cluster)
	fmt.Fprintf(os.Stderr, "  Investigation:     %s\n", investigationID)
	fmt.Fprintf(os.Stderr, "  Access Point:      %s (deleted)\n", accessPointID)
	fmt.Fprintf(os.Stderr, "  Tasks Stopped:     %d\n", tasksStopped)
	fmt.Fprintf(os.Stderr, "  Task Defs Removed: %d\n", taskDefsRemoved)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Note: EFS data is preserved on the filesystem.")
}

package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

var listTasksCmd = &cobra.Command{
	Use:   "list-tasks",
	Short: "List ECS tasks in the cluster",
	Long: `List running (or stopped) ECS tasks in the configured ECS cluster,
including tag metadata such as cluster_id, investigation_id, and username.`,
	RunE: runListTasks,
}

var (
	listStatus       string
	listOutputFormat string
)

func init() {
	listTasksCmd.Flags().StringVar(&listStatus, "status", "RUNNING", "Task status filter: RUNNING, STOPPED, or all")
	listTasksCmd.Flags().StringVar(&listOutputFormat, "output", "text", "Output format: text or json")
	rootCmd.AddCommand(listTasksCmd)
}

// validateListTasksStatus normalizes and validates --status for list-tasks.
func validateListTasksStatus(status string) (string, error) {
	desiredStatus := strings.ToUpper(status)
	switch desiredStatus {
	case "RUNNING", "STOPPED", "ALL":
		return desiredStatus, nil
	default:
		return "", fmt.Errorf("invalid --status %q: must be RUNNING, STOPPED, or all", status)
	}
}

func runListTasks(cmd *cobra.Command, args []string) error {
	desiredStatus, err := validateListTasksStatus(listStatus)
	if err != nil {
		return err
	}
	if err := validateTextOrJSONOutputFormat(listOutputFormat); err != nil {
		return err
	}

	authRes := getAuthResult(cmd)

	clusterName := authRes.Config.ClusterName
	credProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	ecsClient := awsclient.NewECSClient(authRes.Config.AWSRegion, clusterName, credProvider)

	debugf("Listing tasks in ECS cluster %s with status %q", clusterName, desiredStatus)

	var tasks []awsclient.TaskSummary

	if desiredStatus == "ALL" {
		running, listErr := ecsClient.ListRunningTasks(cmd.Context(), "RUNNING")
		if listErr != nil {
			return fmt.Errorf("cannot list tasks: %w", listErr)
		}
		stopped, listErr := ecsClient.ListRunningTasks(cmd.Context(), "STOPPED")
		if listErr != nil {
			return fmt.Errorf("cannot list tasks: %w", listErr)
		}
		tasks = append(running, stopped...)
	} else {
		var listErr error
		tasks, listErr = ecsClient.ListRunningTasks(cmd.Context(), desiredStatus)
		if listErr != nil {
			return fmt.Errorf("cannot list tasks: %w", listErr)
		}
	}

	if listOutputFormat == "json" {
		return output.JSON(tasks)
	}

	tbl := output.NewTable("TASK ID", "STATUS", "CLUSTER", "INVESTIGATION", "USERNAME", "STARTED")
	tbl.PrintHeader()

	for _, t := range tasks {
		startedAt := ""
		if t.StartedAt != nil {
			startedAt = t.StartedAt.Format("2006-01-02 15:04")
		}
		tbl.PrintRow(
			t.TaskID,
			t.Status,
			t.Tags["cluster_id"],
			t.Tags["investigation_id"],
			t.Tags["username"],
			startedAt,
		)
	}
	tbl.Flush()

	if len(tasks) == 0 {
		output.Status("No tasks found")
	}

	return nil
}

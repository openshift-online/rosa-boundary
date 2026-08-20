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

func runListTasks(cmd *cobra.Command, args []string) error {
	desiredStatus := strings.ToUpper(listStatus)
	switch desiredStatus {
	case "RUNNING", "STOPPED", "ALL":
	default:
		return fmt.Errorf("invalid --status %q: must be RUNNING, STOPPED, or all", listStatus)
	}

	switch listOutputFormat {
	case "text", "json":
	default:
		return fmt.Errorf("invalid --output %q: must be text or json", listOutputFormat)
	}

	authRes := getAuthResult(cmd)

	clusterName := authRes.Config.ClusterName
	credProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	ecsClient := awsclient.NewECSClient(authRes.Config.AWSRegion, clusterName, credProvider)

	debugf("Listing tasks in ECS cluster %s with status %q", clusterName, desiredStatus)

	var tasks []awsclient.TaskSummary
	var err error

	if desiredStatus == "ALL" {
		running, err := ecsClient.ListRunningTasks(cmd.Context(), "RUNNING")
		if err != nil {
			return fmt.Errorf("cannot list tasks: %w", err)
		}
		stopped, err := ecsClient.ListRunningTasks(cmd.Context(), "STOPPED")
		if err != nil {
			return fmt.Errorf("cannot list tasks: %w", err)
		}
		tasks = append(running, stopped...)
	} else {
		tasks, err = ecsClient.ListRunningTasks(cmd.Context(), desiredStatus)
		if err != nil {
			return fmt.Errorf("cannot list tasks: %w", err)
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

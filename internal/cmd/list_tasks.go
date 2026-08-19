package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

type listTasksOptions struct {
	forceLogin bool
	status     string
	output     string
}

func newListTasksCmd() *cobra.Command {
	opts := &listTasksOptions{}

	cmd := &cobra.Command{
		Use:   "list-tasks",
		Short: "List ECS tasks in the cluster",
		Long: `List running (or stopped) ECS tasks in the configured ECS cluster,
including tag metadata such as cluster_id, investigation_id, and username.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.run(cmd)
		},
	}

	AddForceLoginFlag(cmd, &opts.forceLogin)
	cmd.Flags().StringVar(&opts.status, "status", "RUNNING", "Task status filter: RUNNING, STOPPED, or all")
	cmd.Flags().StringVar(&opts.output, "output", "text", "Output format: text or json")

	return cmd
}

func init() {
	rootCmd.AddCommand(newListTasksCmd())
}

func (o *listTasksOptions) run(cmd *cobra.Command) error {
	desiredStatus := strings.ToUpper(o.status)
	switch desiredStatus {
	case "RUNNING", "STOPPED", "ALL":
	default:
		return fmt.Errorf("invalid --status %q: must be RUNNING, STOPPED, or all", o.status)
	}

	switch o.output {
	case "text", "json":
	default:
		return fmt.Errorf("invalid --output %q: must be text or json", o.output)
	}

	authRes, err := GetAWSConfigWithOIDC(cmd, o.forceLogin)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	clusterName := authRes.Config.ClusterName
	credProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	ecsClient := awsclient.NewECSClient(authRes.Config.AWSRegion, clusterName, credProvider)

	debugf("Listing tasks in ECS cluster %s with status %q", clusterName, desiredStatus)

	var tasks []awsclient.TaskSummary
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

	if o.output == "json" {
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

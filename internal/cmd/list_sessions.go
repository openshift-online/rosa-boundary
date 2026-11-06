package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

var (
	listStatus       string
	listOutputFormat string
)

func validateListSessionsStatus(status string) (string, error) {
	desiredStatus := strings.ToUpper(status)
	switch desiredStatus {
	case "RUNNING", "STOPPED", "ALL":
		return desiredStatus, nil
	default:
		return "", fmt.Errorf("invalid --status %q: must be RUNNING, STOPPED, or all", status)
	}
}

func runListSessions(cmd *cobra.Command, args []string) error {
	desiredStatus, err := validateListSessionsStatus(listStatus)
	if err != nil {
		return err
	}
	if err := validateTextOrJSONOutputFormat(listOutputFormat); err != nil {
		return err
	}

	authRes := cachedAuthResult

	clusterName := authRes.Config.ClusterName
	credProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	ecsClient := awsclient.NewECSClient(authRes.Config.AWSRegion, clusterName, credProvider)

	if err := debugf("Listing sessions in ECS cluster %s with status %q", clusterName, desiredStatus); err != nil {
		return fmt.Errorf("debug output failed: %w", err)
	}

	var tasks []awsclient.TaskSummary

	if desiredStatus == "ALL" {
		running, listErr := ecsClient.ListRunningTasks(cmd.Context(), "RUNNING")
		if listErr != nil {
			return fmt.Errorf("cannot list sessions; verify the selected profile's account, region, ECS cluster and access permissions: %w", listErr)
		}
		stopped, listErr := ecsClient.ListRunningTasks(cmd.Context(), "STOPPED")
		if listErr != nil {
			return fmt.Errorf("cannot list sessions; verify the selected profile's account, region, ECS cluster and access permissions: %w", listErr)
		}
		tasks = append(running, stopped...)
	} else {
		var listErr error
		tasks, listErr = ecsClient.ListRunningTasks(cmd.Context(), desiredStatus)
		if listErr != nil {
			return fmt.Errorf("cannot list sessions; verify the selected profile's account, region, ECS cluster and access permissions: %w", listErr)
		}
	}

	if listOutputFormat == "json" {
		rows := make([]map[string]any, 0, len(tasks))
		for _, task := range tasks {
			owner := task.Tags["uuid"]
			if owner == "" {
				owner = task.Tags["username"]
			}
			rows = append(rows, map[string]any{
				"session_id": task.TaskID, "session_arn": task.TaskARN,
				"cluster_id": task.Tags["cluster_id"], "investigation_id": task.Tags["investigation_id"],
				"ecs_cluster": task.ClusterName, "status": task.Status,
				"owner": owner, "started_at": task.StartedAt,
			})
		}
		return output.JSON(map[string]any{"profile": selectedProfile, "sessions": rows})
	}

	tbl := output.NewTable("SESSION ID", "STATUS", "CLUSTER", "INVESTIGATION", "OWNER", "STARTED")
	tbl.PrintHeader()

	for _, t := range tasks {
		startedAt := ""
		if t.StartedAt != nil {
			startedAt = t.StartedAt.Format("2006-01-02 15:04")
		}
		owner := t.Tags["uuid"]
		if owner == "" {
			owner = t.Tags["username"]
		}
		tbl.PrintRow(
			t.TaskID,
			t.Status,
			t.Tags["cluster_id"],
			t.Tags["investigation_id"],
			owner,
			startedAt,
		)
	}
	tbl.Flush()

	if len(tasks) == 0 {
		output.Status("No sessions found")
	}

	return nil
}

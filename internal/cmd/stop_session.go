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

var (
	stopReason string
	stopWait   bool
	stopYes    bool
)

func runStopSession(cmd *cobra.Command, args []string) error {
	sessionID := args[0]

	authRes := cachedAuthResult

	clusterName := authRes.Config.ClusterName
	credProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	ecsClient := awsclient.NewECSClient(authRes.Config.AWSRegion, clusterName, credProvider)
	format, err := commandOutput(cmd)
	if err != nil {
		return err
	}
	task, err := ecsClient.DescribeTask(cmd.Context(), sessionID)
	if err != nil {
		return fmt.Errorf("cannot resolve session before stopping; verify the session ID and selected deployment with 'rosa-boundary session list --status all': %w", err)
	}
	if task.Status == "STOPPED" {
		return fmt.Errorf("session %s is already STOPPED; verify its audit evidence, then use 'rosa-boundary investigation close' if the workspace is no longer needed", sessionID)
	}
	printStopSessionTarget(selectedProfile, authRes.Config.AccountID, authRes.Config.AWSRegion, sessionID, task)
	if !stopYes {
		if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
			return fmt.Errorf("--yes is required without a terminal; run interactively or pass --yes only after confirming the session ID")
		}
		fmt.Fprint(os.Stderr, "Stop this session? [y/N]: ")
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() || !strings.EqualFold(strings.TrimSpace(scanner.Text()), "y") {
			return fmt.Errorf("aborted")
		}
	}

	output.Status("Stopping session...")
	output.Status("  Session: %s", sessionID)
	output.Status("  ECS Cluster: %s", clusterName)
	output.Status("  Reason:  %s", stopReason)

	if err := ecsClient.StopTask(cmd.Context(), sessionID, stopReason); err != nil {
		return fmt.Errorf("stop session failed: %w", err)
	}

	output.Status("Session stop initiated")

	if stopWait {
		output.Status("Waiting for session to reach STOPPED state...")
		if err := ecsClient.WaitForStopped(cmd.Context(), sessionID); err != nil {
			return fmt.Errorf("session did not reach STOPPED state; check 'rosa-boundary session list --status all' for the selected profile and verify audit evidence before closing: %w", err)
		}
		output.Status("Session stopped")
	} else {
		output.Status("\nMonitor session status:")
		output.Status("  rosa-boundary --profile %q session list --status all --region %q --ecs-cluster %q", selectedProfile, authRes.Config.AWSRegion, clusterName)
	}
	if err := printStopSessionResult(format, selectedProfile, sessionID, task, stopWait); err != nil {
		return err
	}
	if format == "json" {
		return nil
	}

	output.Status("\nThe container entrypoint attempts to:")
	output.Status("  1. Receive SIGTERM signal")
	output.Status("  2. Sync non-credential /home/sre files to S3 (verify separately)")
	output.Status("  3. Exit gracefully")

	return nil
}

func printStopSessionTarget(profile, account, region, sessionID string, task *awsclient.TaskSummary) {
	output.Status("Profile: %s", profile)
	output.Status("Account: %s", account)
	output.Status("Region: %s", region)
	output.Status("Session ID: %s", sessionID)
	output.Status("Cluster: %s", task.Tags["cluster_id"])
	output.Status("Investigation: %s", task.Tags["investigation_id"])
	output.Status("Owner: %s", task.Tags["username"])
	output.Status("Closing this session stops its task and leaves the investigation open.")
}

func printStopSessionResult(format, profile, sessionID string, task *awsclient.TaskSummary, waited bool) error {
	if format == "json" {
		status := "STOPPING"
		if waited {
			status = "STOPPED"
		}
		return output.JSON(map[string]any{"profile": profile, "cluster_id": task.Tags["cluster_id"], "investigation_id": task.Tags["investigation_id"], "session_id": sessionID, "status": status, "waited": waited})
	}
	_, err := fmt.Fprintf(os.Stdout, "Session %s stop requested (profile %s). Audit sync must be verified separately.\n", sessionID, profile)
	return err
}

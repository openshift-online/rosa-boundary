package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strings"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/output"
	"github.com/spf13/cobra"
)

type sessionCloser interface {
	ListRunningTasks(context.Context, string) ([]awsclient.TaskSummary, error)
	StopTask(context.Context, string, string) error
	WaitForStopped(context.Context, string) error
}

func runStopAllSessions(cmd *cobra.Command) error {
	auth := cachedAuthResult
	subject, err := authenticatedSubject(auth.IDToken)
	if err != nil {
		return err
	}
	if !validOwnerSubject(subject) {
		return fmt.Errorf("authenticated ID token lacks a valid subject")
	}
	client := awsclient.NewECSClient(auth.Config.AWSRegion, auth.Config.ClusterName, awsclient.StaticCredentialsProvider(auth.Credentials))
	return closeAllSessions(cmd, client, subject, auth.Config.AccountID, auth.Config.AWSRegion)
}

// closeAllSessions confirms the complete owned target set before stopping any task.
// Desired RUNNING includes tasks still starting; stopping sessions are excluded.
func closeAllSessions(cmd *cobra.Command, client sessionCloser, subject, account, region string) error {
	if !validOwnerSubject(subject) {
		return fmt.Errorf("authenticated ID token lacks a valid subject")
	}
	format, err := commandOutput(cmd)
	if err != nil {
		return err
	}
	tasks, err := client.ListRunningTasks(cmd.Context(), "RUNNING")
	if err != nil {
		return fmt.Errorf("cannot list active sessions; no sessions were closed: %w", err)
	}
	targets := make([]awsclient.TaskSummary, 0)
	seen := make(map[string]bool)
	for _, task := range tasks {
		if task.Tags["oidc_sub"] != subject || task.TaskID == "" || task.Status == "STOPPED" || task.DesiredStatus == "STOPPED" || seen[task.TaskID] {
			continue
		}
		seen[task.TaskID] = true
		targets = append(targets, task)
		printStopSessionTarget(selectedProfile, account, region, task.TaskID, &task)
	}
	if len(targets) > 0 && !stopYes {
		if err := requireTerminal(); err != nil {
			return fmt.Errorf("--yes is required without a terminal: %w", err)
		}
		if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Stop all %d sessions listed above? [y/N]: ", len(targets)); err != nil {
			return fmt.Errorf("write confirmation: %w", err)
		}
		scanner := bufio.NewScanner(cmd.InOrStdin())
		if !scanner.Scan() || !strings.EqualFold(strings.TrimSpace(scanner.Text()), "y") {
			return fmt.Errorf("aborted")
		}
	}
	ids := make([]string, 0, len(targets))
	var failures []error
	// Request every stop before waiting for any task's shutdown.
	for _, task := range targets {
		if err := client.StopTask(cmd.Context(), task.TaskID, stopReason); err != nil {
			failures = append(failures, fmt.Errorf("session %s stop failed: %w", task.TaskID, err))
			continue
		}
		ids = append(ids, task.TaskID)
		output.Status("Session %s stop requested; investigation remains open", task.TaskID)
	}
	if stopWait {
		for _, id := range ids {
			if err := client.WaitForStopped(cmd.Context(), id); err != nil {
				failures = append(failures, fmt.Errorf("session %s did not reach STOPPED: %w", id, err))
			}
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("bulk close incomplete (stop requested for %s); check session list --status all and verify audit evidence: %w", strings.Join(ids, ", "), errors.Join(failures...))
	}
	if format == "json" {
		status := "STOPPING"
		if stopWait {
			status = "STOPPED"
		}
		return output.JSONTo(cmd.OutOrStdout(), map[string]any{"profile": selectedProfile, "session_ids": ids, "status": status, "waited": stopWait, "investigations_closed": false})
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Stop requested for %d sessions. Investigations remain open. Audit sync must be verified separately.\n", len(ids))
	return err
}

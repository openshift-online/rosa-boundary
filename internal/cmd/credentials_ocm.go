package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/config"
	ocmcredentials "github.com/openshift-online/rosa-boundary/internal/credentials/ocm"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

const credentialContainer = "rosa-boundary"

var (
	credentialsOCMURL  string
	credentialsOCMFlow string
)

type ocmTokenAcquirer interface {
	Acquire(context.Context, ocmcredentials.Flow) (ocmcredentials.Token, error)
}

type ocmCredentialTransfer interface {
	Configure(context.Context, string, *awsclient.ExecuteCommandSession, *awsclient.TemporaryCredentials, []byte) error
	Clear(context.Context, string, *awsclient.ExecuteCommandSession, *awsclient.TemporaryCredentials) error
}

var newOCMTokenAcquirer = func() ocmTokenAcquirer {
	authenticator := ocmcredentials.NewAuthenticator(output.Status)
	authenticator.Debug = credentialDebugf
	return authenticator
}

var newOCMCredentialTransfer = func() ocmCredentialTransfer {
	transfer := ocmcredentials.NewTransfer()
	transfer.Debug = credentialDebugf
	return transfer
}

// Discovery is deliberately separate from the credential transfer path: an
// omitted ID can only list, never request an OCM token or start ECS Exec.
var listCredentialSessions = func(ctx context.Context, authResult *AuthResult, subject string) ([]awsclient.TaskSummary, error) {
	return newCredentialECSClient(authResult).ListOwnedRunningCredentialTasks(ctx, subject)
}

func optionalCredentialSessionID(_ *cobra.Command, args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("unexpected argument %q (expected at most one <session-id>)", args[1])
	}
	if len(args) == 1 && strings.TrimSpace(args[0]) == "" {
		return fmt.Errorf("<session-id> must not be empty")
	}
	return nil
}

func shellArgument(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func validOwnerSubject(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

func credentialDeploymentOverrides(authResult *AuthResult) (string, error) {
	_, saved, err := config.ReadSavedProfile(selectedProfile)
	if err != nil {
		return "", fmt.Errorf("read saved profile for credential suggestion: %w", err)
	}
	var flags string
	if joinNeedsOverride(authResult.Config.AWSRegion, saved.AWSRegion, "ROSA_BOUNDARY_AWS_REGION") {
		flags += " --region " + shellArgument(authResult.Config.AWSRegion)
	}
	if joinNeedsOverride(authResult.Config.ClusterName, saved.ClusterName, "ROSA_BOUNDARY_ECS_CLUSTER_NAME") {
		flags += " --ecs-cluster " + shellArgument(authResult.Config.ClusterName)
	}
	return flags, nil
}

func guideCredentialSession(cmd *cobra.Command, action string) error {
	authResult := getAuthResult(cmd)
	subject, err := authenticatedSubject(authResult.IDToken)
	if err != nil {
		return err
	}
	if !validOwnerSubject(subject) {
		return fmt.Errorf("authenticated ID token lacks a valid subject")
	}
	tasks, err := listCredentialSessions(cmd.Context(), authResult, subject)
	if err != nil {
		// ECS errors can contain task identifiers; do not disclose unfiltered data.
		return fmt.Errorf("cannot discover RUNNING sessions in profile %q; verify ECS access and the selected deployment, then retry", selectedProfile)
	}
	overrides, err := credentialDeploymentOverrides(authResult)
	if err != nil {
		return err
	}
	eligible := make([]awsclient.TaskSummary, 0)
	for _, task := range tasks {
		owner := task.Tags["oidc_sub"]
		if task.Status == "RUNNING" && task.DesiredStatus != "STOPPED" &&
			task.TaskID != "" && validOwnerSubject(owner) && owner == subject {
			eligible = append(eligible, task)
		}
	}
	if len(eligible) == 0 {
		if format, _ := commandOutput(cmd); format == "json" {
			return output.JSONTo(cmd.OutOrStdout(), map[string]any{"profile": selectedProfile, "provider": "ocm", "action": action, "status": "selection_required", "eligible_count": 0, "credentials_changed": false})
		}
		suggestion := fmt.Sprintf("rosa-boundary --profile %s session credentials %s ocm <session-id>%s", shellArgument(selectedProfile), action, overrides)
		if action == "configure" && cmd.Flags().Changed("ocm-url") {
			suggestion += " --ocm-url " + shellArgument(flagString(cmd, "ocm-url"))
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "No eligible RUNNING sessions found in profile %q. Check your session ID and profile, or create a session; then run: %s\n", selectedProfile, suggestion)
		return err
	}
	if len(eligible) > 1 {
		if format, _ := commandOutput(cmd); format == "json" {
			return output.JSONTo(cmd.OutOrStdout(), map[string]any{"profile": selectedProfile, "provider": "ocm", "action": action, "status": "selection_required", "eligible_count": len(eligible), "credentials_changed": false})
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%d eligible RUNNING sessions found in profile %q. Inspect your sessions with rosa-boundary --profile %s session list --status RUNNING%s, then specify the correct session ID explicitly. No credentials were changed.\n", len(eligible), selectedProfile, shellArgument(selectedProfile), overrides)
		return err
	}
	task := eligible[0]
	suggestion := fmt.Sprintf("rosa-boundary --profile %s session credentials %s ocm %s%s", shellArgument(selectedProfile), action, shellArgument(task.TaskID), overrides)
	if cmd.Flags().Changed("use-device-code") {
		suggestion += fmt.Sprintf(" --use-device-code=%t", flagBool(cmd, "use-device-code"))
	}
	if action == "configure" {
		for _, flag := range []string{"ocm-url", "auth-flow"} {
			if cmd.Flags().Changed(flag) {
				suggestion += " --" + flag + " " + shellArgument(flagString(cmd, flag))
			}
		}
	}
	if format, _ := commandOutput(cmd); format == "json" {
		return output.JSONTo(cmd.OutOrStdout(), map[string]any{"profile": selectedProfile, "provider": "ocm", "action": action, "status": "selection_required", "eligible_count": 1, "credentials_changed": false, "session_id": task.TaskID, "cluster_id": task.Tags["cluster_id"], "investigation_id": task.Tags["investigation_id"], "session_status": task.Status, "suggested_command": suggestion})
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Session ID: %q\nCluster: %q\nInvestigation: %q\nStatus: %s\nNo credentials were changed. To %s OCM credentials, run:\n  %s\n", task.TaskID, task.Tags["cluster_id"], task.Tags["investigation_id"], task.Status, action, suggestion)
	return err
}

func runCredentialsConfigureOCM(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return guideCredentialSession(cmd, "configure")
	}
	environment, err := resolveConfigureOCMEnvironment()
	if err != nil {
		return err
	}
	authResult := getAuthResult(cmd)
	flow := defaultOCMFlow(authResult.Config.OIDCUseDeviceCode)
	if credentialsOCMFlow != "" || cmd.Flags().Changed("auth-flow") {
		flow, err = parseOCMFlow(credentialsOCMFlow)
		if err != nil {
			return err
		}
	}
	ecsClient := newCredentialECSClient(authResult)
	if err := configureOCMForSession(cmd.Context(), ecsClient, authResult.Config.AWSRegion, authResult.Credentials, args[0], environment, flow); err != nil {
		return err
	}
	return credentialActionResult(cmd, "configured", args[0], environment.Name)
}

func runCredentialsClearOCM(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return guideCredentialSession(cmd, "clear")
	}
	authResult := getAuthResult(cmd)
	ecsClient := newCredentialECSClient(authResult)
	if err := prepareCredentialSession(cmd.Context(), ecsClient, args[0]); err != nil {
		return err
	}
	if err := credentialDebugf("Requesting static OCM clear command through ECS Exec"); err != nil {
		return fmt.Errorf("debug output failed: %w", err)
	}
	session, err := ecsClient.ExecuteCommand(cmd.Context(), args[0], credentialContainer, ocmcredentials.ClearCommand)
	if err != nil {
		return fmt.Errorf("could not start OCM credential clear session; check that the Boundary session and its Exec agent are running, then retry or stop the session to remove task-scoped credentials: %w", err)
	}
	if err := credentialDebugf("ECS Exec clear session established: %s", session.SessionID); err != nil {
		return fmt.Errorf("debug output failed: %w", err)
	}
	if err := newOCMCredentialTransfer().Clear(cmd.Context(), authResult.Config.AWSRegion, session, authResult.Credentials); err != nil {
		return fmt.Errorf("could not clear OCM credentials; retry on the running session or stop the session to remove task-scoped credentials: %w", err)
	}
	output.Status("Cleared OCM credentials from session %s", args[0])
	return credentialActionResult(cmd, "cleared", args[0], "")
}

// credentialActionResult is called only after a successful credential transfer.
func credentialActionResult(cmd *cobra.Command, action, sessionID, environment string) error {
	if format, _ := commandOutput(cmd); format == "json" {
		result := map[string]any{"profile": selectedProfile, "provider": "ocm", "action": action, "session_id": sessionID}
		if environment != "" {
			result["environment"] = environment
		}
		return output.JSONTo(cmd.OutOrStdout(), result)
	}
	return nil
}

func newCredentialECSClient(authResult *AuthResult) *awsclient.ECSClient {
	provider := awsclient.StaticCredentialsProvider(authResult.Credentials)
	return awsclient.NewECSClient(authResult.Config.AWSRegion, authResult.Config.ClusterName, provider)
}

func configureOCMForSession(ctx context.Context, ecsClient *awsclient.ECSClient, region string, credentials *awsclient.TemporaryCredentials, sessionID string, environment ocmcredentials.Environment, flow ocmcredentials.Flow) error {
	if err := prepareCredentialSession(ctx, ecsClient, sessionID); err != nil {
		return err
	}
	output.Status("Requesting a fresh OCM access token for %s...", environment.Name)
	acquirer := newOCMTokenAcquirer()
	token, err := acquirer.Acquire(ctx, flow)
	if err != nil {
		return fmt.Errorf("OCM authentication failed; verify the selected OCM environment and complete the requested approval before retrying: %w", err)
	}
	if token.Expiry.IsZero() {
		output.Status("Fresh OCM access token acquired; server supplied no expiry")
	} else {
		output.Status("Fresh OCM access token acquired; expires at %s", token.Expiry.Format(time.RFC3339))
	}
	request, err := ocmcredentials.MarshalRequest(token.AccessToken, environment)
	token.AccessToken = ""
	if err != nil {
		return err
	}
	defer func() {
		for index := range request {
			request[index] = 0
		}
	}()

	output.Status("Uploading OCM access token to session %s...", sessionID)
	if err := credentialDebugf("Requesting static OCM configure command through ECS Exec"); err != nil {
		return fmt.Errorf("debug output failed: %w", err)
	}
	session, err := ecsClient.ExecuteCommand(ctx, sessionID, credentialContainer, ocmcredentials.ConfigureCommand)
	if err != nil {
		return fmt.Errorf("could not start OCM credential configure session; check that the Boundary session and its Exec agent are running, then retry: %w", err)
	}
	if err := credentialDebugf("ECS Exec configure session established: %s", session.SessionID); err != nil {
		return fmt.Errorf("debug output failed: %w", err)
	}
	if err := newOCMCredentialTransfer().Configure(ctx, region, session, credentials, request); err != nil {
		return fmt.Errorf("could not configure OCM credentials; verify the session is running, then retry with a fresh OCM approval: %w", err)
	}

	if token.Expiry.IsZero() {
		output.Status("Configured OCM credentials for session %s (%s)", sessionID, environment.Name)
	} else {
		output.Status("Configured OCM credentials for session %s (%s); expires at %s", sessionID, environment.Name, token.Expiry.Format(time.RFC3339))
	}
	return nil
}

func prepareCredentialSession(ctx context.Context, ecsClient *awsclient.ECSClient, sessionID string) error {
	if err := credentialDebugf("Checking access to session %s", sessionID); err != nil {
		return fmt.Errorf("debug output failed: %w", err)
	}
	task, err := ecsClient.DescribeTask(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("cannot access session %s; verify the ID and selected profile with 'rosa-boundary session list --status all': %w", sessionID, err)
	}
	if task.Status != "RUNNING" {
		return fmt.Errorf("session %s is not RUNNING (status: %s); configure or clear credentials on a running session", sessionID, task.Status)
	}
	if err := credentialDebugf("Session %s is RUNNING; waiting for ECS Exec agent", sessionID); err != nil {
		return fmt.Errorf("debug output failed: %w", err)
	}
	if err := ecsClient.WaitForExecAgent(ctx, sessionID, credentialContainer, 30*time.Second); err != nil {
		return fmt.Errorf("session %s exec agent is not ready; check the session status and retry when the agent is ready: %w", sessionID, err)
	}
	if err := credentialDebugf("Session %s ECS Exec agent is ready", sessionID); err != nil {
		return fmt.Errorf("debug output failed: %w", err)
	}
	return nil
}

func credentialDebugf(format string, args ...any) error {
	return output.Debug(format, args...)
}

func resolveConfigureOCMEnvironment() (ocmcredentials.Environment, error) {
	return ocmcredentials.ResolveEnvironment(credentialsOCMURL)
}

func parseOCMFlow(value string) (ocmcredentials.Flow, error) {
	flow := ocmcredentials.Flow(value)
	if flow != ocmcredentials.FlowAuthCode && flow != ocmcredentials.FlowDevice {
		return "", fmt.Errorf("unsupported OCM authentication flow %q; use auth-code or device", value)
	}
	return flow, nil
}

func defaultOCMFlow(device bool) ocmcredentials.Flow {
	if device {
		return ocmcredentials.FlowDevice
	}
	return ocmcredentials.FlowAuthCode
}

package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	ocmcredentials "github.com/openshift-online/rosa-boundary/internal/credentials/ocm"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

const credentialContainer = "rosa-boundary"

var (
	credentialsOCMURL      string
	credentialsOCMFlow     string
	resolvedOCMEnvironment *ocmcredentials.Environment
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

var credentialsConfigureOCMCmd = &cobra.Command{
	Use:   "ocm <task-id>",
	Short: "Issue and configure a fresh OCM access token",
	Args:  cobra.ExactArgs(1),
	RunE:  runCredentialsConfigureOCM,
}

var credentialsClearOCMCmd = &cobra.Command{
	Use:   "ocm <task-id>",
	Short: "Clear OCM and derived kubeconfig credentials",
	Args:  cobra.ExactArgs(1),
	RunE:  runCredentialsClearOCM,
}

func init() {
	credentialsConfigureOCMCmd.Flags().StringVar(&credentialsOCMURL, "ocm-url", "", "OCM environment alias or approved canonical API URL")
	credentialsConfigureOCMCmd.Flags().StringVar(&credentialsOCMFlow, "auth-flow", string(ocmcredentials.FlowAuthCode), "OCM authentication flow: auth-code or device")
	credentialsConfigureCmd.AddCommand(credentialsConfigureOCMCmd)
	credentialsClearCmd.AddCommand(credentialsClearOCMCmd)
}

func runCredentialsConfigureOCM(cmd *cobra.Command, args []string) error {
	environment, err := resolveConfigureOCMEnvironment()
	if err != nil {
		return err
	}
	flow, err := parseOCMFlow(credentialsOCMFlow)
	if err != nil {
		return err
	}
	authResult := getAuthResult(cmd)
	ecsClient := newCredentialECSClient(authResult)
	return configureOCMForTask(cmd.Context(), ecsClient, authResult.Config.AWSRegion, authResult.Credentials, args[0], environment, flow)
}

func runCredentialsClearOCM(cmd *cobra.Command, args []string) error {
	authResult := getAuthResult(cmd)
	ecsClient := newCredentialECSClient(authResult)
	if err := prepareCredentialTask(cmd.Context(), ecsClient, args[0]); err != nil {
		return err
	}
	credentialDebugf("Requesting static OCM clear command through ECS Exec")
	session, err := ecsClient.ExecuteCommand(cmd.Context(), args[0], credentialContainer, ocmcredentials.ClearCommand)
	if err != nil {
		return fmt.Errorf("start OCM credential clear session: %w", err)
	}
	credentialDebugf("ECS Exec clear session established: %s", session.SessionID)
	if err := newOCMCredentialTransfer().Clear(cmd.Context(), authResult.Config.AWSRegion, session, authResult.Credentials); err != nil {
		return fmt.Errorf("clear OCM credentials: %w", err)
	}
	output.Status("Cleared OCM credentials from task %s", args[0])
	return nil
}

func newCredentialECSClient(authResult *AuthResult) *awsclient.ECSClient {
	provider := awsclient.StaticCredentialsProvider(authResult.Credentials)
	return awsclient.NewECSClient(authResult.Config.AWSRegion, authResult.Config.ClusterName, provider)
}

func configureOCMForTask(ctx context.Context, ecsClient *awsclient.ECSClient, region string, credentials *awsclient.TemporaryCredentials, taskID string, environment ocmcredentials.Environment, flow ocmcredentials.Flow) error {
	output.Status("Requesting a fresh OCM access token for %s...", environment.Name)
	token, err := newOCMTokenAcquirer().Acquire(ctx, flow)
	if err != nil {
		return fmt.Errorf("OCM authentication failed: %w", err)
	}
	if token.Expiry.IsZero() {
		credentialDebugf("Fresh OCM access token acquired; server supplied no expiry")
	} else {
		credentialDebugf("Fresh OCM access token acquired; expires at %s", token.Expiry.Format(time.RFC3339))
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

	if err := prepareCredentialTask(ctx, ecsClient, taskID); err != nil {
		return err
	}
	credentialDebugf("Requesting static OCM configure command through ECS Exec")
	session, err := ecsClient.ExecuteCommand(ctx, taskID, credentialContainer, ocmcredentials.ConfigureCommand)
	if err != nil {
		return fmt.Errorf("start OCM credential configure session: %w", err)
	}
	credentialDebugf("ECS Exec configure session established: %s", session.SessionID)
	if err := newOCMCredentialTransfer().Configure(ctx, region, session, credentials, request); err != nil {
		return fmt.Errorf("configure OCM credentials: %w", err)
	}

	if token.Expiry.IsZero() {
		output.Status("Configured OCM credentials for task %s (%s)", taskID, environment.Name)
	} else {
		output.Status("Configured OCM credentials for task %s (%s); expires at %s", taskID, environment.Name, token.Expiry.Format(time.RFC3339))
	}
	return nil
}

func prepareCredentialTask(ctx context.Context, ecsClient *awsclient.ECSClient, taskID string) error {
	credentialDebugf("Checking access to task %s", taskID)
	task, err := ecsClient.DescribeTask(ctx, taskID)
	if err != nil {
		return fmt.Errorf("cannot access task %s: %w", taskID, err)
	}
	if task.Status != "RUNNING" {
		return fmt.Errorf("task %s is not RUNNING (status: %s)", taskID, task.Status)
	}
	credentialDebugf("Task %s is RUNNING; waiting for ECS Exec agent", taskID)
	if err := ecsClient.WaitForExecAgent(ctx, taskID, credentialContainer, 30*time.Second); err != nil {
		return fmt.Errorf("task %s exec agent is not ready: %w", taskID, err)
	}
	credentialDebugf("Task %s ECS Exec agent is ready", taskID)
	return nil
}

func credentialDebugf(format string, args ...any) {
	_ = output.Debug(format, args...)
}

func resolveConfigureOCMEnvironment() (ocmcredentials.Environment, error) {
	if resolvedOCMEnvironment != nil {
		return *resolvedOCMEnvironment, nil
	}
	environment, err := ocmcredentials.ResolveEnvironment(credentialsOCMURL)
	if err != nil {
		return ocmcredentials.Environment{}, err
	}
	resolvedOCMEnvironment = &environment
	return environment, nil
}

func parseOCMFlow(value string) (ocmcredentials.Flow, error) {
	flow := ocmcredentials.Flow(value)
	if flow != ocmcredentials.FlowAuthCode && flow != ocmcredentials.FlowDevice {
		return "", fmt.Errorf("unsupported OCM authentication flow %q; use auth-code or device", value)
	}
	return flow, nil
}

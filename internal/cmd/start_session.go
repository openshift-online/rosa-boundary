package cmd

import (
	"fmt"
	"os"
	"path"
	"strings"

	petname "github.com/dustinkirkland/golang-petname"
	"github.com/spf13/cobra"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/config"
	ocmcredentials "github.com/openshift-online/rosa-boundary/internal/credentials/ocm"
	"github.com/openshift-online/rosa-boundary/internal/lambda"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

var (
	startClusterID        string
	startInvestigationID  string
	startOCVersion        string
	sessionTimeoutSeconds int
	startConnect          bool
	startNoWait           bool
	startOutputFormat     string
	startCredentials      string
	startOCMURL           string
	startOCMFlow          string
)

func runStartSession(cmd *cobra.Command, args []string) (resultErr error) {
	switch startOutputFormat {
	case "text", "json":
	default:
		return fmt.Errorf("invalid --output %q: must be text or json", startOutputFormat)
	}

	configureOCM, ocmEnvironment, ocmFlow, err := validateStartCredentials(cmd.Flags().Changed("ocm-auth-flow"))
	if err != nil {
		return err
	}

	authRes := cachedAuthResult
	cfg := authRes.Config
	if configureOCM && !cmd.Flags().Changed("ocm-auth-flow") && startOCMFlow == "" {
		ocmFlow = defaultOCMFlow(cfg.OIDCUseDeviceCode)
	}

	clusterID := startClusterID

	investigationID := startInvestigationID
	if investigationID == "" {
		investigationID = petname.Generate(3, "-")
		output.Status("Generated investigation ID: %s", investigationID)
	}

	// Step 1: Call Lambda (SigV4-signed)
	output.Status("=== Step 1: Starting investigation session via Lambda ===")
	output.Status("Cluster:        %s", clusterID)
	output.Status("Investigation:  %s", investigationID)
	output.Status("OC Version:     %s", startOCVersion)
	output.Status("Session lifetime: %d seconds", sessionTimeoutSeconds)

	invokerCredProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	lambdaClient := lambda.New(cfg.LambdaFunctionName, cfg.AWSRegion, invokerCredProvider)
	lambdaResp, err := lambdaClient.CreateInvestigation(cmd.Context(), authRes.IDToken, lambda.InvestigationRequest{
		ClusterID:       clusterID,
		InvestigationID: investigationID,
		OCVersion:       startOCVersion,
		TaskTimeout:     sessionTimeoutSeconds,
		TaskTimeoutSet:  true,
	})
	if err != nil {
		return fmt.Errorf("lambda call failed (outcome may be unknown for %s/%s; inspect with rosa-boundary --profile %q session list --status all --region %q --ecs-cluster %q before retrying): %w", clusterID, investigationID, selectedProfile, cfg.AWSRegion, cfg.ClusterName, err)
	}

	// The Boundary session ID is the underlying ECS task ID.
	sessionID := path.Base(lambdaResp.TaskARN)
	defer func() {
		if resultErr == nil {
			return
		}
		resultErr = sessionCreationError(resultErr, sessionID, clusterID, investigationID, cfg.AWSRegion, cfg.ClusterName)
	}()

	// Use override role ARN if configured, otherwise use what Lambda returned
	roleARN := cfg.SRERoleARN
	if roleARN == "" {
		roleARN = lambdaResp.RoleARN
	}
	if roleARN == "" {
		return fmt.Errorf("no SRE role ARN available; configure sre_role_arn in the selected profile or ensure Lambda returns role_arn")
	}
	if err := checkRoleAccounts(cfg.AccountID, map[string]string{"sre_role_arn": roleARN}); err != nil {
		return fmt.Errorf("lambda returned a role outside the selected deployment: %w", err)
	}

	output.Status("Session launched: %s", sessionID)

	// Step 2: Assume SRE role
	output.Status("\n=== Step 2: Assuming Shared SRE Role ===")
	output.Status("Role: %s", roleARN)

	sessionName := "rosa-boundary-sre"
	if lambdaResp.Owner != "" {
		sessionName = "rosa-boundary-" + sanitizeSessionName(lambdaResp.Owner)
	}

	if err := debugf("Assuming role %s as session %s", roleARN, sessionName); err != nil {
		return fmt.Errorf("investigation %q created session %q, but debug output failed: %w", investigationID, sessionID, err)
	}

	pkce := auth.PKCEConfig{
		KeycloakURL: cfg.KeycloakURL,
		Realm:       cfg.KeycloakRealm,
		ClientID:    cfg.OIDCClientID,
	}

	// We use assumeRoleWithRetry to do the second assumption (SRE role) using the same OIDC token (which should be cached).
	// This also handles a retry if for some reason the token was invalidated in the split second since the last call.
	options, err := tokenOptions(cmd, cfg)
	if err != nil {
		return err
	}
	_, creds, err := assumeRoleWithRetryOptions(cmd.Context(), pkce, cfg.AWSRegion, roleARN, sessionName, false, options)
	if err != nil {
		return fmt.Errorf("role assumption failed: %w", err)
	}
	output.Status("Role assumed successfully")

	credProvider := awsclient.StaticCredentialsProvider(creds)

	// Use the configured ECS cluster name (from --ecs-cluster / config / env),
	// NOT the ROSA cluster ID from the Lambda response. The Lambda's cluster_id
	// is the investigation target, not the ECS cluster where tasks run.
	ecsCluster := cfg.ClusterName
	ecsClient := awsclient.NewECSClient(cfg.AWSRegion, ecsCluster, credProvider)

	// Step 3: Wait for RUNNING (unless --no-wait)
	if !startNoWait {
		output.Status("\n=== Step 3: Waiting for session to be RUNNING ===")
		output.Status("Session: %s", sessionID)
		if err := ecsClient.WaitForRunning(cmd.Context(), sessionID); err != nil {
			return fmt.Errorf("session did not reach RUNNING: %w", err)
		}
		output.Status("Session is RUNNING")
	}

	// Configure credentials only after the task and exec agent are ready, keeping
	// the freshly issued OCM token's useful lifetime as long as possible.
	if configureOCM {
		output.Status("\n=== Step 4: Configuring OCM Credentials ===")
		if err := configureOCMForSession(cmd.Context(), ecsClient, cfg.AWSRegion, creds, sessionID, ocmEnvironment, ocmFlow); err != nil {
			return sessionCredentialFailure(investigationID, sessionID, ecsCluster, cfg.AWSRegion, ocmEnvironment, ocmFlow, err)
		}
	}

	return finishStartSession(cmd, ecsClient, creds, ecsCluster, clusterID, investigationID, sessionID, cfg.AWSRegion,
		lambdaResp, roleARN, configureOCM)
}

// finishStartSession only reports success after the interactive shell exits.
// The task may remain RUNNING after the shell disconnects.
func finishStartSession(cmd *cobra.Command, ecsClient *awsclient.ECSClient, creds *awsclient.TemporaryCredentials,
	ecsCluster, clusterID, investigationID, sessionID, region string, lambdaResp *lambda.InvestigationResponse,
	roleARN string, configureOCM bool) error {
	// Auto-connect only after any requested credential configuration succeeds.
	if startConnect && !startNoWait {
		step := 4
		if configureOCM {
			step = 5
		}
		output.Status("\n=== Step %d: Connecting to session ===", step)
		if err := openInteractiveSession(cmd.Context(), ecsClient, region, creds, sessionID, "rosa-boundary", defaultExecCommand, false); err != nil {
			return err
		}
	}

	if startOutputFormat == "json" {
		return output.JSON(startSessionJSONResult(clusterID, investigationID, sessionID, ecsCluster, lambdaResp.TaskARN, startOCVersion, sessionTimeoutSeconds, lambdaResp.AccessPointID, roleARN, configureOCM, startNoWait, startConnect))
	}
	if err := printStartSessionSummary(ecsCluster, clusterID, investigationID, sessionID, region, startNoWait, startConnect); err != nil {
		return err
	}
	return nil
}

func sessionCreationError(cause error, sessionID, clusterID, investigationID, region, ecsCluster string) error {
	cleanup := fmt.Sprintf("rosa-boundary --profile %q session close %q --yes --region %q --ecs-cluster %q", selectedProfile, sessionID, region, ecsCluster)
	return fmt.Errorf("session %s created for %s/%s (profile %s; region %s; ECS cluster %s), then operation failed: %w; inspect session list --status all; cleanup: %s", sessionID, clusterID, investigationID, selectedProfile, region, ecsCluster, cause, cleanup)
}

func startSessionJSONResult(clusterID, investigationID, sessionID, ecsCluster, taskARN, ocVersion string, timeout int, accessPointID, roleARN string, configureOCM, noWait, connected bool) map[string]any {
	summary := startSessionResult(clusterID, investigationID, sessionID, ecsCluster, taskARN, ocVersion, timeout, accessPointID, roleARN, configureOCM)
	switch {
	case noWait:
		summary["status"] = "launched"
	case connected:
		summary["status"] = "disconnected"
		summary["task_closed"] = false
		summary["investigation_closed"] = false
	default:
		summary["status"] = "RUNNING"
	}
	return summary
}

// startSessionResult exposes the user-facing lifetime and preserves the legacy
// task_timeout key for existing JSON consumers.
func startSessionResult(clusterID, investigationID, sessionID, ecsCluster, taskARN, ocVersion string, timeout int, accessPointID, roleARN string, configureOCM bool) map[string]any {
	summary := map[string]any{
		"profile":          selectedProfile,
		"session_id":       sessionID,
		"ecs_cluster":      ecsCluster,
		"cluster_id":       clusterID,
		"investigation_id": investigationID,
		// Preserve ECS-specific fields for callers that need the underlying task resource.
		"task_id":         sessionID,
		"task_arn":        taskARN,
		"oc_version":      ocVersion,
		"session_timeout": timeout,
		"task_timeout":    timeout,
		"access_point_id": accessPointID,
		"role_arn":        roleARN,
	}
	if configureOCM {
		summary["credentials"] = []string{"ocm"}
	}
	return summary
}

func validateStartCredentials(explicit ...bool) (bool, ocmcredentials.Environment, ocmcredentials.Flow, error) {
	flowExplicit := len(explicit) != 0 && explicit[0]
	if startOCMFlow != "" || flowExplicit {
		if _, err := parseOCMFlow(startOCMFlow); err != nil {
			return false, ocmcredentials.Environment{}, "", err
		}
	}
	if startCredentials == "" {
		return false, ocmcredentials.Environment{}, "", nil
	}
	if startNoWait {
		return false, ocmcredentials.Environment{}, "", fmt.Errorf("--with-credentials cannot be combined with --no-wait")
	}
	if startCredentials != "ocm" {
		return false, ocmcredentials.Environment{}, "", fmt.Errorf("unsupported credential provider %q", startCredentials)
	}
	environment, err := ocmcredentials.ResolveEnvironment(startOCMURL)
	if err != nil {
		return false, ocmcredentials.Environment{}, "", err
	}
	flow := ocmcredentials.Flow("")
	if startOCMFlow != "" || flowExplicit {
		flow, err = parseOCMFlow(startOCMFlow)
		if err != nil {
			return false, ocmcredentials.Environment{}, "", err
		}
	}
	return true, environment, flow, nil
}

func sessionCredentialFailure(investigationID, sessionID, ecsCluster, region string, environment ocmcredentials.Environment, flow ocmcredentials.Flow, cause error) error {
	callbackNotice := ""
	if flow == ocmcredentials.FlowAuthCode {
		callbackNotice = "; auth-code retry requires a local browser callback (omit --auth-flow for the saved preference)"
	}
	return fmt.Errorf(
		"investigation %q created session %q, but credential configuration failed: %w; the session is still running; retry with: rosa-boundary --profile %q session credentials configure ocm %q --ocm-url %q --auth-flow %q --ecs-cluster %q --region %q%s; clean it up with: rosa-boundary --profile %q session close %q --yes --ecs-cluster %q --region %q",
		investigationID, sessionID, cause, selectedProfile, sessionID, environment.Name, flow, ecsCluster, region, callbackNotice, selectedProfile, sessionID, ecsCluster, region,
	)
}

func printStartSessionSummary(ecsCluster, clusterID, investigationID, sessionID, region string, noWait, connected bool) error {
	_, saved, err := config.ReadSavedProfile(selectedProfile)
	if err != nil {
		return fmt.Errorf("read saved profile for join suggestion: %w", err)
	}
	join := fmt.Sprintf("rosa-boundary --profile %q session join %q", selectedProfile, sessionID)
	// A saved value alone is insufficient when the environment would override it
	// on the next invocation. Explicit flags must win over both sources.
	if joinNeedsOverride(region, saved.AWSRegion, "ROSA_BOUNDARY_AWS_REGION") {
		join += fmt.Sprintf(" --region %q", region)
	}
	if joinNeedsOverride(ecsCluster, saved.ClusterName, "ROSA_BOUNDARY_ECS_CLUSTER_NAME") {
		join += fmt.Sprintf(" --ecs-cluster %q", ecsCluster)
	}
	state := "Session created and RUNNING."
	joinHeading := "To join this session, run:"
	lifecycle := ""
	if noWait {
		state = "Session launched; RUNNING has not been confirmed."
		joinHeading = "Once this session is RUNNING, to join it, run:"
	} else if connected {
		state = "Session created; interactive shell disconnected."
		lifecycle = "The task and investigation remain open. Stop the task with session close when finished.\n"
	}
	_, err = fmt.Fprintf(os.Stdout, "\n%s\nCluster: %s\nInvestigation: %s\nSession ID: %s\n%s\n%s\n  %s\n", state, clusterID, investigationID, sessionID, lifecycle, joinHeading, join)
	return err
}

func joinNeedsOverride(effective, saved, envKey string) bool {
	if effective != saved {
		return true
	}
	env, set := os.LookupEnv(envKey)
	return set && env != effective
}

// sanitizeSessionName replaces characters not allowed in STS session names.
func sanitizeSessionName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == '@' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	s := b.String()
	if len(s) > 64 {
		s = s[:64]
	}
	for len(s) < 2 {
		s += "-"
	}
	return s
}

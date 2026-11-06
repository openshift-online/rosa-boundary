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
	startCredentials      []string
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

	if cfg.LambdaFunctionName == "" {
		return fmt.Errorf("lambda function name is required; set --lambda-function-name, ROSA_BOUNDARY_LAMBDA_FUNCTION_NAME, or LAMBDA_FUNCTION_NAME")
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
		cleanup := fmt.Sprintf("rosa-boundary --profile %q session stop %q --yes --region %q --ecs-cluster %q", selectedProfile, sessionID, cfg.AWSRegion, cfg.ClusterName)
		resultErr = fmt.Errorf("session %s created for %s/%s (profile %s; region %s; ECS cluster %s), then operation failed: %w; inspect session list --status all; cleanup: %s", sessionID, clusterID, investigationID, selectedProfile, cfg.AWSRegion, cfg.ClusterName, resultErr, cleanup)
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
		if err := configureOCMForSession(cmd.Context(), ecsClient, cfg.AWSRegion, creds, sessionID, ocmEnvironment, ocmFlow, cmd); err != nil {
			return sessionCredentialFailure(investigationID, sessionID, ecsCluster, cfg.AWSRegion, ocmEnvironment, ocmFlow, err)
		}
	}

	// Print summary
	if startOutputFormat == "json" {
		summary := map[string]any{
			"profile":          selectedProfile,
			"session_id":       sessionID,
			"ecs_cluster":      ecsCluster,
			"cluster_id":       clusterID,
			"investigation_id": investigationID,
			// Preserve ECS-specific fields for callers that need the underlying task resource.
			"task_id":         sessionID,
			"task_arn":        lambdaResp.TaskARN,
			"oc_version":      startOCVersion,
			"task_timeout":    sessionTimeoutSeconds,
			"access_point_id": lambdaResp.AccessPointID,
			"role_arn":        roleARN,
		}
		if configureOCM {
			summary["credentials"] = []string{"ocm"}
		}
		if err := output.JSON(summary); err != nil {
			return err
		}
	} else {
		if err := printStartSessionSummary(ecsCluster, clusterID, investigationID, sessionID, startOCVersion, sessionTimeoutSeconds, lambdaResp.AccessPointID, roleARN, cfg.AWSRegion); err != nil {
			return err
		}
	}

	// Auto-connect only after any requested credential configuration succeeds.
	if startConnect && !startNoWait {
		step := 4
		if configureOCM {
			step = 5
		}
		output.Status("\n=== Step %d: Connecting to session ===", step)
		return connectToSession(cmd.Context(), ecsClient, cfg.AWSRegion, creds, sessionID, "rosa-boundary", defaultExecCommand, false)
	}

	return nil
}

func validateStartCredentials(explicit ...bool) (bool, ocmcredentials.Environment, ocmcredentials.Flow, error) {
	flowExplicit := len(explicit) != 0 && explicit[0]
	if startOCMFlow != "" || flowExplicit {
		if _, err := parseOCMFlow(startOCMFlow); err != nil {
			return false, ocmcredentials.Environment{}, "", err
		}
	}
	if len(startCredentials) == 0 {
		return false, ocmcredentials.Environment{}, "", nil
	}
	if startNoWait {
		return false, ocmcredentials.Environment{}, "", fmt.Errorf("--with-credentials cannot be combined with --no-wait")
	}
	seenOCM := false
	for _, provider := range startCredentials {
		if provider != "ocm" {
			return false, ocmcredentials.Environment{}, "", fmt.Errorf("unsupported credential provider %q", provider)
		}
		if seenOCM {
			return false, ocmcredentials.Environment{}, "", fmt.Errorf("credential provider ocm was requested more than once")
		}
		seenOCM = true
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
		"investigation %q created session %q, but credential configuration failed: %w; the session is still running; retry with: rosa-boundary --profile %q session credentials configure ocm %q --ocm-url %q --auth-flow %q --ecs-cluster %q --region %q%s; clean it up with: rosa-boundary --profile %q session stop %q --yes --ecs-cluster %q --region %q",
		investigationID, sessionID, cause, selectedProfile, sessionID, environment.Name, flow, ecsCluster, region, callbackNotice, selectedProfile, sessionID, ecsCluster, region,
	)
}

func printStartSessionSummary(ecsCluster, clusterID, investigationID, sessionID, ocVersion string, timeout int, accessPointID, roleARN, region string) error {
	summary := fmt.Sprintf("Session %s created for %s/%s (profile %s).\n", sessionID, clusterID, investigationID, selectedProfile)
	summary += fmt.Sprintf("ECS cluster: %s; region: %s; OC version: %s; lifetime: %d seconds; access point: %s; role: %s\n", ecsCluster, region, ocVersion, timeout, accessPointID, roleARN)
	summary += fmt.Sprintf("Join: rosa-boundary --profile %q session join %q", selectedProfile, sessionID)
	if region != "" {
		summary += fmt.Sprintf(" --region %q", region)
	}
	if ecsCluster != "" {
		summary += fmt.Sprintf(" --ecs-cluster %q", ecsCluster)
	}
	_, err := fmt.Fprintln(os.Stdout, summary)
	return err
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

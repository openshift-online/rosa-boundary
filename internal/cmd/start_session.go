package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	petname "github.com/dustinkirkland/golang-petname"
	"github.com/spf13/cobra"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/config"
	ocmcredentials "github.com/openshift-online/rosa-boundary/internal/credentials/ocm"
	"github.com/openshift-online/rosa-boundary/internal/lambda"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

func sessionCreateInvokeError(err error, profile, clusterID, investigationID, region, ecsCluster string) error {
	var responseErr *lambda.ResponseError
	if errors.As(err, &responseErr) && responseErr.StatusCode == http.StatusConflict && responseErr.ExistingSessionID != "" {
		return fmt.Errorf("%w\n\nTo join the existing session, run:\n  rosa-boundary --profile %s session join %s --region %s --ecs-cluster %s",
			err, shellArgument(profile), shellArgument(responseErr.ExistingSessionID), shellArgument(region), shellArgument(ecsCluster))
	}
	return fmt.Errorf("lambda call failed (outcome may be unknown for %s/%s; inspect with rosa-boundary --profile %q session list --status all --region %q --ecs-cluster %q before retrying): %w",
		clusterID, investigationID, profile, region, ecsCluster, err)
}

var (
	startClusterID        string
	startInvestigationID  string
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

	// The resolved value includes explicit flags, environment overrides and the
	// selected profile. Empty preserves the legacy local OCM URL fallback.
	startOCMURL = cachedAuthResult.Config.OCMURL
	configureOCM, ocmEnvironment, ocmFlow, err := validateStartCredentials(cmd.Flags().Changed("ocm-auth-flow"), cmd.Flags().Changed("with-credentials"))
	if err != nil {
		return err
	}

	authRes := cachedAuthResult
	cfg := authRes.Config
	if configureOCM && ocmFlow == "" {
		ocmFlow = defaultOCMFlow(cfg.OIDCUseDeviceCode)
	}
	ocmOptions := ocmSetup{environment: ocmEnvironment, flow: ocmFlow}

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
	output.Status("Session lifetime: %d seconds", sessionTimeoutSeconds)

	invokerCredProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	lambdaClient := lambda.New(cfg.LambdaFunctionName, cfg.AWSRegion, invokerCredProvider)
	invokeStart := time.Now()
	lambdaResp, err := lambdaClient.CreateInvestigation(cmd.Context(), authRes.IDToken, lambda.InvestigationRequest{
		ClusterID:       clusterID,
		InvestigationID: investigationID,
		TaskTimeout:     sessionTimeoutSeconds,
		TaskTimeoutSet:  true,
	})
	if err != nil {
		return sessionCreateInvokeError(err, selectedProfile, clusterID, investigationID, cfg.AWSRegion, cfg.ClusterName)
	}

	timings := sessionStartupTimings{LambdaRoundTripMS: time.Since(invokeStart).Milliseconds()}

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
	sreIDToken, creds, err := assumeRoleWithRetryOptions(cmd.Context(), pkce, cfg.AWSRegion, roleARN, sessionName, false, options)
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

	// Start the OCM authorization before waiting so the human approval overlaps
	// task startup instead of following it. This spends roughly the startup time
	// of the token's lifetime. It begins only after the Boundary role assumption
	// above, so two interactive sign-ins never compete. An absent local OCM URL
	// is recoverable: the task remains usable and the user can retry with
	// --ocm-url on the configure command.
	var pendingOCM *pendingOCMToken
	var renewal *ocmRenewal
	var renewalAuth *renewalAWS
	var ocmErr error
	if configureOCM {
		if ocmOptions.environment.Name == "" {
			ocmOptions.environment, ocmErr = ocmcredentials.ResolveEnvironment(startOCMURL)
		}
		if ocmErr == nil {
			output.Status("\n=== Authorizing OCM while the session starts ===")
			var attachmentAuth attachmentOCMAuth
			if startOCMRenewalEnabled(configureOCM, startConnect, startNoWait, flagBool(cmd, "no-ocm-renewal")) {
				attachmentAuth = newAttachmentOCMAuth()
				renewalAuth = newRenewalAWS(cfg, creds, roleARN, sessionName, sreIDToken, options)
			}
			pendingOCM = startOCMTokenAcquisition(cmd.Context(), ocmOptions.environment, ocmOptions.flow, attachmentAuth)
			defer pendingOCM.Discard()
		}
	}

	// Step 3: Wait for RUNNING (unless --no-wait)
	if !startNoWait {
		output.Status("\n=== Step 3: Waiting for session to be RUNNING ===")
		output.Status("Session: %s", sessionID)
		startup, err := ecsClient.WaitForRunningWithTimings(cmd.Context(), sessionID)
		if err != nil {
			return fmt.Errorf("session did not reach RUNNING: %w", err)
		}
		readyMS := time.Since(invokeStart).Milliseconds()
		timings.recordRunning(readyMS, startup)
		output.Status("Session is RUNNING")
	}
	timings.print()

	var credentialWarning string
	backplaneLoggedIn := false
	if startNoWait {
		credentialWarning = noWaitCredentialWarning(sessionID, ecsCluster, cfg.AWSRegion)
		output.Warning("%s", credentialWarning)
	}

	// Upload only after the task and exec agent are ready.
	if configureOCM {
		output.Status("\n=== Step 4: Configuring OCM Credentials ===")
		if ocmErr == nil {
			renewal, ocmErr = configureOCMWithPendingToken(cmd.Context(), ecsClient, cfg.AWSRegion, creds, ecsCluster, sessionID, ocmOptions, pendingOCM, renewalAuth)
		}
		if ocmErr != nil {
			credentialWarning = warnStartCredentialFailure(investigationID, sessionID, ecsCluster, cfg.AWSRegion, ocmOptions, ocmErr)
			configureOCM = false
		} else if loginErr := backplaneLoginForStart(cmd.Context(), ecsClient, cfg.AWSRegion, creds, sessionID, clusterID); loginErr != nil {
			credentialWarning = warnBackplaneLoginFailure(sessionID, clusterID, ecsCluster, cfg.AWSRegion, loginErr)
		} else {
			backplaneLoggedIn = true
		}
	}

	// Build the service again after shell exit: a session may
	// outlive the credentials and ID token this command started with.
	closeServiceFor := func() (closeService, error) { return newCloseService(cmd, authRes) }
	return finishStartSession(cmd, ecsClient, creds, ecsCluster, clusterID, investigationID, sessionID, cfg.AWSRegion,
		lambdaResp, roleARN, configureOCM, credentialWarning, timings, renewal, closeServiceFor, backplaneLoggedIn)
}

func startOCMRenewalEnabled(configure, connect, noWait, optedOut bool) bool {
	return configure && connect && !noWait && !optedOut
}

// finishStartSession only reports success after the interactive shell exits.
// The task may remain RUNNING after the shell disconnects.
func finishStartSession(cmd *cobra.Command, ecsClient *awsclient.ECSClient, creds *awsclient.TemporaryCredentials,
	ecsCluster, clusterID, investigationID, sessionID, region string, lambdaResp *lambda.InvestigationResponse,
	roleARN string, configureOCM bool, credentialWarning string, timings sessionStartupTimings,
	renewal *ocmRenewal, newService closeServiceFactory, backplaneLoggedIn ...bool) error {
	// Also release the grant if intent registration fails before attachment.
	if renewal != nil {
		defer renewal.grant.Release()
	}
	target := sessionCloseTarget{ClusterID: clusterID, InvestigationID: investigationID, SessionID: sessionID, AccessPointID: lambdaResp.AccessPointID}
	outcome := sessionCloseOutcome{}
	// Auto-connect after the credential attempt; a warning leaves the task
	// usable even when OCM credentials could not be configured.
	if startConnect && !startNoWait {
		var registeredWith closeService
		if autoCloseRequested {
			service, err := newService()
			if err != nil {
				return fmt.Errorf("--auto-close could not be set up: %w", err)
			}
			if err := registerAutoCloseIntent(cmd.Context(), service, target); err != nil {
				return err
			}
			registeredWith = service
		}
		step := 4
		if configureOCM {
			step = 5
		}
		output.Status("\n=== Step %d: Connecting to session ===", step)
		// A close may be accepted while this new task waits for its Exec agent.
		admit := func(ctx context.Context) error {
			service, err := newService()
			if err != nil {
				return fmt.Errorf("cannot verify close status before attaching: %w", err)
			}
			return requireOpenForJoin(ctx, service, target)
		}
		if err := openInteractiveSession(cmd.Context(), ecsClient, region, creds, sessionID, credentialContainer, defaultExecCommand, false, attachOCM{renewal: renewal, admit: admit}); err != nil {
			if autoCloseRequested {
				// The SRE asked to close when their session ended, not when it
				// failed to start.
				withdrawAutoCloseIntent(cmd.Context(), registeredWith, target)
			}
			return err
		}
		outcome = afterAttachedSession(cmd.Context(), newService,
			func() (sessionCloseTarget, error) { return target, nil }, startOutputFormat == "json")
	}

	if startOutputFormat == "json" {
		result := startSessionJSONResult(clusterID, investigationID, sessionID, ecsCluster, lambdaResp.TaskARN, sessionTimeoutSeconds, lambdaResp.AccessPointID, roleARN, configureOCM, startNoWait, startConnect)
		if startConnect && !startNoWait {
			result = applyCloseOutcome(result, outcome)
		}
		if output.Verbose {
			result["startup_timings"] = timings
		}
		if configureOCM {
			result["backplane_login"] = len(backplaneLoggedIn) > 0 && backplaneLoggedIn[0]
		}
		if credentialWarning != "" {
			result["warnings"] = []string{credentialWarning}
		}
		return output.JSON(result)
	}
	if err := printStartSessionSummary(ecsCluster, clusterID, investigationID, sessionID, region, startNoWait, startConnect, outcome); err != nil {
		return err
	}
	return nil
}

func sessionCreationError(cause error, sessionID, clusterID, investigationID, region, ecsCluster string) error {
	cleanup := fmt.Sprintf("rosa-boundary --profile %q session close %q --yes --region %q --ecs-cluster %q", selectedProfile, sessionID, region, ecsCluster)
	return fmt.Errorf("session %s created for %s/%s (profile %s; region %s; ECS cluster %s), then operation failed: %w; inspect session list --status all; cleanup: %s", sessionID, clusterID, investigationID, selectedProfile, region, ecsCluster, cause, cleanup)
}

func startSessionJSONResult(clusterID, investigationID, sessionID, ecsCluster, taskARN string, timeout int, accessPointID, roleARN string, configureOCM, noWait, connected bool) map[string]any {
	summary := startSessionResult(clusterID, investigationID, sessionID, ecsCluster, taskARN, timeout, accessPointID, roleARN, configureOCM)
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
func startSessionResult(clusterID, investigationID, sessionID, ecsCluster, taskARN string, timeout int, accessPointID, roleARN string, configureOCM bool) map[string]any {
	summary := map[string]any{
		"profile":          selectedProfile,
		"session_id":       sessionID,
		"ecs_cluster":      ecsCluster,
		"cluster_id":       clusterID,
		"investigation_id": investigationID,
		// Preserve ECS-specific fields for callers that need the underlying task resource.
		"task_id":         sessionID,
		"task_arn":        taskARN,
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
	credentialsExplicit := len(explicit) > 1 && explicit[1]
	var flow ocmcredentials.Flow
	var err error
	if startOCMFlow != "" || flowExplicit {
		flow, err = parseOCMFlow(startOCMFlow)
		if err != nil {
			return false, ocmcredentials.Environment{}, "", err
		}
	}
	if startCredentials == "none" || (startNoWait && !credentialsExplicit && startCredentials == "ocm") {
		return false, ocmcredentials.Environment{}, "", nil
	}
	if startNoWait {
		return false, ocmcredentials.Environment{}, "", fmt.Errorf("--with-credentials cannot be combined with --no-wait")
	}
	if startCredentials != "ocm" {
		return false, ocmcredentials.Environment{}, "", fmt.Errorf("unsupported credential provider %q", startCredentials)
	}
	var environment ocmcredentials.Environment
	// Reject invalid user-supplied destinations before creating a task. The
	// implicit local URL is resolved after launch so missing local OCM config
	// warns instead of preventing an otherwise usable session.
	if startOCMURL != "" {
		environment, err = ocmcredentials.ResolveEnvironment(startOCMURL)
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
	retry := (ocmSetup{environment: environment, flow: flow}).configureCommand(region, ecsCluster, sessionID)
	if environment.URL == "" {
		callbackNotice += "; specify --ocm-url production, staging, or integration on retry"
	}
	return fmt.Errorf(
		"investigation %q created session %q, but OCM credential configuration failed: %w; the session is still running without confirmed OCM credentials; retry with: %s%s; clean it up with: rosa-boundary --profile %s session close %s --yes --ecs-cluster %s --region %s",
		investigationID, sessionID, cause, retry, callbackNotice, shellArgument(selectedProfile), shellArgument(sessionID), shellArgument(ecsCluster), shellArgument(region),
	)
}

func warnStartCredentialFailure(investigationID, sessionID, ecsCluster, region string, setup ocmSetup, cause error) string {
	warning := sessionCredentialFailure(investigationID, sessionID, ecsCluster, region, setup.environment, setup.flow, cause).Error()
	output.Warning("%s", warning)
	return warning
}

func noWaitCredentialWarning(sessionID, ecsCluster, region string) string {
	return fmt.Sprintf("--no-wait launched session %q without OCM credentials; once RUNNING, configure them with: %s", sessionID, (ocmSetup{}).configureCommand(region, ecsCluster, sessionID))
}

func printStartSessionSummary(ecsCluster, clusterID, investigationID, sessionID, region string, noWait, connected bool, outcome sessionCloseOutcome) error {
	if outcome.Requested || outcome.Note != "" {
		message := outcome.Note
		if outcome.Requested {
			message = "Investigation close requested; finalization is pending."
		}
		_, err := fmt.Fprintf(os.Stdout, "\nInteractive shell disconnected.\nCluster: %s\nInvestigation: %s\nSession ID: %s\n%s\n", clusterID, investigationID, sessionID, message)
		return err
	}
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

var backplaneLoginForStart = initializeBackplaneLogin

func backplaneLoginFailure(sessionID, clusterID, ecsCluster, region string, cause error) error {
	return fmt.Errorf(
		"session %q is running with OCM credentials, but Backplane login for cluster %q was not initialized: %w; retry inside the session with: ocm backplane login -- %s; if the cluster ID is wrong, clean up with: rosa-boundary --profile %q session close %q --yes --ecs-cluster %q --region %q",
		sessionID, clusterID, cause, shellArgument(clusterID), selectedProfile, sessionID, ecsCluster, region,
	)
}

func warnBackplaneLoginFailure(sessionID, clusterID, ecsCluster, region string, cause error) string {
	warning := backplaneLoginFailure(sessionID, clusterID, ecsCluster, region, cause).Error()
	output.Warning("%s", warning)
	return warning
}

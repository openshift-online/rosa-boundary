package cmd

import (
	"fmt"
	"os"
	"path"
	"strings"

	petname "github.com/dustinkirkland/golang-petname"
	"github.com/spf13/cobra"

	"github.com/openshift/rosa-boundary/internal/auth"
	awsclient "github.com/openshift/rosa-boundary/internal/aws"
	"github.com/openshift/rosa-boundary/internal/lambda"
	"github.com/openshift/rosa-boundary/internal/output"
)

var startTaskCmd = &cobra.Command{
	Use:   "start-task",
	Short: "Create an investigation and start an ECS task",
	Long: `Authenticate with Keycloak, call the create-investigation Lambda,
assume the returned SRE role, and wait for the task to reach RUNNING state.

The cluster defaults to the configured cluster_name. If --investigation-id is
omitted, a random three-word name is generated (e.g. "swift-dance-party").

Prints connection info and the join-task command upon completion.`,
	Args: cobra.NoArgs,
	RunE: runStartTask,
}

var (
	startClusterID       string
	startInvestigationID string
	startOCVersion       string
	startTaskTimeout     int
	startConnect         bool
	startNoWait          bool
	startForceLogin      bool
	startOutputFormat    string
)

func init() {
	startTaskCmd.Flags().StringVar(&startClusterID, "cluster-id", "", "Cluster ID (defaults to configured cluster_name)")
	startTaskCmd.Flags().StringVar(&startInvestigationID, "investigation-id", "", "Investigation ID (auto-generated if omitted)")
	startTaskCmd.Flags().StringVar(&startOCVersion, "oc-version", "4.20", "OpenShift CLI version to use")
	startTaskCmd.Flags().IntVar(&startTaskTimeout, "task-timeout", 3600, "Task timeout in seconds (0 = no timeout)")
	startTaskCmd.Flags().BoolVar(&startConnect, "connect", false, "Automatically join the task after it is RUNNING")
	startTaskCmd.Flags().BoolVar(&startNoWait, "no-wait", false, "Return immediately without waiting for RUNNING")
	startTaskCmd.Flags().BoolVar(&startForceLogin, "force-login", false, "Force fresh OIDC authentication")
	startTaskCmd.Flags().StringVar(&startOutputFormat, "output", "text", "Output format: text or json")
	rootCmd.AddCommand(startTaskCmd)
}

func runStartTask(cmd *cobra.Command, args []string) error {
	cfg, err := getConfig(false, true)
	if err != nil {
		return err
	}

	clusterID := startClusterID
	if clusterID == "" {
		clusterID = cfg.ClusterName
	}

	investigationID := startInvestigationID
	if investigationID == "" {
		investigationID = petname.Generate(3, "-")
		output.Status("Generated investigation ID: %s", investigationID)
	}

	if cfg.InvokerRoleARN == "" {
		return fmt.Errorf("invoker role ARN is required; set --invoker-role-arn, ROSA_BOUNDARY_INVOKER_ROLE_ARN, or INVOKER_ROLE_ARN")
	}
	if cfg.LambdaFunctionName == "" {
		return fmt.Errorf("lambda function name is required; set --lambda-function-name, ROSA_BOUNDARY_LAMBDA_FUNCTION_NAME, or LAMBDA_FUNCTION_NAME")
	}

	// Step 1: Get OIDC token
	output.Status("=== Step 1: Authenticating with Keycloak ===")
	pkce := auth.PKCEConfig{
		KeycloakURL: cfg.KeycloakURL,
		Realm:       cfg.KeycloakRealm,
		ClientID:    cfg.OIDCClientID,
	}
	idToken, err := auth.GetToken(cmd.Context(), pkce, startForceLogin)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	output.Status("OIDC token obtained")

	// Step 2: Assume Lambda Invoker role
	output.Status("\n=== Step 2: Assuming Lambda Invoker Role ===")
	output.Status("Role: %s", cfg.InvokerRoleARN)

	invokerCreds, err := awsclient.AssumeRoleWithWebIdentity(cmd.Context(), cfg.AWSRegion, cfg.InvokerRoleARN, idToken, "rosa-boundary-invoker")
	if err != nil {
		return fmt.Errorf("lambda invoker role assumption failed: %w", err)
	}
	output.Status("Invoker role assumed")

	// Step 3: Call Lambda (SigV4-signed)
	output.Status("\n=== Step 3: Creating Investigation via Lambda ===")
	output.Status("Cluster:        %s", clusterID)
	output.Status("Investigation:  %s", investigationID)
	output.Status("OC Version:     %s", startOCVersion)
	output.Status("Task Timeout:   %d seconds", startTaskTimeout)

	invokerCredProvider := awsclient.StaticCredentialsProvider(invokerCreds)
	lambdaClient := lambda.New(cfg.LambdaFunctionName, cfg.AWSRegion, invokerCredProvider)
	lambdaResp, err := lambdaClient.CreateInvestigation(cmd.Context(), idToken, lambda.InvestigationRequest{
		ClusterID:       clusterID,
		InvestigationID: investigationID,
		OCVersion:       startOCVersion,
		TaskTimeout:     startTaskTimeout,
	})
	if err != nil {
		return fmt.Errorf("lambda call failed: %w", err)
	}

	taskID := path.Base(lambdaResp.TaskARN)

	// Use override role ARN if configured, otherwise use what Lambda returned
	roleARN := cfg.SRERoleARN
	if roleARN == "" {
		roleARN = lambdaResp.RoleARN
	}
	if roleARN == "" {
		return fmt.Errorf("no role ARN available; set --role-arn, ROSA_BOUNDARY_SRE_ROLE_ARN, or ensure Lambda returns role_arn")
	}

	output.Status("Investigation created: task %s", taskID)

	// Step 4: Assume SRE role
	output.Status("\n=== Step 4: Assuming Shared SRE Role ===")
	output.Status("Role: %s", roleARN)

	sessionName := "rosa-boundary-sre"
	if lambdaResp.Owner != "" {
		sessionName = "rosa-boundary-" + sanitizeSessionName(lambdaResp.Owner)
	}

	debugf("Assuming role %s as session %s", roleARN, sessionName)

	creds, err := awsclient.AssumeRoleWithWebIdentity(cmd.Context(), cfg.AWSRegion, roleARN, idToken, sessionName)
	if err != nil {
		return fmt.Errorf("role assumption failed: %w", err)
	}
	output.Status("Role assumed successfully")

	credProvider := awsclient.StaticCredentialsProvider(creds)
	clusterName := lambdaResp.ClusterID
	if clusterName == "" {
		clusterName = cfg.ClusterName
	}

	ecsClient := awsclient.NewECSClient(cfg.AWSRegion, clusterName, credProvider)

	// Step 5: Wait for RUNNING (unless --no-wait)
	if !startNoWait {
		output.Status("\n=== Step 5: Waiting for Task to be RUNNING ===")
		output.Status("Task: %s", taskID)
		if err := ecsClient.WaitForRunning(cmd.Context(), taskID); err != nil {
			output.Status("Warning: task may not be running yet: %v", err)
		} else {
			output.Status("Task is RUNNING")
		}
	}

	// Print summary
	if startOutputFormat == "json" {
		summary := map[string]any{
			"cluster":          clusterName,
			"investigation_id": investigationID,
			"task_id":          taskID,
			"task_arn":         lambdaResp.TaskARN,
			"oc_version":       startOCVersion,
			"task_timeout":     startTaskTimeout,
			"access_point_id":  lambdaResp.AccessPointID,
			"role_arn":         roleARN,
		}
		if err := output.JSON(summary); err != nil {
			return err
		}
	} else {
		printStartSummary(clusterName, investigationID, taskID, startOCVersion, startTaskTimeout, lambdaResp.AccessPointID, roleARN, cfg.AWSRegion)
	}

	// Step 6: Auto-connect if requested
	if startConnect && !startNoWait {
		output.Status("\n=== Step 6: Connecting to Task ===")
		return runJoinWithClient(cmd.Context(), ecsClient, cfg.AWSRegion, taskID, "rosa-boundary", "/bin/bash", false)
	}

	return nil
}

func printStartSummary(cluster, investigationID, taskID, ocVersion string, timeout int, accessPointID, roleARN, region string) {
	fmt.Fprintln(os.Stderr, "\n========================================")
	fmt.Fprintln(os.Stderr, "Investigation Created Successfully!")
	fmt.Fprintln(os.Stderr, "========================================")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  Cluster:        %s\n", cluster)
	fmt.Fprintf(os.Stderr, "  Investigation:  %s\n", investigationID)
	fmt.Fprintf(os.Stderr, "  Task:           %s\n", taskID)
	fmt.Fprintf(os.Stderr, "  OC Version:     %s\n", ocVersion)
	fmt.Fprintf(os.Stderr, "  Task Timeout:   %d seconds\n", timeout)
	fmt.Fprintf(os.Stderr, "  EFS Access Pt:  %s\n", accessPointID)
	fmt.Fprintf(os.Stderr, "  Your Role:      %s\n", roleARN)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Connect to task:")
	fmt.Fprintf(os.Stderr, "  rosa-boundary join-task %s --cluster %s --region %s\n", taskID, cluster, region)
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
	return s
}

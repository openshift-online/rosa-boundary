package cmd

import (
	"fmt"
	"os"

	petname "github.com/dustinkirkland/golang-petname"
	"github.com/spf13/cobra"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/lambda"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

var createInvestigationCmd = &cobra.Command{
	Use:   "create-investigation",
	Short: "Create an investigation workspace (EFS access point) without starting a task",
	Long: `Authenticate with Keycloak, call the create-investigation Lambda with skip_task=true,
creating only the EFS access point without launching an ECS task.

Use this to pre-create an investigation workspace before starting a task, or to
re-create a workspace with specific parameters.

If --investigation-id is omitted, a random three-word name is generated
(e.g. "swift-dance-party").`,
	Args: cobra.NoArgs,
	RunE: runCreateInvestigation,
}

var (
	createClusterID       string
	createInvestigationID string
	createForceLogin      bool
	createOutputFormat    string
)

func init() {
	createInvestigationCmd.Flags().StringVar(&createClusterID, "cluster-id", "", "ROSA cluster ID to investigate")
	_ = createInvestigationCmd.MarkFlagRequired("cluster-id")
	createInvestigationCmd.Flags().StringVar(&createInvestigationID, "investigation-id", "", "Investigation ID (auto-generated if omitted)")
	createInvestigationCmd.Flags().BoolVar(&createForceLogin, "force-login", false, "Force fresh OIDC authentication")
	createInvestigationCmd.Flags().StringVar(&createOutputFormat, "output", "text", "Output format: text or json")
	rootCmd.AddCommand(createInvestigationCmd)
}

func runCreateInvestigation(cmd *cobra.Command, args []string) error {
	switch createOutputFormat {
	case "text", "json":
	default:
		return fmt.Errorf("invalid --output %q: must be text or json", createOutputFormat)
	}

	authRes := cachedAuthResult
	cfg := authRes.Config

	clusterID := createClusterID

	investigationID := createInvestigationID
	if investigationID == "" {
		investigationID = petname.Generate(3, "-")
		output.Status("Generated investigation ID: %s", investigationID)
	}

	if cfg.LambdaFunctionName == "" {
		return fmt.Errorf("lambda function name is required; set --lambda-function-name, ROSA_BOUNDARY_LAMBDA_FUNCTION_NAME, or LAMBDA_FUNCTION_NAME")
	}

	// Step 1: Call Lambda with skip_task=true (creates only the EFS access point)
	output.Status("=== Step 1: Creating Investigation Workspace via Lambda ===")
	output.Status("Cluster:        %s", clusterID)
	output.Status("Investigation:  %s", investigationID)

	invokerCredProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	lambdaClient := lambda.New(cfg.LambdaFunctionName, cfg.AWSRegion, invokerCredProvider)
	lambdaResp, err := lambdaClient.CreateInvestigationOnly(cmd.Context(), authRes.IDToken, lambda.InvestigationRequest{
		ClusterID:       clusterID,
		InvestigationID: investigationID,
	})
	if err != nil {
		return fmt.Errorf("lambda call failed: %w", err)
	}

	output.Status("Investigation workspace created: access point %s", lambdaResp.AccessPointID)

	if createOutputFormat == "json" {
		summary := map[string]any{
			"cluster":          clusterID,
			"investigation_id": investigationID,
			"access_point_id":  lambdaResp.AccessPointID,
		}
		if err := output.JSON(summary); err != nil {
			return err
		}
	} else {
		printCreateInvestigationSummary(clusterID, investigationID, lambdaResp.AccessPointID)
	}

	return nil
}

func printCreateInvestigationSummary(cluster, investigationID, accessPointID string) {
	fmt.Fprintln(os.Stderr, "\n========================================")
	fmt.Fprintln(os.Stderr, "Investigation Workspace Created!")
	fmt.Fprintln(os.Stderr, "========================================")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  Cluster:        %s\n", cluster)
	fmt.Fprintf(os.Stderr, "  Investigation:  %s\n", investigationID)
	fmt.Fprintf(os.Stderr, "  EFS Access Pt:  %s\n", accessPointID)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Start a task for this investigation:")
	fmt.Fprintf(os.Stderr, "  rosa-boundary start-task --cluster-id %s --investigation-id %s\n", cluster, investigationID)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Close this investigation when done:")
	fmt.Fprintf(os.Stderr, "  rosa-boundary close-investigation --cluster-id %s --investigation-id %s --yes\n", cluster, investigationID)
}

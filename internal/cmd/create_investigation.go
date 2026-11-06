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

var (
	createClusterID       string
	createInvestigationID string
	createOutputFormat    string
)

func runCreateInvestigation(cmd *cobra.Command, args []string) (resultErr error) {
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
		return fmt.Errorf("lambda call failed (outcome may be unknown for %s/%s; inspect with rosa-boundary --profile %q investigation list --cluster-id %q --region %q before retrying): %w", clusterID, investigationID, selectedProfile, clusterID, cfg.AWSRegion, err)
	}
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("investigation %s/%s created (access point %s; profile %s; region %s) but result failed: %w", clusterID, investigationID, lambdaResp.AccessPointID, selectedProfile, cfg.AWSRegion, resultErr)
		}
	}()

	output.Status("Investigation workspace created: access point %s", lambdaResp.AccessPointID)

	if createOutputFormat == "json" {
		summary := map[string]any{
			"profile":          selectedProfile,
			"cluster_id":       clusterID,
			"investigation_id": investigationID,
			"access_point_id":  lambdaResp.AccessPointID,
		}
		if err := output.JSON(summary); err != nil {
			return err
		}
	} else {
		if err := printCreateInvestigationSummary(clusterID, investigationID, lambdaResp.AccessPointID, cfg.AWSRegion); err != nil {
			return err
		}
	}

	return nil
}

func printCreateInvestigationSummary(cluster, investigationID, accessPointID, region string) error {
	_, err := fmt.Fprintf(os.Stdout, "Investigation %s/%s created (profile %s; access point %s).\nStart a session: rosa-boundary --profile %q session start %q --investigation-id %q --region %q\n", cluster, investigationID, selectedProfile, accessPointID, selectedProfile, cluster, investigationID, region)
	return err
}

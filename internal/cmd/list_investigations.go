package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

type listInvestigationsOptions struct {
	forceLogin bool
	clusterID  string
	output     string
}

func newListInvestigationsCmd() *cobra.Command {
	opts := &listInvestigationsOptions{}

	cmd := &cobra.Command{
		Use:   "list-investigations",
		Short: "List investigations (EFS access points) on the configured filesystem",
		Long: `List all rosa-boundary investigations on the configured EFS filesystem.

An investigation exists as long as its EFS access point exists — even if no
tasks are currently running. Use --cluster-id to narrow results to a single
cluster, or omit it to see all investigations across all clusters.

Requires efs_filesystem_id to be set in config, ROSA_BOUNDARY_EFS_FILESYSTEM_ID,
or --efs-filesystem-id.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.run(cmd)
		},
	}

	AddForceLoginFlag(cmd, &opts.forceLogin)
	cmd.Flags().StringVar(&opts.clusterID, "cluster-id", "", "Filter by cluster ID (lists all clusters if omitted)")
	cmd.Flags().StringVar(&opts.output, "output", "text", "Output format: text or json")

	return cmd
}

func init() {
	rootCmd.AddCommand(newListInvestigationsCmd())
}

func (o *listInvestigationsOptions) run(cmd *cobra.Command) error {
	switch o.output {
	case "text", "json":
	default:
		return fmt.Errorf("invalid --output %q: must be text or json", o.output)
	}

	authRes, err := GetAWSConfigWithOIDC(cmd, o.forceLogin)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	if authRes.Config.EFSFilesystemID == "" {
		return fmt.Errorf("EFS filesystem ID is required; set --efs-filesystem-id, ROSA_BOUNDARY_EFS_FILESYSTEM_ID, or efs_filesystem_id in config")
	}

	credProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	efsClient := awsclient.NewEFSClient(authRes.Config.AWSRegion, authRes.Config.EFSFilesystemID, credProvider)

	investigations, err := efsClient.ListInvestigations(cmd.Context(), o.clusterID)
	if err != nil {
		return fmt.Errorf("failed to list investigations: %w", err)
	}

	if o.output == "json" {
		type jsonRow struct {
			InvestigationID string `json:"investigation_id"`
			ClusterID       string `json:"cluster_id"`
			Username        string `json:"username"`
			AccessPointID   string `json:"access_point_id"`
			State           string `json:"state"`
		}
		rows := make([]jsonRow, len(investigations))
		for i, inv := range investigations {
			rows[i] = jsonRow{
				InvestigationID: inv.Tags["InvestigationID"],
				ClusterID:       inv.Tags["ClusterID"],
				Username:        inv.Tags["username"],
				AccessPointID:   inv.AccessPointID,
				State:           inv.LifeCycleState,
			}
		}
		return output.JSON(rows)
	}

	tbl := output.NewTable("INVESTIGATION", "CLUSTER", "USERNAME", "ACCESS POINT", "STATE")
	tbl.PrintHeader()
	for _, inv := range investigations {
		tbl.PrintRow(
			inv.Tags["InvestigationID"],
			inv.Tags["ClusterID"],
			inv.Tags["username"],
			inv.AccessPointID,
			inv.LifeCycleState,
		)
	}
	tbl.Flush()

	if len(investigations) == 0 {
		output.Status("No investigations found")
	}

	return nil
}

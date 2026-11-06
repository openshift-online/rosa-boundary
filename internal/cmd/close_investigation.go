package cmd

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

var closeInvestigationCmd = &cobra.Command{
	Use:   "close-investigation",
	Short: "Close an investigation: stop tasks, deregister task defs, delete EFS access point",
	Long: `Close an investigation workspace by:
  1. Finding the EFS access point for the investigation
  2. Stopping any running tasks (requires --force if tasks are running)
  3. Deregistering associated task definitions
  4. Deleting the EFS access point (prompts for confirmation unless --yes)

Note: The EFS data remains on the filesystem after the access point is deleted.
Use --efs-filesystem-id or set efs_filesystem_id in your config.`,
	Args: cobra.NoArgs,
	RunE: runCloseInvestigation,
}

var (
	closeClusterID       string
	closeInvestigationID string
	closeForce           bool
	closeYes             bool
	closeDryRun          bool
	closeOutputFormat    string
)

var taskDefinitionTimestamp = regexp.MustCompile(`^\d{8}T\d{6}$`)

// Lambda appends a timestamp to the exact investigation family. ECS family
// prefix queries also return e.g. incident-42-extra; never deregister those.
func investigationTaskDefinitions(arns []string, familyPrefix string) []string {
	result := make([]string, 0)
	for _, arn := range arns {
		family, _, _ := strings.Cut(path.Base(arn), ":")
		if suffix, ok := strings.CutPrefix(family, familyPrefix+"-"); ok && taskDefinitionTimestamp.MatchString(suffix) {
			result = append(result, arn)
		}
	}
	slices.Sort(result)
	return result
}

// init registers the close-investigation command and its flags with the root command.
func init() {
	closeInvestigationCmd.Flags().StringVar(&closeClusterID, "cluster-id", "", "Cluster ID (optional; required if investigation ID is ambiguous)")
	closeInvestigationCmd.Flags().StringVar(&closeInvestigationID, "investigation-id", "", "Investigation ID (required)")
	closeInvestigationCmd.Flags().BoolVar(&closeForce, "force", false, "Stop running tasks before deleting (default: error if tasks are running)")
	closeInvestigationCmd.Flags().BoolVar(&closeYes, "yes", false, "Skip confirmation prompt for EFS access point deletion")
	addOutputFlag(closeInvestigationCmd, true, &closeOutputFormat)
	_ = closeInvestigationCmd.MarkFlagRequired("investigation-id")
	rootCmd.AddCommand(closeInvestigationCmd)
}

// runCloseInvestigation executes the close-investigation command workflow.
// It finds the EFS access point by investigation ID (optionally filtered by cluster ID),
// stops any running tasks if --force is specified, deregisters task definitions,
// and deletes the EFS access point after user confirmation.
func runCloseInvestigation(cmd *cobra.Command, args []string) error {
	if err := validateTextOrJSONOutputFormat(closeOutputFormat); err != nil {
		return err
	}

	authRes := cachedAuthResult

	if authRes.Config.EFSFilesystemID == "" {
		return fmt.Errorf("EFS filesystem ID is required; set --efs-filesystem-id, ROSA_BOUNDARY_EFS_FILESYSTEM_ID, or efs_filesystem_id in config")
	}

	credProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	efsClient := awsclient.NewEFSClient(authRes.Config.AWSRegion, authRes.Config.EFSFilesystemID, credProvider)
	ecsClient := awsclient.NewECSClient(authRes.Config.AWSRegion, authRes.Config.ClusterName, credProvider)

	subject, err := authenticatedSubject(authRes.IDToken)
	if err != nil {
		return err
	}
	plan, err := resolveClosePlan(cmd.Context(), efsClient, ecsClient, closeClusterID, closeInvestigationID, authRes.Config.ClusterName, authRes.Config.EFSFilesystemID, subject)
	if err != nil {
		return err
	}
	if len(plan.SessionIDs)+len(plan.SessionsWaiting) != 0 && !closeForce && !closeDryRun {
		return fmt.Errorf("%d active session(s) remain (including sessions shutting down); use --force to stop/wait or --dry-run to preview", len(plan.SessionIDs)+len(plan.SessionsWaiting))
	}
	plan.Profile = newSelectedProfile
	plan.AccountID = authRes.Config.AccountID
	plan.Region = authRes.Config.AWSRegion
	printClosePlan(plan)
	if closeDryRun {
		if closeOutputFormat == "json" {
			return output.JSON(plan)
		}
		return nil
	}
	if !closeYes {
		if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
			return fmt.Errorf("--yes is required without a terminal (or use --dry-run)")
		}
		fmt.Fprintf(os.Stderr, "\nClose investigation %s/%s? [y/N]: ", plan.ClusterID, plan.InvestigationID)
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() || !strings.EqualFold(strings.TrimSpace(scanner.Text()), "y") {
			return fmt.Errorf("aborted")
		}
	}
	// Re-discover rather than acting on resources which changed during a prompt.
	check, err := resolveClosePlan(cmd.Context(), efsClient, ecsClient, plan.ClusterID, plan.InvestigationID, plan.ECSCluster, plan.FilesystemID, subject)
	if err != nil {
		return fmt.Errorf("close plan changed before mutation: %w", err)
	}
	if !sameClosePlan(plan, check) {
		return fmt.Errorf("close plan changed before mutation; preview and confirm again")
	}
	stopped := 0
	for _, taskID := range plan.SessionIDs {
		if err := ecsClient.StopTask(cmd.Context(), taskID, "Investigation closed via rosa-boundary"); err != nil {
			return fmt.Errorf("stopped %d/%d sessions; failed to stop %s (remaining sessions: %v; task definitions: %v; access point: %s): %w", stopped, len(plan.SessionIDs), taskID, plan.SessionIDs[stopped:], plan.TaskDefinitions, plan.AccessPointID, err)
		}
		stopped++
	}
	for _, taskID := range append(slices.Clone(plan.SessionIDs), plan.SessionsWaiting...) {
		if err := ecsClient.WaitForStopped(cmd.Context(), taskID); err != nil {
			return fmt.Errorf("stopped %d/%d sessions but %s did not reach STOPPED; task definitions %v and access point %s remain: %w", stopped, len(plan.SessionIDs), taskID, plan.TaskDefinitions, plan.AccessPointID, err)
		}
	}
	// A new task may start during the stop wait. Never delete its access point.
	remaining, err := ecsClient.ListTasksByInvestigation(cmd.Context(), plan.ClusterID, plan.InvestigationID)
	if err != nil || len(remaining) != 0 {
		return fmt.Errorf("cannot verify investigation has no active sessions after stops (remaining: %d): %v", len(remaining), err)
	}
	removed := 0
	for _, arn := range plan.TaskDefinitions {
		if err := ecsClient.DeregisterTaskDefinition(cmd.Context(), arn); err != nil {
			return fmt.Errorf("deregistered %d/%d task definitions; remaining: %v; access point %s remains: %w", removed, len(plan.TaskDefinitions), plan.TaskDefinitions[removed:], plan.AccessPointID, err)
		}
		removed++
	}
	// Detect a new launch during task-definition cleanup. This is still
	// best-effort; ECS/EFS do not provide an atomic close-and-create lock.
	remaining, err = ecsClient.ListTasksByInvestigation(cmd.Context(), plan.ClusterID, plan.InvestigationID)
	if err != nil || len(remaining) != 0 {
		return fmt.Errorf("deregistered %d definitions but cannot safely delete access point %s (active sessions: %d): %v", removed, plan.AccessPointID, len(remaining), err)
	}
	if err := efsClient.DeleteAccessPoint(cmd.Context(), plan.AccessPointID); err != nil {
		return fmt.Errorf("stopped %d sessions and deregistered %d definitions, but access point %s remains: %w", stopped, removed, plan.AccessPointID, err)
	}

	if closeOutputFormat == "json" {
		summary := map[string]any{
			"profile": newSelectedProfile, "cluster_id": plan.ClusterID,
			"investigation_id": plan.InvestigationID, "access_point_id": plan.AccessPointID,
			"sessions_stopped": stopped, "task_defs_removed": removed,
		}
		if err := output.JSON(summary); err != nil {
			return err
		}
	} else {
		if err := printCloseInvestigationSummary(plan.ClusterID, plan.InvestigationID, plan.AccessPointID, stopped, removed); err != nil {
			return err
		}
	}

	return nil
}

type closePlan struct {
	Profile         string   `json:"profile"`
	AccountID       string   `json:"account_id"`
	Region          string   `json:"region"`
	ECSCluster      string   `json:"ecs_cluster"`
	FilesystemID    string   `json:"efs_filesystem_id"`
	AccessPointID   string   `json:"access_point_id"`
	ClusterID       string   `json:"cluster_id"`
	InvestigationID string   `json:"investigation_id"`
	SessionIDs      []string `json:"sessions_to_stop"`
	SessionsWaiting []string `json:"sessions_to_wait_for_stop"`
	TaskDefinitions []string `json:"task_definitions_to_deregister"`
}

// The same ID token was accepted by STS before this check. Never use the
// locally decoded claim as authentication on its own.
func authenticatedSubject(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("authenticated ID token is malformed")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("authenticated ID token has invalid claims: %w", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(data, &claims); err != nil || claims.Sub == "" {
		return "", fmt.Errorf("authenticated ID token lacks a subject")
	}
	return claims.Sub, nil
}

func checkInvestigationOwner(tags map[string]string, subject string) error {
	if subject == "" || tags["oidc_sub"] == "" || tags["oidc_sub"] != subject {
		return fmt.Errorf("only the investigation owner may close this workspace (owner subject missing or does not match authenticated identity)")
	}
	return nil
}

func resolveClosePlan(ctx context.Context, efsClient *awsclient.EFSClient, ecsClient *awsclient.ECSClient, clusterID, investigationID, ecsCluster, filesystemID, subject string) (closePlan, error) {
	ap, err := efsClient.FindAccessPointByTags(ctx, clusterID, investigationID)
	if err != nil {
		return closePlan{}, fmt.Errorf("find EFS access point: %w", err)
	}
	if ap == nil {
		return closePlan{}, fmt.Errorf("investigation %s/%s not found", clusterID, investigationID)
	}
	if ap.Tags["ClusterID"] != clusterID || ap.Tags["InvestigationID"] != investigationID || ap.AccessPointID == "" {
		return closePlan{}, fmt.Errorf("investigation access point has missing or conflicting identity tags")
	}
	if ap.Tags["ManagedBy"] != "rosa-boundary-lambda" {
		return closePlan{}, fmt.Errorf("investigation access point is not marked as Lambda-managed; refusing cleanup")
	}
	if err := checkInvestigationOwner(ap.Tags, subject); err != nil {
		return closePlan{}, err
	}
	tasks, err := ecsClient.ListTasksByInvestigation(ctx, clusterID, investigationID)
	if err != nil {
		return closePlan{}, fmt.Errorf("list active sessions: %w", err)
	}
	family := fmt.Sprintf("%s-%s-%s", ecsCluster, clusterID, investigationID)
	defs, err := ecsClient.ListTaskDefinitionsByFamily(ctx, family)
	if err != nil {
		return closePlan{}, fmt.Errorf("list task definitions: %w", err)
	}
	verifiedDefs := make([]string, 0)
	for _, arn := range investigationTaskDefinitions(defs, family) {
		mountedAP, err := ecsClient.TaskDefinitionAccessPoint(ctx, arn)
		if err != nil {
			return closePlan{}, fmt.Errorf("verify investigation task definition mount: %w", err)
		}
		if mountedAP == ap.AccessPointID {
			verifiedDefs = append(verifiedDefs, arn)
		}
	}
	p := closePlan{ECSCluster: ecsCluster, FilesystemID: filesystemID, AccessPointID: ap.AccessPointID, ClusterID: clusterID, InvestigationID: investigationID, SessionIDs: []string{}, SessionsWaiting: []string{}, TaskDefinitions: verifiedDefs}
	for _, task := range tasks {
		if task.DesiredStatus == "STOPPED" {
			p.SessionsWaiting = append(p.SessionsWaiting, task.TaskID)
		} else {
			p.SessionIDs = append(p.SessionIDs, task.TaskID)
		}
	}
	slices.Sort(p.SessionIDs)
	slices.Sort(p.SessionsWaiting)
	return p, nil
}

func sameClosePlan(a, b closePlan) bool {
	return a.AccessPointID == b.AccessPointID && a.ClusterID == b.ClusterID && a.InvestigationID == b.InvestigationID && slices.Equal(a.SessionIDs, b.SessionIDs) && slices.Equal(a.SessionsWaiting, b.SessionsWaiting) && slices.Equal(a.TaskDefinitions, b.TaskDefinitions)
}

func printClosePlan(p closePlan) {
	output.Status("Profile: %s Account: %s Region: %s", p.Profile, p.AccountID, p.Region)
	output.Status("ECS: %s EFS: %s Access point: %s", p.ECSCluster, p.FilesystemID, p.AccessPointID)
	output.Status("Investigation: %s/%s", p.ClusterID, p.InvestigationID)
	output.Status("Sessions to stop: %v", p.SessionIDs)
	output.Status("Sessions already stopping (wait for STOPPED): %v", p.SessionsWaiting)
	output.Status("Task definitions to deregister: %v", p.TaskDefinitions)
}

// printCloseInvestigationSummary writes the text result to stdout.
func printCloseInvestigationSummary(cluster, investigationID, accessPointID string, tasksStopped, taskDefsRemoved int) error {
	_, err := fmt.Fprintf(os.Stdout, "Investigation %s/%s closed (profile %s; access point %s deleted).\nSessions stopped: %d; task definitions removed: %d. EFS data remains; verify audit evidence separately.\n", cluster, investigationID, newSelectedProfile, accessPointID, tasksStopped, taskDefsRemoved)
	return err
}

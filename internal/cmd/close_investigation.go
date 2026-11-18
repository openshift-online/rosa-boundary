package cmd

import (
	"bufio"
	"context"
	"crypto/sha256"
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

var (
	closeClusterID       string
	closeInvestigationID string
	closeForce           bool
	closeYes             bool
	closeDryRun          bool
	closeOutputFormat    string
)

var taskDefinitionTimestamp = regexp.MustCompile(`^\d{8}T\d{6}$`)

// Lambda appends a timestamp to the exact investigation family. The client-side
// family scan also finds e.g. incident-42-extra; never deregister those.
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

// runCloseInvestigation plans and closes a workspace after confirming ownership.
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
	reader := awsclient.NewCloseReceiptReader(authRes.Config.AWSRegion, authRes.Config.AccountID, credProvider)
	resolve := func() (closePlan, error) {
		p, err := resolveClosePlan(cmd.Context(), efsClient, ecsClient, closeClusterID, closeInvestigationID, authRes.Config.ClusterName, authRes.Config.EFSFilesystemID, subject)
		p.Profile, p.AccountID, p.Region = selectedProfile, authRes.Config.AccountID, authRes.Config.AWSRegion
		if err == nil {
			p.checkReceipt(cmd.Context(), reader.Read)
		}
		return p, err
	}
	return closeInvestigation(cmd.Context(), resolve, ecsClient, efsClient.DeleteAccessPoint)
}

type closeECS interface {
	StopTask(context.Context, string, string) error
	WaitForStopped(context.Context, string) error
	DeregisterTaskDefinition(context.Context, string) error
}

func closeInvestigation(ctx context.Context, resolve func() (closePlan, error), ecsClient closeECS, deleteAP func(context.Context, string) error) error {
	plan, err := resolve()
	if err != nil {
		return err
	}
	if len(plan.SessionIDs)+len(plan.SessionsWaiting) != 0 && !closeForce && !closeDryRun {
		return fmt.Errorf("%d active session(s) remain (including sessions shutting down); use --force to stop/wait or --dry-run to preview", len(plan.SessionIDs)+len(plan.SessionsWaiting))
	}
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
		fmt.Fprintf(os.Stderr, "\nProceed with this plan for %s/%s? [y/N]: ", plan.ClusterID, plan.InvestigationID)
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() || !strings.EqualFold(strings.TrimSpace(scanner.Text()), "y") {
			return fmt.Errorf("aborted")
		}
	}
	// Re-discover rather than acting on resources which changed during a prompt.
	check, err := resolve()
	if err != nil {
		return fmt.Errorf("close plan changed before mutation; rerun the --dry-run preview and investigate the resources before retrying: %w", err)
	}
	if !sameClosePlan(plan, check) {
		return fmt.Errorf("close plan changed before mutation; rerun 'rosa-boundary investigation close <cluster-id> <investigation-id> --dry-run' and review the new plan before retrying")
	}
	stopped := 0
	for _, sessionID := range plan.SessionIDs {
		if err := ecsClient.StopTask(ctx, sessionID, "Investigation close requested via rosa-boundary"); err != nil {
			return fmt.Errorf("stopped %d/%d sessions; failed to stop %s (remaining sessions: %v; task definitions: %v; access point: %s); inspect 'rosa-boundary session list --status all' and ask the deployment operator to reconcile partial cleanup before retrying: %w", stopped, len(plan.SessionIDs), sessionID, plan.SessionIDs[stopped:], plan.TaskDefinitions, plan.AccessPointID, err)
		}
		stopped++
	}
	for _, sessionID := range append(slices.Clone(plan.SessionIDs), plan.SessionsWaiting...) {
		if err := ecsClient.WaitForStopped(ctx, sessionID); err != nil {
			return fmt.Errorf("stopped %d/%d sessions but %s did not reach STOPPED; task definitions %v and access point %s remain; check session status and audit evidence before retrying cleanup: %w", stopped, len(plan.SessionIDs), sessionID, plan.TaskDefinitions, plan.AccessPointID, err)
		}
	}
	// Neither ECS visibility nor a task-written S3 marker establishes complete escrow.
	unresolved := append(slices.Clone(plan.SessionIDs), plan.SessionsWaiting...)
	unresolved = append(unresolved, plan.VisibleStopped...)
	if len(plan.SessionIDs)+len(plan.SessionsWaiting) > 0 || plan.ReceiptDigest == "" || plan.FinalizationBlocked != "" {
		return fmt.Errorf("cannot finalize investigation %s/%s: %s; visible unresolved task IDs: %v (older IDs may be unknown); access point %s and task definitions retained; ask the operator to verify complete escrow after shutdown", plan.ClusterID, plan.InvestigationID, plan.FinalizationBlocked, unresolved, plan.AccessPointID)
	}
	// A seal must also fence new launches server-side. Recheck the same owner,
	// seal, exact receipt bytes, mounts and idle state before each mutation.
	checkBeforeCleanup := func(removed int) error {
		next, err := resolve()
		if err != nil {
			return fmt.Errorf("after deregistering %d definitions, cannot verify close: %w", removed, err)
		}
		expected := plan
		expected.TaskDefinitions = plan.TaskDefinitions[removed:]
		if !sameClosePlan(expected, next) || next.FinalizationBlocked != "" {
			return fmt.Errorf("after deregistering %d definitions, close evidence or resources changed; retaining access point %s", removed, plan.AccessPointID)
		}
		return nil
	}
	for i, arn := range plan.TaskDefinitions {
		if err := checkBeforeCleanup(i); err != nil {
			return err
		}
		if err := ecsClient.DeregisterTaskDefinition(ctx, arn); err != nil {
			return fmt.Errorf("after deregistering %d definitions, cannot deregister %s; retaining access point: %w", i, arn, err)
		}
	}
	if err := checkBeforeCleanup(len(plan.TaskDefinitions)); err != nil {
		return err
	}
	if err := deleteAP(ctx, plan.AccessPointID); err != nil {
		return fmt.Errorf("delete verified investigation access point: %w", err)
	}
	if closeOutputFormat == "json" {
		summary := map[string]any{
			"profile": selectedProfile, "cluster_id": plan.ClusterID,
			"investigation_id": plan.InvestigationID, "access_point_id": plan.AccessPointID,
			"sessions_stopped": stopped, "task_defs_removed": len(plan.TaskDefinitions),
		}
		if err := output.JSON(summary); err != nil {
			return err
		}
	} else {
		if err := printCloseInvestigationSummary(plan.ClusterID, plan.InvestigationID, plan.AccessPointID, stopped, len(plan.TaskDefinitions)); err != nil {
			return err
		}
	}

	return nil
}

var closeSeal = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var closeBucket = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func (p *closePlan) checkReceipt(ctx context.Context, read func(context.Context, string, string, string) ([]byte, error)) {
	p.ReceiptDigest = ""
	if len(p.SessionIDs)+len(p.SessionsWaiting) != 0 {
		p.FinalizationBlocked = "sessions have not stopped; operator verification requires a quiescent sealed workspace"
		return
	}
	if p.VerifiedSeal != p.Seal || !closeSeal.MatchString(p.Seal) || !closeBucket.MatchString(p.Bucket) {
		p.FinalizationBlocked = "operator seal, verification tag or audit bucket tag is missing, mismatched or invalid"
		return
	}
	b, err := read(ctx, p.Bucket, p.AccessPointID, p.Seal)
	if err != nil {
		p.FinalizationBlocked = fmt.Sprintf("cannot read operator receipt: %v", err)
		return
	}
	var r struct {
		Version       int    `json:"schema_version"`
		Cluster       string `json:"cluster_id"`
		Investigation string `json:"investigation_id"`
		AP            string `json:"access_point_id"`
		Seal          string `json:"seal"`
		Status        string `json:"status"`
		Manifest      string `json:"manifest_ref"`
	}
	if json.Unmarshal(b, &r) != nil || r.Version != 1 || r.Cluster != p.ClusterID || r.Investigation != p.InvestigationID || r.AP != p.AccessPointID || r.Seal != p.Seal || r.Status != "verified" || strings.TrimSpace(r.Manifest) == "" {
		p.FinalizationBlocked = "operator receipt is invalid or does not match this sealed investigation"
		return
	}
	p.FinalizationBlocked = ""
	p.ReceiptDigest = fmt.Sprintf("%x", sha256.Sum256(b))
}

// printCloseInvestigationSummary writes the text result to stdout.
func printCloseInvestigationSummary(cluster, investigationID, accessPointID string, sessionsStopped, taskDefsRemoved int) error {
	_, err := fmt.Fprintf(os.Stdout, "Investigation %s/%s closed (profile %s; access point %s deleted).\nSessions stopped: %d; task definitions removed: %d. EFS data remains; operator close receipt verified.\n", cluster, investigationID, selectedProfile, accessPointID, sessionsStopped, taskDefsRemoved)
	return err
}

type closePlan struct {
	Profile             string   `json:"profile"`
	AccountID           string   `json:"account_id"`
	Region              string   `json:"region"`
	ECSCluster          string   `json:"ecs_cluster"`
	FilesystemID        string   `json:"efs_filesystem_id"`
	AccessPointID       string   `json:"access_point_id"`
	ClusterID           string   `json:"cluster_id"`
	InvestigationID     string   `json:"investigation_id"`
	SessionIDs          []string `json:"sessions_to_stop"`
	SessionsWaiting     []string `json:"sessions_to_wait_for_stop"`
	VisibleStopped      []string `json:"visible_stopped_sessions"`
	FinalizationBlocked string   `json:"finalization_blocked_reason"`
	TaskDefinitions     []string `json:"task_definitions_to_deregister"`
	VerifiedSeal        string   `json:"audit_close_verified,omitempty"`
	Seal                string   `json:"audit_close_seal,omitempty"`
	Bucket              string   `json:"audit_close_bucket,omitempty"`
	ReceiptDigest       string   `json:"receipt_sha256,omitempty"`
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
		return fmt.Errorf("only the investigation owner may close this workspace (owner subject missing or does not match authenticated identity); sign in as the owner, or ask the deployment operator to investigate the access-point tags")
	}
	return nil
}

func resolveClosePlan(ctx context.Context, efsClient *awsclient.EFSClient, ecsClient *awsclient.ECSClient, clusterID, investigationID, ecsCluster, filesystemID, subject string) (closePlan, error) {
	ap, err := efsClient.FindAccessPointByTags(ctx, clusterID, investigationID)
	if err != nil {
		return closePlan{}, fmt.Errorf("find EFS access point: %w", err)
	}
	if ap == nil {
		return closePlan{}, fmt.Errorf("investigation %s/%s not found; check the cluster/investigation IDs and selected profile with 'rosa-boundary investigation list --cluster-id %q'", clusterID, investigationID, clusterID)
	}
	if ap.Tags["ClusterID"] != clusterID || ap.Tags["InvestigationID"] != investigationID || ap.AccessPointID == "" {
		return closePlan{}, fmt.Errorf("investigation access point has missing or conflicting identity tags; cleanup was refused, ask the deployment operator to inspect the access point")
	}
	if ap.FileSystemID != filesystemID || ap.Path != "/"+clusterID+"/"+investigationID {
		return closePlan{}, fmt.Errorf("investigation access point mount does not match the requested workspace; cleanup refused")
	}
	if ap.Tags["ManagedBy"] != "rosa-boundary-lambda" {
		return closePlan{}, fmt.Errorf("investigation access point is not marked as Lambda-managed; cleanup was refused, ask the deployment operator to verify its origin")
	}
	if err := checkInvestigationOwner(ap.Tags, subject); err != nil {
		return closePlan{}, err
	}
	tasks, err := ecsClient.ListVisibleInvestigationTasks(ctx, clusterID, investigationID)
	if err != nil {
		return closePlan{}, fmt.Errorf("list visible sessions: %w", err)
	}
	family := fmt.Sprintf("%s-%s-%s", ecsCluster, clusterID, investigationID)
	defs, err := ecsClient.ListTaskDefinitionsByFamily(ctx, family)
	if err != nil {
		return closePlan{}, fmt.Errorf("list task definitions: %w", err)
	}
	verifiedDefs := make([]string, 0)
	for _, arn := range investigationTaskDefinitions(defs, family) {
		mountedAP, err := ecsClient.ActiveTaskDefinitionAccessPoint(ctx, arn)
		if err != nil {
			return closePlan{}, fmt.Errorf("verify investigation task definition mount: %w", err)
		}
		if mountedAP == ap.AccessPointID {
			verifiedDefs = append(verifiedDefs, arn)
		}
	}
	p := closePlan{VerifiedSeal: ap.Tags["AuditCloseVerified"], Seal: ap.Tags["AuditCloseSeal"], Bucket: ap.Tags["AuditCloseBucket"], ECSCluster: ecsCluster, FilesystemID: filesystemID, AccessPointID: ap.AccessPointID, ClusterID: clusterID, InvestigationID: investigationID, SessionIDs: []string{}, SessionsWaiting: []string{}, TaskDefinitions: verifiedDefs}
	for _, task := range tasks {
		if task.Status == "STOPPED" {
			p.VisibleStopped = append(p.VisibleStopped, task.TaskID)
		} else if task.DesiredStatus == "STOPPED" {
			p.SessionsWaiting = append(p.SessionsWaiting, task.TaskID)
		} else {
			p.SessionIDs = append(p.SessionIDs, task.TaskID)
		}
	}
	slices.Sort(p.VisibleStopped)
	slices.Sort(p.SessionIDs)
	slices.Sort(p.SessionsWaiting)
	return p, nil
}

func sameClosePlan(a, b closePlan) bool {
	return a.VerifiedSeal == b.VerifiedSeal && a.Seal == b.Seal && a.Bucket == b.Bucket && a.ReceiptDigest == b.ReceiptDigest && a.AccessPointID == b.AccessPointID && a.ClusterID == b.ClusterID && a.InvestigationID == b.InvestigationID && slices.Equal(a.SessionIDs, b.SessionIDs) && slices.Equal(a.SessionsWaiting, b.SessionsWaiting) && slices.Equal(a.VisibleStopped, b.VisibleStopped) && slices.Equal(a.TaskDefinitions, b.TaskDefinitions)
}

func printClosePlan(p closePlan) {
	output.Status("Profile: %s Account: %s Region: %s", p.Profile, p.AccountID, p.Region)
	output.Status("ECS: %s EFS: %s Access point: %s", p.ECSCluster, p.FilesystemID, p.AccessPointID)
	output.Status("Investigation: %s/%s", p.ClusterID, p.InvestigationID)
	output.Status("Sessions to stop: %v", p.SessionIDs)
	output.Status("Sessions already stopping (wait for STOPPED): %v", p.SessionsWaiting)
	output.Status("Visible stopped sessions: %v", p.VisibleStopped)
	output.Status("Task definitions (deregister only after verification): %v", p.TaskDefinitions)
	if p.FinalizationBlocked != "" {
		output.Status("Finalization blocked: %s", p.FinalizationBlocked)
	} else {
		output.Status("Operator receipt SHA-256: %s", p.ReceiptDigest)
	}
}

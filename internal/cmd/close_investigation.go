package cmd

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/config"
	"github.com/openshift-online/rosa-boundary/internal/lambda"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

var (
	closeClusterID       string
	closeInvestigationID string
	closeForce           bool
	closeYes             bool
	closeDryRun          bool
	closeWait            bool
	closeOutputFormat    string
)

// closeStatusPoll is the interval between status lookups while waiting, and
// closeWaitLimit bounds the wait itself. The command deadline cannot be relied
// on here: an interactive run leaves the context without one.
var (
	closeStatusPoll = 10 * time.Second
	closeWaitLimit  = 30 * time.Minute
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

// closeServiceAPI is the close service as the CLI uses it. One interface
// keeps the close command and the session hook talking to the same contract.
type closeServiceAPI interface {
	CloseIdleSession(context.Context, string, lambda.CloseActionRequest) error
	RequestClose(context.Context, string, lambda.CloseActionRequest) (*lambda.CloseActionResponse, error)
	RegisterAutoClose(context.Context, string, lambda.CloseActionRequest) (*lambda.CloseActionResponse, error)
	CancelAutoClose(context.Context, string, lambda.CloseActionRequest) (*lambda.CloseActionResponse, error)
	CloseStatus(context.Context, string, lambda.CloseActionRequest) (*lambda.CloseStatusResponse, error)
}

// runCloseInvestigation previews the workspace, then asks the close service to
// finalize it. The CLI no longer stops tasks, deregisters definitions or
// deletes the access point: a request is recorded, and the scheduled reaper
// performs sealing, verification and cleanup under its own authorization
// recheck. "Accepted" is therefore never "closed".
func runCloseInvestigation(cmd *cobra.Command, args []string) error {
	if err := validateTextOrJSONOutputFormat(closeOutputFormat); err != nil {
		return err
	}

	authRes := cachedAuthResult
	if flagBool(cmd, "status") {
		service := closeServiceForAuth(authRes.Config, authRes.Credentials, authRes.IDToken)
		return showRecordedCloseStatus(cmd.Context(), cmd.OutOrStdout(), service, closeClusterID, closeInvestigationID)
	}

	if authRes.Config.EFSFilesystemID == "" {
		return fmt.Errorf("EFS filesystem ID is required; set --efs-filesystem-id, ROSA_BOUNDARY_EFS_FILESYSTEM_ID, or efs_filesystem_id in config")
	}

	credProvider := awsclient.StaticCredentialsProvider(authRes.Credentials)
	efsClient := awsclient.NewEFSClient(authRes.Config.AWSRegion, authRes.Config.EFSFilesystemID, credProvider)
	ecsClient := awsclient.NewECSClient(authRes.Config.AWSRegion, authRes.Config.ClusterName, credProvider)

	reader := awsclient.NewCloseReceiptReader(authRes.Config.AWSRegion, authRes.Config.AccountID, credProvider)
	plan, err := resolveClosePlan(cmd.Context(), efsClient, ecsClient, closeClusterID, closeInvestigationID, authRes.Config.ClusterName, authRes.Config.EFSFilesystemID)
	if err != nil {
		return err
	}
	plan.Profile, plan.AccountID, plan.Region = selectedProfile, authRes.Config.AccountID, authRes.Config.AWSRegion
	plan.checkReceipt(cmd.Context(), reader.Read)

	preview := plan.preview()
	printClosePlan(preview)
	submit, err := closeSubmissionGate(plan, confirmCloseOnTerminal)
	if err != nil {
		return err
	}
	if !submit {
		if closeDryRun && closeOutputFormat == "json" {
			return output.JSON(preview)
		}
		return nil
	}

	service, err := newCloseService(cmd, authRes)
	if err != nil {
		return err
	}
	return submitCloseRequest(cmd.Context(), service, plan.ClusterID, plan.InvestigationID)
}

// closeSubmissionGate decides whether a close request may be submitted at all.
// Running tasks affect finalization, not submission: without --force the
// recorded request waits for the tasks to stop on their own.
func closeSubmissionGate(plan closePlan, confirm func(closePlan) (bool, error)) (bool, error) {
	if closeDryRun {
		return false, nil
	}
	if closeYes {
		return true, nil
	}
	agreed, err := confirm(plan)
	if err != nil {
		return false, err
	}
	if !agreed {
		return false, errors.New("aborted")
	}
	return true, nil
}

func confirmCloseOnTerminal(plan closePlan) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
		return false, errors.New("--yes is required without a terminal (or use --dry-run)")
	}
	if _, err := fmt.Fprintf(os.Stderr, "\nRequest close for %s/%s? [y/N]: ", plan.ClusterID, plan.InvestigationID); err != nil {
		return false, err
	}
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return false, nil
	}
	return strings.EqualFold(strings.TrimSpace(scanner.Text()), "y"), nil
}

// closeService pairs a close-service client with the identity token it was
// built for. They must travel together: the service validates the token's
// expiry, and a session can outlive the token the command started with.
type closeService struct {
	client  closeServiceAPI
	idToken string
	expiry  time.Time
}

// refreshIfExpired replaces both credentials and the paired ID token when
// either is due to expire.
func (s closeService) refreshIfExpired(newService closeServiceFactory) (closeService, error) {
	if !s.expiry.IsZero() && !time.Now().Before(s.expiry) {
		return newService()
	}
	return s, nil
}

// newCloseService assumes the invoker role so the close service is called with
// the identity the deployment already uses for Lambda work, and returns the ID
// token minted alongside those credentials rather than an older one.
func newCloseService(cmd *cobra.Command, authRes *AuthResult) (closeService, error) {
	cfg := authRes.Config
	if cfg.LambdaFunctionName == "" || cfg.InvokerRoleARN == "" {
		return closeService{}, fmt.Errorf("this profile has no close service configured; set lambda_function_name and invoker_role_arn (see 'rosa-boundary config init --help')")
	}
	options, err := tokenOptions(cmd, cfg)
	if err != nil {
		return closeService{}, err
	}
	pkce := auth.PKCEConfig{KeycloakURL: cfg.KeycloakURL, Realm: cfg.KeycloakRealm, ClientID: cfg.OIDCClientID}
	idToken, creds, err := assumeRoleWithRetryOptions(cmd.Context(), pkce, cfg.AWSRegion, cfg.InvokerRoleARN, "rosa-boundary-invoker", invokerSTSDurationSeconds, false, options)
	if err != nil {
		return closeService{}, fmt.Errorf("cannot reach the close service: %w", err)
	}
	return closeServiceForAuth(cfg, creds, idToken), nil
}

func closeServiceForAuth(cfg *config.Config, creds *awsclient.TemporaryCredentials, idToken string) closeService {
	expiry := creds.Expiry
	// The JWT expiry is only a client-side scheduling hint, not authorization.
	if refreshAt, err := auth.TokenRefreshTime(idToken); err == nil && (expiry.IsZero() || refreshAt.Before(expiry)) {
		expiry = refreshAt
	}
	return closeService{
		client:  lambda.New(cfg.LambdaFunctionName, cfg.AWSRegion, awsclient.StaticCredentialsProvider(creds)),
		idToken: idToken,
		expiry:  expiry,
	}
}

// Look up the durable record, without requiring an access point or planning a close.
func showRecordedCloseStatus(ctx context.Context, out io.Writer, service closeService, clusterID, investigationID string) error {
	var status *lambda.CloseStatusResponse
	var err error
	if closeWait {
		status, err = waitForCloseStatus(ctx, service, clusterID, investigationID, "")
		if err != nil {
			return err
		}
	} else {
		status, err = service.client.CloseStatus(ctx, service.idToken, lambda.CloseActionRequest{
			ClusterID: clusterID, InvestigationID: investigationID,
		})
		if err != nil {
			return fmt.Errorf("cannot read close status for %s/%s (no request submitted): %w", clusterID, investigationID, err)
		}
	}
	if err := writeRecordedCloseStatus(out, clusterID, investigationID, status); err != nil {
		return err
	}
	return closeWaitOutcome(clusterID, investigationID, status)
}

func writeRecordedCloseStatus(out io.Writer, clusterID, investigationID string, status *lambda.CloseStatusResponse) error {
	if closeOutputFormat == "json" {
		return json.NewEncoder(out).Encode(status)
	}
	var message strings.Builder
	fmt.Fprintf(&message, "Close status for %s/%s: %s\n", clusterID, investigationID, status.Status)
	if status.Phase != "" {
		fmt.Fprintf(&message, "Phase: %s\n", status.Phase)
	}
	if status.RequestToken != "" {
		fmt.Fprintf(&message, "Request: %s\n", status.RequestToken)
	}
	fmt.Fprintln(&message, status.Reason)
	_, err := io.WriteString(out, message.String())
	return err
}

// closeStopScope maps --force onto stop consent. Authorization is separate:
// consent to stop tasks never decides who may close.
func closeStopScope() string {
	if closeForce {
		return lambda.StopScopeInvestigation
	}
	return lambda.StopScopeNone
}

// closeRequestFailure distinguishes an explicit refusal from a request that
// may have been recorded before the client lost confirmation.
func closeRequestFailure(clusterID, investigationID string, err error) error {
	var response *lambda.ResponseError
	if errors.As(err, &response) {
		switch response.StatusCode {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict:
			return fmt.Errorf("close request rejected for %s/%s: %w", clusterID, investigationID, err)
		}
	}
	return fmt.Errorf("close request outcome is unknown for %s/%s; look it up with 'rosa-boundary investigation close %s %s --status' before retrying: %w", clusterID, investigationID, clusterID, investigationID, err)
}

func submitCloseRequest(ctx context.Context, service closeService, clusterID, investigationID string) error {
	accepted, err := service.client.RequestClose(ctx, service.idToken, lambda.CloseActionRequest{
		ClusterID:       clusterID,
		InvestigationID: investigationID,
		StopScope:       closeStopScope(),
		Trigger:         lambda.TriggerCLIClose,
	})
	if err != nil {
		return closeRequestFailure(clusterID, investigationID, err)
	}
	status := &lambda.CloseStatusResponse{
		Status:            accepted.Status,
		Phase:             "accepted",
		Reason:            accepted.Message,
		RequestToken:      accepted.RequestToken,
		DirectoryRetained: true,
	}
	if closeWait {
		status, err = waitForCloseStatus(ctx, service, clusterID, investigationID, accepted.RequestToken)
		if err != nil {
			return err
		}
	}
	if err := reportCloseStatus(clusterID, investigationID, accepted, status); err != nil {
		return err
	}
	return closeWaitOutcome(clusterID, investigationID, status)
}

func closeWaitOutcome(clusterID, investigationID string, status *lambda.CloseStatusResponse) error {
	if closeWait && status.Status != lambda.CloseStatusCompleted {
		retry := "it will not be retried automatically; investigate before requesting close again"
		if status.Retryable {
			retry = "the scheduled reaper retries it"
		}
		return fmt.Errorf("close for %s/%s is %s: %s; data is retained and %s", clusterID, investigationID, status.Status, status.Reason, retry)
	}
	return nil
}

// waitForCloseStatus only reads status. A wait never reauthenticates or
// submits a request; it ends at the outcome, wait limit, or credential deadline.
func waitForCloseStatus(ctx context.Context, service closeService, clusterID, investigationID, token string) (*lambda.CloseStatusResponse, error) {
	deadline := time.Now().Add(closeWaitLimit)
	limitReason := fmt.Sprintf("the %s wait limit was reached", closeWaitLimit)
	if !service.expiry.IsZero() && !service.expiry.After(deadline) {
		deadline = service.expiry
		limitReason = "close status credentials expired or are about to expire"
	}
	waitCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stopped := func(reason string) error {
		if token == "" {
			return fmt.Errorf("stopped waiting for close of %s/%s: %s; no request submitted", clusterID, investigationID, reason)
		}
		return fmt.Errorf("stopped waiting for close of %s/%s: %s; request %s remains recorded; stopping this wait does not cancel it", clusterID, investigationID, reason, token)
	}
	resume := func() error {
		return fmt.Errorf("%w; to resume polling without submitting a request, run: %s --wait", stopped(limitReason), closeStatusCommand(clusterID, investigationID))
	}
	stopReason := func() error {
		if ctx.Err() != nil {
			return fmt.Errorf("%w: %w", stopped("the command was cancelled"), ctx.Err())
		}
		if !time.Now().Before(deadline) {
			return resume()
		}
		return nil
	}
	for {
		if err := stopReason(); err != nil {
			return nil, err
		}
		status, err := service.client.CloseStatus(waitCtx, service.idToken, lambda.CloseActionRequest{
			ClusterID: clusterID, InvestigationID: investigationID,
		})
		if err != nil {
			if stop := stopReason(); stop != nil {
				return nil, stop
			}
			return nil, fmt.Errorf("%w: %w", stopped("could not read close status"), err)
		}
		if slices.Contains(lambda.CloseWaitEndStatuses, status.Status) {
			return status, nil
		}
		if status.Status == lambda.CloseStatusNone || status.Status == lambda.CloseStatusUnknown {
			return nil, stopped(fmt.Sprintf("the service reports status %q", status.Status))
		}
		if token == "" {
			token = status.RequestToken
		}
		output.Status("Close is %s (%s); waiting…", status.Status, status.Phase)
		select {
		case <-waitCtx.Done():
		case <-time.After(closeStatusPoll):
		}
	}
}

func reportCloseStatus(clusterID, investigationID string, accepted *lambda.CloseActionResponse, status *lambda.CloseStatusResponse) error {
	if closeOutputFormat == "json" {
		return output.JSON(map[string]any{
			"profile":              selectedProfile,
			"cluster_id":           clusterID,
			"investigation_id":     investigationID,
			"request_token":        accepted.RequestToken,
			"duplicate_request":    accepted.Duplicate,
			"stop_scope":           accepted.StopScope,
			"status":               status.Status,
			"phase":                status.Phase,
			"reason":               status.Reason,
			"attempt_id":           status.AttemptID,
			"directory_retained":   status.DirectoryRetained,
			"retryable":            status.Retryable,
			"access_point_deleted": status.AccessPointDeleted,
			"waited":               closeWait,
		})
	}
	_, err := fmt.Fprintf(os.Stdout, "Close requested for %s/%s (profile %s).\nRequest: %s\nStatus: %s%s\n%s\nThe EFS directory is retained; the close service verifies the backup before removing the access point.\n",
		clusterID, investigationID, selectedProfile, accepted.RequestToken, status.Status,
		closeStatusDetail(status), closeStatusGuidance(clusterID, investigationID, status))
	return err
}

func closeStatusDetail(status *lambda.CloseStatusResponse) string {
	if status.Reason == "" {
		return ""
	}
	return " — " + status.Reason
}

func closeStatusGuidance(clusterID, investigationID string, status *lambda.CloseStatusResponse) string {
	if status.Status == lambda.CloseStatusCompleted {
		return "Close completed."
	}
	return "Accepted is not closed. Check progress with: " + closeStatusCommand(clusterID, investigationID)
}

func closeStatusCommand(clusterID, investigationID string) string {
	// Quote these as shell literals so copy-pasting cannot expand substitutions.
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	return fmt.Sprintf("rosa-boundary --profile %s investigation close %s %s --status", quote(selectedProfile), quote(clusterID), quote(investigationID))
}

// The reaper issues a lowercase UUIDv4 as the seal. It becomes one S3 key
// component in _boundary-close/<ap>/<seal>.json; never interpret it as a path.
var closeSeal = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// AuditCloseBucket must name a bucket, not an ARN or an s3:// URI. This is a
// syntax guard, not a full S3 naming check or proof that the bucket is trusted.
var closeBucket = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

var closeManifestAttempt = regexp.MustCompile(`/attempts/([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})/`)
var closeSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// checkReceipt reads the published close receipt, if any, and records whether
// it matches this exact workspace, seal and evidence. It accepts the legacy v1
// receipt unchanged and the v2 observed-quiescence receipt, and refuses any
// other schema rather than guessing what a future version guarantees.
func (p *closePlan) checkReceipt(ctx context.Context, read func(context.Context, string, string, string) ([]byte, error)) {
	p.ReceiptDigest = ""
	p.ReceiptAssurance = ""
	if len(p.SessionIDs)+len(p.SessionsWaiting) != 0 {
		// Do not fetch a receipt until sessions have stopped.
		return
	}
	if !closeSeal.MatchString(p.Seal) || !closeBucket.MatchString(p.Bucket) {
		p.receiptError = "close seal or audit bucket tag is missing or invalid"
		return
	}
	b, err := read(ctx, p.Bucket, p.AccessPointID, p.Seal)
	if err != nil {
		p.receiptError = fmt.Sprintf("cannot read close receipt: %v", err)
		return
	}
	var r struct {
		Version         int    `json:"schema_version"`
		Assurance       string `json:"assurance"`
		Cluster         string `json:"cluster_id"`
		Investigation   string `json:"investigation_id"`
		AP              string `json:"access_point_id"`
		Seal            string `json:"seal"`
		Status          string `json:"status"`
		Manifest        string `json:"manifest_ref"`
		RequestToken    string `json:"request_token"`
		AttemptID       string `json:"attempt_id"`
		VerificationRef string `json:"verification_ref"`
		ManifestSHA256  string `json:"manifest_sha256"`
	}
	if json.Unmarshal(b, &r) != nil {
		p.receiptError = "close receipt is not readable JSON"
		return
	}
	if r.Cluster != p.ClusterID || r.Investigation != p.InvestigationID || r.AP != p.AccessPointID || r.Seal != p.Seal || r.Status != "verified" {
		p.receiptError = "close receipt does not match this sealed investigation"
		return
	}
	switch r.Version {
	case 1:
		// Legacy operator receipt. Its separate verification tag stays
		// required, so an old deployment behaves exactly as before.
		if p.VerifiedSeal != p.Seal {
			p.receiptError = "legacy receipt is present without its verification tag"
			return
		}
		if strings.TrimSpace(r.Manifest) == "" {
			p.receiptError = "legacy receipt names no manifest"
			return
		}
		p.ReceiptAssurance = "operator-verified (schema v1)"
	case 2:
		// Observed quiescence. A nonempty manifest reference is not enough:
		// the receipt must name the same attempt in both evidence references
		// and carry the request token the close was authorized under.
		if r.Assurance != "observed-quiescence" {
			p.receiptError = "v2 receipt does not state the observed-quiescence assurance level"
			return
		}
		if !closeSeal.MatchString(r.RequestToken) {
			p.receiptError = "v2 receipt names no close request"
			return
		}
		if !closeSHA256.MatchString(r.ManifestSHA256) {
			p.receiptError = "v2 receipt carries no manifest digest"
			return
		}
		if !receiptEvidenceMatches(p.Bucket, p.AccessPointID, r.Manifest, r.VerificationRef, r.AttemptID) {
			p.receiptError = "v2 receipt evidence references do not name its own attempt"
			return
		}
		p.ReceiptAssurance = "observed quiescence (schema v2): verified against the recorded source observations, not an atomic cutoff"
	default:
		p.receiptError = fmt.Sprintf("close receipt schema %d is not supported by this client; upgrade rosa-boundary before relying on it", r.Version)
		return
	}
	p.receiptError = ""
	p.ReceiptDigest = fmt.Sprintf("%x", sha256.Sum256(b))
}

// receiptEvidenceMatches requires both evidence references to name this
// attempt, in this access point's evidence prefix, in the bucket the seal tag
// names. Matching the attempt UUID alone would accept a reference to another
// access point's — or another bucket's — attempt that happened to carry the
// same identifier, which is the binding this check exists to make.
func receiptEvidenceMatches(bucket, accessPointID, manifestRef, verificationRef, attemptID string) bool {
	if bucket == "" || accessPointID == "" || attemptID == "" {
		return false
	}
	expected := fmt.Sprintf("s3://%s/_boundary-close/evidence/%s/attempts/%s/",
		bucket, accessPointID, attemptID)
	for _, ref := range []string{manifestRef, verificationRef} {
		ref = strings.TrimSpace(ref)
		if !strings.HasPrefix(ref, expected) {
			return false
		}
		match := closeManifestAttempt.FindStringSubmatch(ref)
		if len(match) != 2 || match[1] != attemptID {
			return false
		}
	}
	return manifestRef != verificationRef
}

// closePlan is the read-only preview. Its three task fields keep their
// `sessions_*` JSON names for output compatibility, but they hold ECS task
// IDs: the CLI cannot observe attached sessions, and the service — not this
// plan — decides who holds the investigation. The human-readable output says
// "tasks" for that reason.
type closePlan struct {
	Profile          string   `json:"profile"`
	AccountID        string   `json:"account_id"`
	Region           string   `json:"region"`
	ECSCluster       string   `json:"ecs_cluster"`
	FilesystemID     string   `json:"efs_filesystem_id"`
	AccessPointID    string   `json:"access_point_id"`
	ClusterID        string   `json:"cluster_id"`
	InvestigationID  string   `json:"investigation_id"`
	SessionIDs       []string `json:"sessions_to_stop"`
	SessionsWaiting  []string `json:"sessions_to_wait_for_stop"`
	VisibleStopped   []string `json:"visible_stopped_sessions"`
	receiptError     string
	TaskDefinitions  []string `json:"task_definitions_to_deregister"`
	VerifiedSeal     string   `json:"audit_close_verified,omitempty"`
	Seal             string   `json:"audit_close_seal,omitempty"`
	ManagedSeal      bool     `json:"managed_close_seal"`
	Bucket           string   `json:"audit_close_bucket,omitempty"`
	ReceiptDigest    string   `json:"receipt_sha256,omitempty"`
	ReceiptAssurance string   `json:"receipt_assurance,omitempty"`
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

// resolveClosePlan builds the read-only preview. It deliberately performs no
// authorization: the service authorizes the request, and the access point's
// creator tag is provenance rather than permission.
func resolveClosePlan(ctx context.Context, efsClient *awsclient.EFSClient, ecsClient *awsclient.ECSClient, clusterID, investigationID, ecsCluster, filesystemID string) (closePlan, error) {
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
	tasks, err := ecsClient.ListVisibleInvestigationTasks(ctx, clusterID, investigationID)
	if err != nil {
		return closePlan{}, fmt.Errorf("list visible investigation tasks: %w", err)
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
	p := closePlan{VerifiedSeal: ap.Tags["AuditCloseVerified"], Seal: ap.Tags["AuditCloseSeal"], Bucket: ap.Tags["AuditCloseBucket"], ManagedSeal: ap.Tags["AuditCloseManagedBy"] == "rosa-boundary-reaper", ECSCluster: ecsCluster, FilesystemID: filesystemID, AccessPointID: ap.AccessPointID, ClusterID: clusterID, InvestigationID: investigationID, SessionIDs: []string{}, SessionsWaiting: []string{}, TaskDefinitions: verifiedDefs}
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

// blockingReason describes why the close service cannot finish yet. It is
// advisory: the service re-derives every one of these conditions, and an
// absent reason here never means cleanup already happened.
func (p closePlan) blockingReason() string {
	switch {
	case len(p.SessionIDs)+len(p.SessionsWaiting) != 0:
		return "tasks have not stopped; verification requires a quiescent workspace"
	case p.receiptError != "":
		return p.receiptError
	case p.ReceiptDigest == "":
		return "no verified close receipt yet"
	default:
		return ""
	}
}

type closePreview struct {
	closePlan
	FinalizationBlocked string `json:"finalization_blocked_reason"`
}

func (p closePlan) preview() closePreview {
	return closePreview{p, p.blockingReason()}
}

func printClosePlan(p closePreview) {
	output.Status("Profile: %s Account: %s Region: %s", p.Profile, p.AccountID, p.Region)
	output.Status("ECS: %s EFS: %s Access point: %s", p.ECSCluster, p.FilesystemID, p.AccessPointID)
	output.Status("Investigation: %s/%s", p.ClusterID, p.InvestigationID)
	output.Status("Running tasks the service would stop with --force: %v", p.SessionIDs)
	output.Status("Tasks already stopping (service waits for STOPPED): %v", p.SessionsWaiting)
	output.Status("Visible stopped tasks: %v", p.VisibleStopped)
	output.Status("Task definitions the service deregisters after verification: %v", p.TaskDefinitions)
	if p.Seal != "" {
		kind := "legacy or manual"
		if p.ManagedSeal {
			kind = "managed automated close"
		}
		output.Status("Close seal present (%s)", kind)
	}
	if p.FinalizationBlocked != "" {
		output.Status("Finalization blocked: %s", p.FinalizationBlocked)
	} else {
		output.Status("Close receipt SHA-256: %s (%s)", p.ReceiptDigest, p.ReceiptAssurance)
	}
}

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/lambda"
)

const testSeal = "fe156137-c122-45cd-9fe7-adb2d2240c0a"
const testRequest = "0c2d8b41-7ad2-4f9e-9b0a-6d2f3c5e7a81"
const testAttempt = "3b5c9f2e-8a41-4d7b-9c0e-1f2a3b4c5d6e"

const receipt = `{"schema_version":1,"cluster_id":"cluster","investigation_id":"inv","access_point_id":"fsap-1","seal":"` + testSeal + `","status":"verified","manifest_ref":"operator-manifest"}`

// The layout the reaper actually writes: attempt evidence sits under
// `evidence/` so it falls outside the SRE role's receipt read grant.
const manifestRef = `s3://regional-audit/_boundary-close/evidence/fsap-1/attempts/` + testAttempt + `/source-manifest.json`
const verificationRef = `s3://regional-audit/_boundary-close/evidence/fsap-1/attempts/` + testAttempt + `/verification.json`

var receiptV2 = `{"schema_version":2,"assurance":"observed-quiescence","cluster_id":"cluster","investigation_id":"inv",` +
	`"access_point_id":"fsap-1","seal":"` + testSeal + `","status":"verified","request_token":"` + testRequest + `",` +
	`"attempt_id":"` + testAttempt + `","manifest_ref":"` + manifestRef + `","verification_ref":"` + verificationRef + `",` +
	`"manifest_sha256":"` + strings.Repeat("ab", 32) + `"}`

func sealedPlan() closePlan {
	return closePlan{ClusterID: "cluster", InvestigationID: "inv", AccessPointID: "fsap-1", Seal: testSeal, VerifiedSeal: testSeal, Bucket: "regional-audit", VisibleStopped: []string{"task-old"}, TaskDefinitions: []string{"def"}}
}

func TestCloseReceiptValidation(t *testing.T) {
	for _, tc := range []struct {
		name, body        string
		unreadable, valid bool
	}{
		{"v1 verified", receipt, false, true},
		{"v1 denied", receipt, true, false},
		{"absent", "", false, false},
		{"v1 wrong cluster", strings.Replace(receipt, `"cluster"`, `"other"`, 1), false, false},
		{"v1 wrong investigation", strings.Replace(receipt, `"inv"`, `"other"`, 1), false, false},
		{"v1 wrong access point", strings.Replace(receipt, "fsap-1", "fsap-2", 1), false, false},
		{"v1 old seal", strings.Replace(receipt, testSeal, "other", 1), false, false},
		{"v1 transfer report", strings.Replace(receipt, "verified", "uploaded", 1), false, false},
		{"v1 no manifest", strings.Replace(receipt, "operator-manifest", "  ", 1), false, false},
		{"v1 trailing data", receipt + "{}", false, false},
		{"unsupported future schema", strings.Replace(receiptV2, `"schema_version":2`, `"schema_version":3`, 1), false, false},

		{"v2 verified", receiptV2, false, true},
		{"v2 without assurance", strings.Replace(receiptV2, "observed-quiescence", "atomic", 1), false, false},
		{"v2 without request token", strings.Replace(receiptV2, testRequest, "", 1), false, false},
		{"v2 without manifest digest", strings.Replace(receiptV2, strings.Repeat("ab", 32), "", 1), false, false},
		{"v2 evidence from another attempt", strings.Replace(receiptV2, testAttempt+`/verification.json`,
			"7a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d/verification.json", 1), false, false},
		{"v2 manifest reference without an attempt", strings.Replace(receiptV2, manifestRef,
			"s3://regional-audit/some/manifest.json", 1), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := sealedPlan()
			p.checkReceipt(context.Background(), func(_ context.Context, b, ap, s string) ([]byte, error) {
				if b != p.Bucket || ap != p.AccessPointID || s != testSeal {
					t.Fatal("wrong receipt lookup")
				}
				if tc.unreadable {
					return nil, errors.New("denied")
				}
				return []byte(tc.body), nil
			})
			if (p.ReceiptDigest != "") != tc.valid || (p.blockingReason() == "") != tc.valid {
				t.Fatalf("incorrect receipt decision: %+v (%s)", p, p.blockingReason())
			}
			if tc.valid && p.ReceiptAssurance == "" {
				t.Fatal("an accepted receipt must state its assurance level")
			}
		})
	}
	for _, change := range []func(*closePlan){
		func(p *closePlan) { p.Seal = "" },
		func(p *closePlan) { p.Seal = "../other"; p.VerifiedSeal = p.Seal },
		func(p *closePlan) { p.Bucket = "" },
		func(p *closePlan) { p.SessionsWaiting = []string{"writer"} },
	} {
		p := sealedPlan()
		change(&p)
		p.checkReceipt(context.Background(), nil)
		if p.blockingReason() == "" || p.ReceiptDigest != "" {
			t.Fatal("allowed invalid close state")
		}
	}
}

// A v1 receipt still needs its separate verification tag, so an older
// deployment behaves exactly as it did before. A v2 receipt does not: the
// generic tag is deliberately not set alongside weaker evidence, which is what
// makes an older client refuse it.
func TestReceiptVersionsUseTheirOwnVerificationSignal(t *testing.T) {
	v1 := sealedPlan()
	v1.VerifiedSeal = ""
	v1.checkReceipt(context.Background(), func(context.Context, string, string, string) ([]byte, error) {
		return []byte(receipt), nil
	})
	if v1.ReceiptDigest != "" || !strings.Contains(v1.blockingReason(), "verification tag") {
		t.Fatalf("legacy receipt accepted without its verification tag: %s", v1.blockingReason())
	}

	v2 := sealedPlan()
	v2.VerifiedSeal = ""
	v2.checkReceipt(context.Background(), func(context.Context, string, string, string) ([]byte, error) {
		return []byte(receiptV2), nil
	})
	if v2.ReceiptDigest == "" || v2.blockingReason() != "" {
		t.Fatalf("v2 receipt rejected: %s", v2.blockingReason())
	}
	if !strings.Contains(v2.ReceiptAssurance, "observed quiescence") {
		t.Fatalf("v2 assurance not reported: %q", v2.ReceiptAssurance)
	}
}

func TestIncompleteClosePlanPreview(t *testing.T) {
	p := sealedPlan() // No receipt read and no validation error.
	b, err := json.Marshal(p.preview())
	if err != nil {
		t.Fatal(err)
	}
	var preview map[string]any
	if err := json.Unmarshal(b, &preview); err != nil {
		t.Fatal(err)
	}
	if preview["finalization_blocked_reason"] != "no verified close receipt yet" || preview["access_point_id"] != p.AccessPointID {
		t.Fatalf("unexpected preview: %s", b)
	}
}

// fakeCloseService records what the CLI asked the close service to do.
type fakeCloseService struct {
	requests     []lambda.CloseActionRequest
	intents      []lambda.CloseActionRequest
	cancellation []lambda.CloseActionRequest
	accept       *lambda.CloseActionResponse
	acceptErr    error
	cancelErr    error
	statuses     []*lambda.CloseStatusResponse
	statusErr    error
	calls        int
	tokens       []string
}

// service wraps the fake in the pairing the CLI actually passes around.
func (f *fakeCloseService) service() closeService {
	return closeService{client: f, idToken: "fresh-token"}
}

func (f *fakeCloseService) CancelAutoClose(_ context.Context, _ string, req lambda.CloseActionRequest) (*lambda.CloseActionResponse, error) {
	f.cancellation = append(f.cancellation, req)
	if f.cancelErr != nil {
		return nil, f.cancelErr
	}
	return &lambda.CloseActionResponse{Cancelled: true, TaskID: req.TaskID}, nil
}

func (f *fakeCloseService) RequestClose(_ context.Context, idToken string, req lambda.CloseActionRequest) (*lambda.CloseActionResponse, error) {
	f.requests = append(f.requests, req)
	f.tokens = append(f.tokens, idToken)
	if f.acceptErr != nil {
		return nil, f.acceptErr
	}
	return f.accept, nil
}

func (f *fakeCloseService) RegisterAutoClose(_ context.Context, idToken string, req lambda.CloseActionRequest) (*lambda.CloseActionResponse, error) {
	f.intents = append(f.intents, req)
	f.tokens = append(f.tokens, idToken)
	if f.acceptErr != nil {
		return nil, f.acceptErr
	}
	return &lambda.CloseActionResponse{Registered: true, TaskID: req.TaskID, StopScope: req.StopScope}, nil
}

func (f *fakeCloseService) CloseStatus(_ context.Context, _ string, _ lambda.CloseActionRequest) (*lambda.CloseStatusResponse, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	status := f.statuses[min(f.calls, len(f.statuses)-1)]
	f.calls++
	return status, nil
}

func accepted() *lambda.CloseActionResponse {
	return &lambda.CloseActionResponse{RequestToken: testRequest, Status: lambda.CloseStatusAccepted, StopScope: lambda.StopScopeNone}
}

func TestCloseRequestSubmission(t *testing.T) {
	oldForce, oldWait, oldFormat, oldPoll := closeForce, closeWait, closeOutputFormat, closeStatusPoll
	t.Cleanup(func() {
		closeForce, closeWait, closeOutputFormat, closeStatusPoll = oldForce, oldWait, oldFormat, oldPoll
	})
	closeOutputFormat = "text"
	closeStatusPoll = time.Millisecond

	t.Run("accepted without waiting is not closed", func(t *testing.T) {
		closeForce, closeWait = false, false
		service := &fakeCloseService{accept: accepted()}
		if err := submitCloseRequest(context.Background(), service.service(), "cluster", "inv"); err != nil {
			t.Fatal(err)
		}
		if len(service.requests) != 1 || service.requests[0].StopScope != lambda.StopScopeNone {
			t.Fatalf("unexpected request: %+v", service.requests)
		}
		if service.requests[0].Trigger != lambda.TriggerCLIClose {
			t.Fatalf("unexpected trigger: %q", service.requests[0].Trigger)
		}
		if service.calls != 0 {
			t.Fatal("status must not be polled without --wait")
		}
	})

	t.Run("force is stop consent", func(t *testing.T) {
		closeForce, closeWait = true, false
		service := &fakeCloseService{accept: accepted()}
		if err := submitCloseRequest(context.Background(), service.service(), "cluster", "inv"); err != nil {
			t.Fatal(err)
		}
		if service.requests[0].StopScope != lambda.StopScopeInvestigation {
			t.Fatalf("--force must consent to stopping this investigation's tasks: %+v", service.requests[0])
		}
	})

	t.Run("waiting reports completion", func(t *testing.T) {
		closeForce, closeWait = false, true
		service := &fakeCloseService{accept: accepted(), statuses: []*lambda.CloseStatusResponse{
			{Status: lambda.CloseStatusWaitingForTasks, Phase: "drain"},
			{Status: lambda.CloseStatusCompleted, Phase: "finished", DirectoryRetained: true},
		}}
		if err := submitCloseRequest(context.Background(), service.service(), "cluster", "inv"); err != nil {
			t.Fatal(err)
		}
		if service.calls != 2 {
			t.Fatalf("expected the wait to poll until terminal, got %d calls", service.calls)
		}
	})

	t.Run("a retained outcome is not success", func(t *testing.T) {
		closeForce, closeWait = false, true
		service := &fakeCloseService{accept: accepted(), statuses: []*lambda.CloseStatusResponse{
			{Status: lambda.CloseStatusRetained, Phase: "verify", Reason: "a task was observed after the copy"},
		}}
		err := submitCloseRequest(context.Background(), service.service(), "cluster", "inv")
		if err == nil || !strings.Contains(err.Error(), "retained") {
			t.Fatalf("retained close reported as success: %v", err)
		}
	})

	t.Run("an attached shell is a definitive conflict", func(t *testing.T) {
		refusal := &lambda.ResponseError{StatusCode: 409, Message: "disconnect and retry close"}
		service := &fakeCloseService{acceptErr: refusal}
		err := submitCloseRequest(context.Background(), service.service(), "cluster", "inv")
		if !errors.Is(err, refusal) || !strings.Contains(err.Error(), "rejected for cluster/inv") || !strings.Contains(err.Error(), refusal.Message) || strings.Contains(err.Error(), "--status") {
			t.Fatalf("expected definitive refusal with service guidance, got %v", err)
		}
	})

	t.Run("an unknown outcome is not reported as persisted", func(t *testing.T) {
		closeForce, closeWait = false, false
		for _, cause := range []error{errors.New("timeout"), &lambda.ResponseError{StatusCode: 503, Message: "service unavailable"}} {
			service := &fakeCloseService{acceptErr: cause}
			err := submitCloseRequest(context.Background(), service.service(), "cluster", "inv")
			if !errors.Is(err, cause) || !strings.Contains(err.Error(), "outcome is unknown") || !strings.Contains(err.Error(), "--status") {
				t.Fatalf("expected status lookup guidance, got %v", err)
			}
		}
	})

	t.Run("stopping a wait does not cancel the request", func(t *testing.T) {
		closeForce, closeWait = false, true
		ctx, cancel := context.WithCancel(context.Background())
		service := &fakeCloseService{accept: accepted(), statuses: []*lambda.CloseStatusResponse{
			{Status: lambda.CloseStatusVerifying, Phase: "copy"},
		}}
		go func() {
			time.Sleep(5 * time.Millisecond)
			cancel()
		}()
		err := submitCloseRequest(ctx, service.service(), "cluster", "inv")
		if err == nil || !strings.Contains(err.Error(), "remains recorded") {
			t.Fatalf("expected the wait to say the request persists, got %v", err)
		}
	})
}

// Confirmation gates submission. Stop consent controls later drain, not submission.
func TestCloseSubmissionGate(t *testing.T) {
	oldForce, oldYes, oldDry := closeForce, closeYes, closeDryRun
	t.Cleanup(func() { closeForce, closeYes, closeDryRun = oldForce, oldYes, oldDry })

	busy := closePlan{ClusterID: "cluster", InvestigationID: "inv", SessionIDs: []string{"task-1"}}
	stopping := closePlan{ClusterID: "cluster", InvestigationID: "inv", SessionsWaiting: []string{"task-1"}}
	idle := closePlan{ClusterID: "cluster", InvestigationID: "inv"}

	for _, tc := range []struct {
		name               string
		plan               closePlan
		force, yes, dryRun bool
		answer             bool
		answerErr          error
		wantSubmit         bool
		wantErr            string
		wantAsked          bool
	}{
		{name: "dry run submits nothing", plan: busy, dryRun: true},
		{name: "dry run does not even ask", plan: idle, dryRun: true},
		{name: "running session without consent", plan: busy, yes: true, wantSubmit: true},
		{name: "session already stopping without consent", plan: stopping, yes: true, wantSubmit: true},
		{name: "force is consent", plan: busy, force: true, yes: true, wantSubmit: true},
		{name: "confirmation declined", plan: idle, wantAsked: true, wantErr: "aborted"},
		{name: "confirmation accepted", plan: idle, answer: true, wantAsked: true,
			wantSubmit: true},
		{name: "confirmation unavailable", plan: idle, wantAsked: true,
			answerErr: errors.New("--yes is required without a terminal"),
			wantErr:   "--yes is required"},
		{name: "yes skips the prompt", plan: idle, yes: true, wantSubmit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closeForce, closeYes, closeDryRun = tc.force, tc.yes, tc.dryRun
			asked := false
			submit, err := closeSubmissionGate(tc.plan, func(closePlan) (bool, error) {
				asked = true
				return tc.answer, tc.answerErr
			})
			if submit != tc.wantSubmit {
				t.Fatalf("submit = %v, want %v", submit, tc.wantSubmit)
			}
			if (tc.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if asked != tc.wantAsked {
				t.Fatalf("confirmation asked = %v, want %v", asked, tc.wantAsked)
			}
		})
	}
}

// A session can outlive the credentials the command started with, so the
// request must carry the token the close service was built with.
func TestCloseRequestUsesTheServiceToken(t *testing.T) {
	oldWait, oldFormat := closeWait, closeOutputFormat
	t.Cleanup(func() { closeWait, closeOutputFormat = oldWait, oldFormat })
	closeWait, closeOutputFormat = false, "text"
	service := &fakeCloseService{accept: accepted()}
	if err := submitCloseRequest(context.Background(), service.service(), "cluster", "inv"); err != nil {
		t.Fatal(err)
	}
	if len(service.tokens) != 1 || service.tokens[0] != "fresh-token" {
		t.Fatalf("request sent with %v, want the service's own token", service.tokens)
	}
}

func TestWaitEndsOnEveryOutcomeTheServiceWillNotLeave(t *testing.T) {
	oldWait, oldFormat, oldPoll := closeWait, closeOutputFormat, closeStatusPoll
	t.Cleanup(func() { closeWait, closeOutputFormat, closeStatusPoll = oldWait, oldFormat, oldPoll })
	closeWait, closeOutputFormat, closeStatusPoll = true, "text", time.Millisecond

	for _, tc := range []struct {
		status  string
		wantErr string
	}{
		{lambda.CloseStatusCompleted, ""},
		{lambda.CloseStatusRetained, "retained"},
		// A finished pass that needs attention must end the wait, not spin.
		{lambda.CloseStatusCleanupIncomplete, "cleanup_incomplete"},
	} {
		t.Run(tc.status, func(t *testing.T) {
			service := &fakeCloseService{accept: accepted(), statuses: []*lambda.CloseStatusResponse{
				{Status: tc.status, Phase: "finished"},
			}}
			err := submitCloseRequest(context.Background(), service.service(), "cluster", "inv")
			if (tc.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestWaitRefusesAStatusItCannotTrack(t *testing.T) {
	oldWait, oldFormat, oldPoll := closeWait, closeOutputFormat, closeStatusPoll
	t.Cleanup(func() { closeWait, closeOutputFormat, closeStatusPoll = oldWait, oldFormat, oldPoll })
	closeWait, closeOutputFormat, closeStatusPoll = true, "text", time.Millisecond
	for _, status := range []string{lambda.CloseStatusNone, lambda.CloseStatusUnknown} {
		service := &fakeCloseService{accept: accepted(), statuses: []*lambda.CloseStatusResponse{
			{Status: status},
		}}
		err := submitCloseRequest(context.Background(), service.service(), "cluster", "inv")
		if err == nil || !strings.Contains(err.Error(), "remains recorded") {
			t.Fatalf("status %q did not end the wait: %v", status, err)
		}
	}
}

// An interactive command has no context deadline, so the wait has to bound
// itself rather than poll forever.
func TestWaitIsBoundedWithoutAContextDeadline(t *testing.T) {
	oldWait, oldFormat, oldPoll, oldLimit := closeWait, closeOutputFormat, closeStatusPoll, closeWaitLimit
	t.Cleanup(func() {
		closeWait, closeOutputFormat, closeStatusPoll, closeWaitLimit = oldWait, oldFormat, oldPoll, oldLimit
	})
	closeWait, closeOutputFormat = true, "text"
	closeStatusPoll, closeWaitLimit = time.Millisecond, 2*time.Millisecond
	service := &fakeCloseService{accept: accepted(), statuses: []*lambda.CloseStatusResponse{
		{Status: lambda.CloseStatusVerifying, Phase: "copy"},
	}}
	err := submitCloseRequest(context.Background(), service.service(), "cluster", "inv")
	if err == nil || !strings.Contains(err.Error(), "remains recorded") {
		t.Fatalf("the wait was not bounded: %v", err)
	}
}

func TestWaitSurfacesAStatusLookupFailure(t *testing.T) {
	oldWait, oldFormat := closeWait, closeOutputFormat
	t.Cleanup(func() { closeWait, closeOutputFormat = oldWait, oldFormat })
	closeWait, closeOutputFormat = true, "text"
	service := &fakeCloseService{accept: accepted(), statusErr: errors.New("denied")}
	err := submitCloseRequest(context.Background(), service.service(), "cluster", "inv")
	if err == nil || !strings.Contains(err.Error(), "does not cancel it") {
		t.Fatalf("expected the request to be described as persisting: %v", err)
	}
}

// Only a retention the service will revisit may be described as retried.
func TestRetentionReportsWhetherItWillBeRetried(t *testing.T) {
	oldWait, oldFormat, oldPoll := closeWait, closeOutputFormat, closeStatusPoll
	t.Cleanup(func() { closeWait, closeOutputFormat, closeStatusPoll = oldWait, oldFormat, oldPoll })
	closeWait, closeOutputFormat, closeStatusPoll = true, "text", time.Millisecond
	for _, tc := range []struct {
		retryable bool
		want      string
	}{
		{true, "scheduled reaper retries it"},
		{false, "will not be retried automatically"},
	} {
		service := &fakeCloseService{accept: accepted(), statuses: []*lambda.CloseStatusResponse{
			{Status: lambda.CloseStatusRetained, Reason: "a manual hold is present",
				Retryable: tc.retryable},
		}}
		err := submitCloseRequest(context.Background(), service.service(), "cluster", "inv")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("retryable=%v reported as %v", tc.retryable, err)
		}
	}
}

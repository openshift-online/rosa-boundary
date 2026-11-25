package cmd

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/lambda"
)

func TestOnlyCreatorMayJoin(t *testing.T) {
	token := credentialGuidanceToken("user-1")
	for _, tc := range []struct {
		token, creator string
		ok             bool
	}{
		{token, "user-1", true}, {token, "other", false}, {token, "", false}, {"", "", false},
	} {
		if err := requireSessionCreator(tc.token, tc.creator); (err == nil) != tc.ok {
			t.Errorf("creator %q: %v", tc.creator, err)
		}
	}
}

func hookTarget() sessionCloseTarget {
	return sessionCloseTarget{ClusterID: "cluster", InvestigationID: "inv", SessionID: "task-1", AccessPointID: "fsap-1"}
}

func resolvesTo(target sessionCloseTarget) func() (sessionCloseTarget, error) {
	return func() (sessionCloseTarget, error) { return target, nil }
}

func withHookState(t *testing.T, auto, stopAll bool, answer bool) *fakeCloseService {
	t.Helper()
	previousAuto, previousAll, previousPrompt := autoCloseRequested, autoCloseStopAll, sessionClosePrompt
	t.Cleanup(func() {
		autoCloseRequested, autoCloseStopAll, sessionClosePrompt = previousAuto, previousAll, previousPrompt
	})
	autoCloseRequested, autoCloseStopAll = auto, stopAll
	sessionClosePrompt = func(sessionCloseTarget) bool { return answer }
	return &fakeCloseService{accept: &lambda.CloseActionResponse{
		RequestToken: "token-1", Status: lambda.CloseStatusAccepted,
	}}
}

func TestJoinRequiresOpenInvestigation(t *testing.T) {
	target := hookTarget()
	open := lambda.CloseStatusResponse{ClusterID: target.ClusterID, InvestigationID: target.InvestigationID, Status: lambda.CloseStatusNone, Seal: "none", AccessPointPresent: true, JoinAccessPointID: target.AccessPointID}
	for _, tc := range []struct {
		name   string
		change func(*lambda.CloseStatusResponse)
	}{
		{"open", func(*lambda.CloseStatusResponse) {}},
		{"accepted", func(s *lambda.CloseStatusResponse) { s.Status = lambda.CloseStatusAccepted }},
		{"completed", func(s *lambda.CloseStatusResponse) { s.Status = lambda.CloseStatusCompleted }},
		{"unknown", func(s *lambda.CloseStatusResponse) { s.Status = lambda.CloseStatusUnknown }},
		{"queued", func(s *lambda.CloseStatusResponse) { s.OpenRequests = 1 }},
		{"manual seal", func(s *lambda.CloseStatusResponse) { s.Seal = "legacy" }},
		{"old service", func(s *lambda.CloseStatusResponse) { s.JoinAccessPointID = "" }},
		{"replacement AP", func(s *lambda.CloseStatusResponse) { s.JoinAccessPointID = "fsap-2" }},
		{"missing AP", func(s *lambda.CloseStatusResponse) { s.AccessPointPresent = false }},
		{"wrong investigation", func(s *lambda.CloseStatusResponse) { s.InvestigationID = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := open
			tc.change(&s)
			f := &fakeCloseService{statuses: []*lambda.CloseStatusResponse{&s}}
			err := requireOpenForJoin(context.Background(), f.service(), target)
			if (err == nil) != (tc.name == "open") {
				t.Fatalf("join admission: %v", err)
			}
		})
	}
	f := &fakeCloseService{statusErr: errors.New("status unavailable")}
	if err := requireOpenForJoin(context.Background(), f.service(), target); err == nil {
		t.Fatal("joined without status")
	}
}

func runHook(service *fakeCloseService, jsonOutput bool) sessionCloseOutcome {
	return afterAttachedSession(context.Background(),
		func() (closeService, error) { return service.service(), nil },
		resolvesTo(hookTarget()), jsonOutput)
}

// Leaving a shell is not a decision to close: the prompt defaults to no.
func TestExitPromptDefaultsToLeavingTheInvestigationOpen(t *testing.T) {
	service := withHookState(t, false, false, false)
	outcome := runHook(service, false)
	if outcome.Requested || len(service.requests) != 0 {
		t.Fatalf("declining the prompt requested a close: %+v", outcome)
	}
}

func TestExitPromptAcceptedRequestsCloseOfOnlyThisSession(t *testing.T) {
	service := withHookState(t, false, false, true)
	outcome := runHook(service, false)
	if !outcome.Requested || outcome.RequestToken != "token-1" {
		t.Fatalf("accepted prompt did not record a request: %+v", outcome)
	}
	if len(service.requests) != 1 {
		t.Fatalf("unexpected requests: %+v", service.requests)
	}
	req := service.requests[0]
	if req.Trigger != lambda.TriggerSessionExitPrompt || req.StopScope != lambda.StopScopeSessionTask {
		t.Fatalf("unexpected request shape: %+v", req)
	}
	if !slices.Equal(req.StopTaskIDs, []string{"task-1"}) {
		t.Fatalf("exit consent must name only this session's task: %v", req.StopTaskIDs)
	}
}

// Machine-readable output has nobody to answer a prompt, so nothing is asked
// and nothing is closed.
func TestNoPromptForMachineReadableOutput(t *testing.T) {
	service := withHookState(t, false, false, true)
	outcome := runHook(service, true)
	if outcome.Requested || len(service.requests) != 0 {
		t.Fatalf("prompted or closed with JSON output: %+v", outcome)
	}
}

func TestAutoCloseSkipsThePromptAndKeepsItsScope(t *testing.T) {
	service := withHookState(t, true, false, false)
	outcome := runHook(service, true)
	if !outcome.Requested || outcome.Trigger != lambda.TriggerAutoClose {
		t.Fatalf("--auto-close did not request a close: %+v", outcome)
	}
	if service.requests[0].StopScope != lambda.StopScopeSessionTask ||
		!slices.Equal(service.requests[0].StopTaskIDs, []string{"task-1"}) {
		t.Fatalf("--auto-close widened its stop consent: %+v", service.requests[0])
	}
}

func TestAutoCloseStopAllConsentsToTheWholeInvestigation(t *testing.T) {
	service := withHookState(t, true, true, false)
	runHook(service, false)
	req := service.requests[0]
	if req.StopScope != lambda.StopScopeInvestigation || len(req.StopTaskIDs) != 0 {
		t.Fatalf("--auto-close-stop-all did not request whole-investigation consent: %+v", req)
	}
}

// A close that could not be requested must not be reported as one, and must
// not turn a successful session into a failure.
func TestFailedCloseRequestLeavesTheInvestigationOpen(t *testing.T) {
	service := withHookState(t, true, false, false)
	service.acceptErr = errors.New("service unavailable")
	outcome := runHook(service, false)
	if outcome.Requested || outcome.Note == "" {
		t.Fatalf("failed request reported as a close: %+v", outcome)
	}
}

func TestSessionCallbackReportsDefinitiveConflict(t *testing.T) {
	service := withHookState(t, true, false, false)
	service.acceptErr = &lambda.ResponseError{StatusCode: 409, Message: "disconnect and retry close"}
	outcome := runHook(service, true)
	if outcome.Requested || !strings.Contains(outcome.Note, "rejected") || !strings.Contains(outcome.Note, "disconnect and retry close") || strings.Contains(outcome.Note, "--status") {
		t.Fatalf("expected callback refusal, got %+v", outcome)
	}
}

func TestUnresolvableInvestigationDoesNotRequestClose(t *testing.T) {
	service := withHookState(t, true, false, true)
	outcome := afterAttachedSession(context.Background(),
		func() (closeService, error) { return service.service(), nil },
		func() (sessionCloseTarget, error) { return sessionCloseTarget{}, errors.New("no tags") }, false)
	if outcome.Requested || len(service.requests) != 0 {
		t.Fatalf("closed without a trusted investigation identity: %+v", outcome)
	}
}

// --auto-close promises an intent before attaching. If it cannot be persisted,
// the command must fail rather than attach without it.
func TestAutoCloseIntentFailureIsVisible(t *testing.T) {
	service := withHookState(t, true, false, false)
	service.acceptErr = errors.New("denied")
	if err := registerAutoCloseIntent(context.Background(), service.service(), hookTarget()); err == nil {
		t.Fatal("auto-close setup failure was swallowed")
	}
	if err := registerAutoCloseIntent(context.Background(), closeService{}, hookTarget()); err == nil {
		t.Fatal("auto-close accepted without a close service")
	}
}

func TestAutoCloseIntentRecordsTheSelectedTask(t *testing.T) {
	service := withHookState(t, true, false, false)
	if err := registerAutoCloseIntent(context.Background(), service.service(), hookTarget()); err != nil {
		t.Fatal(err)
	}
	if len(service.intents) != 1 || service.intents[0].TaskID != "task-1" ||
		service.intents[0].StopScope != lambda.StopScopeSessionTask {
		t.Fatalf("intent not tied to the selected session: %+v", service.intents)
	}
}

// Accepted is never closed, whatever the hook did.
func TestCloseOutcomeNeverClaimsTheInvestigationIsClosed(t *testing.T) {
	summary := applyCloseOutcome(map[string]any{}, sessionCloseOutcome{
		Requested: true, RequestToken: "token-1", Status: lambda.CloseStatusAccepted,
	})
	if summary["investigation_closed"] != false || summary["close_requested"] != true {
		t.Fatalf("misleading close summary: %v", summary)
	}
	if summary["close_request_token"] != "token-1" {
		t.Fatalf("request identity missing from the summary: %v", summary)
	}
}

// An intent recorded before a session that never attached must be withdrawn:
// the SRE asked to close when their session ended, not when it failed to start.
func TestAutoCloseIntentIsWithdrawnWhenAttachmentFails(t *testing.T) {
	service := withHookState(t, true, false, false)
	withdrawAutoCloseIntent(context.Background(), service.service(), hookTarget(), nil)
	if len(service.cancellation) != 1 || service.cancellation[0].TaskID != "task-1" {
		t.Fatalf("intent not withdrawn: %+v", service.cancellation)
	}
}

func TestAutoCloseWithdrawalRefreshesExpiredInvokerCredentials(t *testing.T) {
	for _, fail := range []bool{false, true} {
		stale, fresh := &fakeCloseService{}, &fakeCloseService{}
		service := stale.service()
		service.expiry = time.Now().Add(-time.Minute)
		withdrawAutoCloseIntent(context.Background(), service, hookTarget(), func() (closeService, error) {
			if fail {
				return closeService{}, errors.New("sign-in failed")
			}
			return fresh.service(), nil
		})
		if len(stale.cancellation) != 0 {
			t.Fatal("attempted withdrawal with expired credentials")
		}
		if fail {
			if len(fresh.cancellation) != 0 {
				t.Fatal("attempted withdrawal despite failed reauthorization")
			}
		} else if len(fresh.cancellation) != 1 || fresh.cancellation[0].TaskID != "task-1" {
			t.Fatalf("intent not withdrawn with fresh credentials: %+v", fresh.cancellation)
		}
	}
}

func TestAFailedWithdrawalWarnsRatherThanFailingTheCommand(t *testing.T) {
	service := withHookState(t, true, false, false)
	service.cancelErr = errors.New("denied")
	// Must not panic or return; the session error is the one that matters.
	withdrawAutoCloseIntent(context.Background(), service.service(), hookTarget(), nil)
	withdrawAutoCloseIntent(context.Background(), closeService{}, hookTarget(), nil)
}

// The close service is built after the shell exits, so a long session cannot
// be closed with credentials that expired during it.
func TestTheHookBuildsItsServiceOnlyWhenACloseIsRequested(t *testing.T) {
	for _, tc := range []struct{ auto, answer, wantBuilt bool }{
		{auto: false, answer: false, wantBuilt: false},
		{auto: false, answer: true, wantBuilt: true},
		{auto: true, answer: false, wantBuilt: true},
	} {
		service := withHookState(t, tc.auto, false, tc.answer)
		built := 0
		afterAttachedSession(context.Background(), func() (closeService, error) {
			built++
			return service.service(), nil
		}, resolvesTo(hookTarget()), false)
		if (built > 0) != tc.wantBuilt {
			t.Fatalf("auto=%v answer=%v built the service %d times", tc.auto, tc.answer, built)
		}
	}
}

func TestTheHookSendsTheServicesOwnToken(t *testing.T) {
	service := withHookState(t, true, false, false)
	runHook(service, false)
	if len(service.tokens) != 1 || service.tokens[0] != "fresh-token" {
		t.Fatalf("request sent with %v, want the service's own token", service.tokens)
	}
}

func TestAnUnavailableCloseServiceLeavesTheInvestigationOpen(t *testing.T) {
	withHookState(t, true, false, false)
	outcome := afterAttachedSession(context.Background(),
		func() (closeService, error) { return closeService{}, errors.New("no credentials") },
		resolvesTo(hookTarget()), false)
	if outcome.Requested || outcome.Note == "" {
		t.Fatalf("an unavailable service must not look like a close: %+v", outcome)
	}
}

package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/lambda"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

// One shared post-attachment policy for both attached paths — session create
// and session join. Disconnecting still does not close an investigation by
// itself: either the SRE answers the prompt, or they asked for --auto-close
// before attaching, and in both cases the close service revalidates who may
// close before anything is sealed.

var (
	autoCloseRequested bool
	autoCloseStopAll   bool
)

// closeServiceFactory builds the close service when one is actually needed.
// It is deliberately called late: a session may run for hours, and the close
// service validates the ID token's expiry, so a token minted before the shell
// started would be rejected after a long session.
type closeServiceFactory func() (closeService, error)

// sessionCloseTarget identifies what a close request would act on. The
// investigation is taken from the service's own task tags, not from whatever
// the user typed on the command line.
type sessionCloseTarget struct {
	ClusterID       string
	InvestigationID string
	SessionID       string
}

func (t sessionCloseTarget) valid() bool {
	return t.ClusterID != "" && t.InvestigationID != "" && t.SessionID != ""
}

// resolveSessionCloseTarget reads the investigation identity recorded on the
// task by the service that launched it.
func resolveSessionCloseTarget(ctx context.Context, ecsClient *awsclient.ECSClient, sessionID string) (sessionCloseTarget, error) {
	task, err := ecsClient.DescribeTask(ctx, sessionID)
	if err != nil {
		return sessionCloseTarget{}, fmt.Errorf("cannot identify the investigation for session %s: %w", sessionID, err)
	}
	target := sessionCloseTarget{
		ClusterID:       task.Tags["cluster_id"],
		InvestigationID: task.Tags["investigation_id"],
		SessionID:       sessionID,
	}
	if !target.valid() {
		return sessionCloseTarget{}, fmt.Errorf("session %s has no investigation identity tags; close cannot be requested for it", sessionID)
	}
	return target, nil
}

func autoCloseStopScope() string {
	if autoCloseStopAll {
		return lambda.StopScopeInvestigation
	}
	return lambda.StopScopeSessionTask
}

// registerAutoCloseIntent persists the intent before the CLI attaches, so a
// crashed or disconnected CLI still leaves a record the reaper can act on once
// the task stops. A persistence failure fails the requested setup rather than
// attaching without the promised intent.
func registerAutoCloseIntent(ctx context.Context, service closeService, target sessionCloseTarget) error {
	if service.client == nil {
		return fmt.Errorf("--auto-close needs the close service; set lambda_function_name and invoker_role_arn in the selected profile")
	}
	req := lambda.CloseActionRequest{
		ClusterID:       target.ClusterID,
		InvestigationID: target.InvestigationID,
		TaskID:          target.SessionID,
		StopScope:       autoCloseStopScope(),
	}
	if _, err := service.client.RegisterAutoClose(ctx, service.idToken, req); err != nil {
		return fmt.Errorf("--auto-close intent could not be recorded for %s/%s, so no session was attached: %w", target.ClusterID, target.InvestigationID, err)
	}
	output.Status("Auto-close intent recorded for %s/%s (stop scope: %s).", target.ClusterID, target.InvestigationID, autoCloseStopScope())
	return nil
}

// withdrawAutoCloseIntent removes an intent whose session never attached. The
// SRE asked to close when their session ended; a session that never began is
// not that, and the reaper would otherwise act on it once the task stops.
func withdrawAutoCloseIntent(ctx context.Context, service closeService, target sessionCloseTarget) {
	if service.client == nil {
		return
	}
	if _, err := service.client.CancelAutoClose(ctx, service.idToken, lambda.CloseActionRequest{
		ClusterID:       target.ClusterID,
		InvestigationID: target.InvestigationID,
		TaskID:          target.SessionID,
	}); err != nil {
		output.Warning("the auto-close intent for %s/%s could not be withdrawn after the session failed to attach; withdraw it with 'rosa-boundary session join %s --auto-close=false' or let the close service supersede it: %v",
			target.ClusterID, target.InvestigationID, target.SessionID, err)
	}
}

// sessionClosePrompt is replaceable by tests that must not open a terminal.
var sessionClosePrompt = promptForClose

// promptForClose asks whether to request close after a normal exit. The
// default is to leave the investigation open: a disconnect is not a decision.
// It prompts on the controlling terminal, which the interactive session has
// already released, and never prompts without one.
func promptForClose(target sessionCloseTarget) bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer func() { _ = tty.Close() }()
	if !term.IsTerminal(int(tty.Fd())) {
		return false
	}
	if _, err := fmt.Fprintf(tty, "\nSession %s ended. Request close of investigation %s/%s? Other sessions would keep it open. [y/N]: ",
		target.SessionID, target.ClusterID, target.InvestigationID); err != nil {
		return false
	}
	scanner := bufio.NewScanner(tty)
	if !scanner.Scan() {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(scanner.Text()), "y")
}

// sessionCloseOutcome reports what the hook did, for the command's result.
type sessionCloseOutcome struct {
	Requested    bool
	RequestToken string
	Status       string
	Trigger      string
	Note         string
}

// afterAttachedSession runs the shared post-attachment policy.
//
// It is only reached after a normal interactive exit: a failed attachment, a
// cancelled command, a timeout or a lost connection returns earlier and
// preserves its own result. Nothing here closes anything directly; it records
// a request the close service must still authorize.
// resolveTarget and newClient are only called once a close is actually in
// play, so a machine-readable run makes no extra API call and an ordinary join
// never pays for a role assumption it does not need.
func afterAttachedSession(ctx context.Context, newService closeServiceFactory, resolveTarget func() (sessionCloseTarget, error), jsonOutput bool) sessionCloseOutcome {
	trigger := lambda.TriggerSessionExitPrompt
	scope := lambda.StopScopeSessionTask
	if autoCloseRequested {
		trigger = lambda.TriggerAutoClose
		scope = autoCloseStopScope()
	} else if jsonOutput {
		// Never prompt when the result is machine-readable.
		return sessionCloseOutcome{}
	}
	target, err := resolveTarget()
	if err != nil || !target.valid() {
		return sessionCloseOutcome{Note: "investigation identity unavailable; no close was requested"}
	}
	if !autoCloseRequested {
		// Default to leaving the investigation open: a disconnect is not a
		// decision, and there may be no terminal to answer on.
		if !sessionClosePrompt(target) {
			return sessionCloseOutcome{}
		}
	}
	service, serviceErr := newService()
	if serviceErr != nil {
		output.Warning("close was not requested for %s/%s: the close service is unavailable (%v); the investigation stays open",
			target.ClusterID, target.InvestigationID, serviceErr)
		return sessionCloseOutcome{Note: "the close service is unavailable; the investigation stays open"}
	}
	if service.client == nil {
		output.Warning("close was not requested for %s/%s: this profile has no close service configured; the investigation stays open",
			target.ClusterID, target.InvestigationID)
		return sessionCloseOutcome{Note: "the close service is not configured; the investigation stays open"}
	}
	stopTasks := []string{target.SessionID}
	if scope == lambda.StopScopeInvestigation {
		stopTasks = nil
	}
	accepted, requestErr := service.client.RequestClose(ctx, service.idToken, lambda.CloseActionRequest{
		ClusterID:       target.ClusterID,
		InvestigationID: target.InvestigationID,
		StopScope:       scope,
		StopTaskIDs:     stopTasks,
		Trigger:         trigger,
	})
	if requestErr != nil {
		// The session itself succeeded; say exactly what is unresolved rather
		// than turning a close failure into a session failure.
		output.Warning("close was not requested for %s/%s: %v; the investigation stays open and can be closed with 'rosa-boundary investigation close %s %s'",
			target.ClusterID, target.InvestigationID, requestErr, target.ClusterID, target.InvestigationID)
		return sessionCloseOutcome{Note: "close request failed; the investigation stays open"}
	}
	output.Status("Close requested for %s/%s (request %s). Accepted is not closed: the close service verifies the backup first.",
		target.ClusterID, target.InvestigationID, accepted.RequestToken)
	return sessionCloseOutcome{
		Requested:    true,
		RequestToken: accepted.RequestToken,
		Status:       accepted.Status,
		Trigger:      trigger,
	}
}

// applyCloseOutcome adds the hook's result to a command's JSON summary.
func applyCloseOutcome(summary map[string]any, outcome sessionCloseOutcome) map[string]any {
	summary["close_requested"] = outcome.Requested
	if outcome.RequestToken != "" {
		summary["close_request_token"] = outcome.RequestToken
		summary["close_status"] = outcome.Status
		summary["close_trigger"] = outcome.Trigger
	}
	if outcome.Note != "" {
		summary["close_note"] = outcome.Note
	}
	// A recorded request is not a completed close.
	summary["investigation_closed"] = false
	return summary
}

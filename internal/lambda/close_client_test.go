package lambda

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
)

// recordingInvoker keeps the event the client sent so the wire contract with
// the Python close handler can be asserted.
type recordingInvoker struct {
	sent    lambdaEventPayload
	payload []byte
}

func (r *recordingInvoker) Invoke(_ context.Context, input *awslambda.InvokeInput, _ ...func(*awslambda.Options)) (*awslambda.InvokeOutput, error) {
	_ = json.Unmarshal(input.Payload, &r.sent)
	return &awslambda.InvokeOutput{Payload: r.payload}, nil
}

func sentBody(t *testing.T, invoker *recordingInvoker) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal([]byte(invoker.sent.Body), &body); err != nil {
		t.Fatalf("request body is not JSON: %q", invoker.sent.Body)
	}
	return body
}

func TestRequestCloseSendsTheAuthenticatedAction(t *testing.T) {
	invoker := &recordingInvoker{payload: buildLambdaResponse(http.StatusOK, map[string]any{
		"action": "request_close", "request_token": "token-1", "status": "accepted",
		"state": "active", "stop_scope": StopScopeSessionTask,
	})}
	client := &Client{functionName: "test-function", sdk: invoker}

	result, err := client.RequestClose(context.Background(), "id-token", CloseActionRequest{
		ClusterID: "cluster", InvestigationID: "inv",
		StopScope: StopScopeSessionTask, StopTaskIDs: []string{"task-1"},
		Trigger: TriggerCLIClose,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RequestToken != "token-1" || result.Status != CloseStatusAccepted {
		t.Fatalf("unexpected response: %+v", result)
	}
	if invoker.sent.Headers["x-oidc-token"] != "id-token" {
		t.Fatalf("OIDC token not sent in headers: %v", invoker.sent.Headers)
	}
	body := sentBody(t, invoker)
	if body["action"] != "request_close" || body["stop_scope"] != StopScopeSessionTask ||
		body["trigger"] != TriggerCLIClose {
		t.Fatalf("unexpected request body: %v", body)
	}
	if ids, ok := body["stop_task_ids"].([]any); !ok || len(ids) != 1 || ids[0] != "task-1" {
		t.Fatalf("stop consent not sent: %v", body["stop_task_ids"])
	}
}

// A response without an identity means the caller cannot look the request up
// later, so it must not read as a successful submission.
func TestRequestCloseRejectsAnAnonymousAcceptance(t *testing.T) {
	invoker := &recordingInvoker{payload: buildLambdaResponse(http.StatusOK, map[string]any{
		"action": "request_close", "status": "accepted",
	})}
	client := &Client{functionName: "test-function", sdk: invoker}
	if _, err := client.RequestClose(context.Background(), "id-token", CloseActionRequest{}); err == nil {
		t.Fatal("accepted a request without its identity")
	}
}

func TestCloseStatusSurfacesServiceErrors(t *testing.T) {
	denied := &recordingInvoker{payload: buildLambdaResponse(http.StatusForbidden, map[string]any{
		"error": "this investigation is held by another SRE",
	})}
	client := &Client{functionName: "test-function", sdk: denied}
	_, err := client.CloseStatus(context.Background(), "id-token", CloseActionRequest{
		ClusterID: "cluster", InvestigationID: "inv",
	})
	if err == nil || !strings.Contains(err.Error(), "held by another SRE") {
		t.Fatalf("service refusal not surfaced: %v", err)
	}

	ok := &recordingInvoker{payload: buildLambdaResponse(http.StatusOK, map[string]any{
		"action": "close_status", "status": CloseStatusRetained, "phase": "verify",
		"reason": "a task was observed after the copy", "directory_retained": true,
		"access_point_present": false,
	})}
	client = &Client{functionName: "test-function", sdk: ok}
	status, err := client.CloseStatus(context.Background(), "id-token", CloseActionRequest{
		ClusterID: "cluster", InvestigationID: "inv",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Status must stay answerable once the access point is gone.
	if status.Status != CloseStatusRetained || !status.DirectoryRetained || status.AccessPointPresent {
		t.Fatalf("unexpected status: %+v", status)
	}
}

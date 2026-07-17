package lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
)

// mockLambdaInvoker is a mock for the Lambda SDK client that implements the
// lambdaInvoker interface.
type mockLambdaInvoker struct {
	payload       []byte
	functionError *string
	err           error
}

func (m *mockLambdaInvoker) Invoke(ctx context.Context, input *awslambda.InvokeInput, opts ...func(*awslambda.Options)) (*awslambda.InvokeOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &awslambda.InvokeOutput{
		Payload:       m.payload,
		FunctionError: m.functionError,
	}, nil
}

// newTestClient returns a Client wired to the given mock SDK invoker.
func newTestClient(mock *mockLambdaInvoker) *Client {
	return &Client{
		functionName: "test-function",
		sdk:          mock,
	}
}

// buildLambdaResponse constructs a mock Lambda API-style response payload.
func buildLambdaResponse(statusCode int, body interface{}) []byte {
	bodyBytes, _ := json.Marshal(body)
	resp := lambdaAPIResponse{
		StatusCode: statusCode,
		Body:       string(bodyBytes),
	}
	payload, _ := json.Marshal(resp)
	return payload
}

func TestGetConfig_Success(t *testing.T) {
	configBody := map[string]interface{}{
		"action": "get_config",
		"config": map[string]interface{}{
			"lambda_function_name": "rosa-boundary-dev-create-investigation",
			"invoker_role_arn":     "arn:aws:iam::123:role/invoker",
			"sre_role_arn":         "arn:aws:iam::123:role/sre-shared",
			"efs_filesystem_id":    "fs-abc123",
			"ecs_cluster_name":     "rosa-boundary-dev",
			"aws_region":           "us-east-2",
			"keycloak_url":         "https://auth.redhat.com/auth",
			"keycloak_realm":       "EmployeeIDP",
			"oidc_client_id":       "rosa-boundary-sre",
		},
	}

	mock := &mockLambdaInvoker{payload: buildLambdaResponse(http.StatusOK, configBody)}
	client := newTestClient(mock)

	cfg, err := client.GetConfig(context.Background())
	if err != nil {
		t.Fatalf("GetConfig returned unexpected error: %v", err)
	}

	if cfg.LambdaFunctionName != "rosa-boundary-dev-create-investigation" {
		t.Errorf("expected lambda_function_name 'rosa-boundary-dev-create-investigation', got %q", cfg.LambdaFunctionName)
	}
	if cfg.InvokerRoleARN != "arn:aws:iam::123:role/invoker" {
		t.Errorf("expected invoker_role_arn, got %q", cfg.InvokerRoleARN)
	}
	if cfg.SRERoleARN != "arn:aws:iam::123:role/sre-shared" {
		t.Errorf("expected sre_role_arn, got %q", cfg.SRERoleARN)
	}
	if cfg.EFSFilesystemID != "fs-abc123" {
		t.Errorf("expected efs_filesystem_id 'fs-abc123', got %q", cfg.EFSFilesystemID)
	}
	if cfg.ECSClusterName != "rosa-boundary-dev" {
		t.Errorf("expected ecs_cluster_name 'rosa-boundary-dev', got %q", cfg.ECSClusterName)
	}
	if cfg.AWSRegion != "us-east-2" {
		t.Errorf("expected aws_region 'us-east-2', got %q", cfg.AWSRegion)
	}
	if cfg.KeycloakURL != "https://auth.redhat.com/auth" {
		t.Errorf("expected keycloak_url, got %q", cfg.KeycloakURL)
	}
	if cfg.KeycloakRealm != "EmployeeIDP" {
		t.Errorf("expected keycloak_realm 'EmployeeIDP', got %q", cfg.KeycloakRealm)
	}
	if cfg.OIDCClientID != "rosa-boundary-sre" {
		t.Errorf("expected oidc_client_id 'rosa-boundary-sre', got %q", cfg.OIDCClientID)
	}
}

func TestGetConfig_ErrorResponse(t *testing.T) {
	errBody := map[string]interface{}{
		"error": "Internal server error",
	}

	mock := &mockLambdaInvoker{payload: buildLambdaResponse(http.StatusInternalServerError, errBody)}
	client := newTestClient(mock)

	cfg, err := client.GetConfig(context.Background())
	if err == nil {
		t.Fatal("expected error from GetConfig, got nil")
	}
	if cfg != nil {
		t.Errorf("expected nil config on error, got %+v", cfg)
	}
	if !strings.Contains(err.Error(), "Internal server error") {
		t.Errorf("expected error to contain 'Internal server error', got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to contain status code '500', got %q", err.Error())
	}
}

func TestGetConfig_MalformedResponse(t *testing.T) {
	// Malformed body that can't be parsed as getConfigBody
	mock := &mockLambdaInvoker{payload: buildLambdaResponse(http.StatusOK, "not a valid json object")}
	client := newTestClient(mock)

	cfg, err := client.GetConfig(context.Background())
	if err == nil {
		t.Fatal("expected error from GetConfig with malformed response, got nil")
	}
	if cfg != nil {
		t.Errorf("expected nil config on malformed response, got %+v", cfg)
	}
	if !strings.Contains(err.Error(), "cannot decode get_config response body") {
		t.Errorf("expected decode error message, got %q", err.Error())
	}
}

func TestGetConfig_InvocationError(t *testing.T) {
	mock := &mockLambdaInvoker{err: fmt.Errorf("connection refused")}
	client := newTestClient(mock)

	cfg, err := client.GetConfig(context.Background())
	if err == nil {
		t.Fatal("expected error from GetConfig when invocation fails, got nil")
	}
	if cfg != nil {
		t.Errorf("expected nil config on invocation error, got %+v", cfg)
	}
	if !strings.Contains(err.Error(), "lambda invocation failed") {
		t.Errorf("expected 'lambda invocation failed' error, got %q", err.Error())
	}
}

func TestGetConfig_FunctionError(t *testing.T) {
	funcErr := "Unhandled"
	mock := &mockLambdaInvoker{
		payload:       []byte(`{"errorMessage":"runtime error"}`),
		functionError: &funcErr,
	}
	client := newTestClient(mock)

	cfg, err := client.GetConfig(context.Background())
	if err == nil {
		t.Fatal("expected error from GetConfig on function error, got nil")
	}
	if cfg != nil {
		t.Errorf("expected nil config on function error, got %+v", cfg)
	}
	if !strings.Contains(err.Error(), "lambda function error") {
		t.Errorf("expected 'lambda function error' message, got %q", err.Error())
	}
}

func TestConfigRequestJSON(t *testing.T) {
	req := ConfigRequest{Action: "get_config"}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal ConfigRequest: %v", err)
	}

	expected := `{"action":"get_config"}`
	if string(data) != expected {
		t.Errorf("expected %s, got %s", expected, string(data))
	}
}

func TestGetConfigEventPayload(t *testing.T) {
	// Verify the event payload structure matches what the Lambda handler expects
	configReq := ConfigRequest{Action: "get_config"}
	bodyBytes, _ := json.Marshal(configReq)

	event := lambdaEventPayload{
		Headers: map[string]string{},
		Body:    string(bodyBytes),
	}

	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}

	// Verify the payload can be decoded and has expected structure
	var decoded map[string]interface{}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}

	headers, ok := decoded["headers"].(map[string]interface{})
	if !ok {
		t.Fatal("headers should be a map")
	}
	if len(headers) != 0 {
		t.Error("headers should be empty for get_config (no OIDC token)")
	}

	bodyStr, ok := decoded["body"].(string)
	if !ok {
		t.Fatal("body should be a string")
	}

	var parsedBody map[string]interface{}
	if err := json.Unmarshal([]byte(bodyStr), &parsedBody); err != nil {
		t.Fatalf("failed to parse body: %v", err)
	}
	if parsedBody["action"] != "get_config" {
		t.Errorf("expected action 'get_config', got %v", parsedBody["action"])
	}
}

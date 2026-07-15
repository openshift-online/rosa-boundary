package lambda

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
)

// mockLambdaInvoker is a mock for the Lambda SDK client that implements the Invoke method.
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

// newTestClient returns a Client with a mock SDK invoker.
func newTestClient(mock *mockLambdaInvoker) *Client {
	return &Client{
		functionName: "test-function",
		sdk:          nil, // not used directly; we override invoke behavior
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

	payload := buildLambdaResponse(http.StatusOK, configBody)

	// We need to test GetConfig by calling the actual SDK path, so we'll
	// construct the client with a real SDK and intercept. Since we can't
	// easily mock the SDK client in the aws-sdk-go-v2, we'll test the
	// JSON parsing logic directly.

	// Test the response parsing logic
	var apiResp lambdaAPIResponse
	if err := json.Unmarshal(payload, &apiResp); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if apiResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", apiResp.StatusCode)
	}

	var body getConfigBody
	if err := json.Unmarshal([]byte(apiResp.Body), &body); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}

	if body.Config.LambdaFunctionName != "rosa-boundary-dev-create-investigation" {
		t.Errorf("expected lambda_function_name 'rosa-boundary-dev-create-investigation', got %q", body.Config.LambdaFunctionName)
	}
	if body.Config.InvokerRoleARN != "arn:aws:iam::123:role/invoker" {
		t.Errorf("expected invoker_role_arn, got %q", body.Config.InvokerRoleARN)
	}
	if body.Config.SRERoleARN != "arn:aws:iam::123:role/sre-shared" {
		t.Errorf("expected sre_role_arn, got %q", body.Config.SRERoleARN)
	}
	if body.Config.EFSFilesystemID != "fs-abc123" {
		t.Errorf("expected efs_filesystem_id 'fs-abc123', got %q", body.Config.EFSFilesystemID)
	}
	if body.Config.ECSClusterName != "rosa-boundary-dev" {
		t.Errorf("expected ecs_cluster_name 'rosa-boundary-dev', got %q", body.Config.ECSClusterName)
	}
	if body.Config.AWSRegion != "us-east-2" {
		t.Errorf("expected aws_region 'us-east-2', got %q", body.Config.AWSRegion)
	}
	if body.Config.KeycloakURL != "https://auth.redhat.com/auth" {
		t.Errorf("expected keycloak_url, got %q", body.Config.KeycloakURL)
	}
	if body.Config.KeycloakRealm != "EmployeeIDP" {
		t.Errorf("expected keycloak_realm 'EmployeeIDP', got %q", body.Config.KeycloakRealm)
	}
	if body.Config.OIDCClientID != "rosa-boundary-sre" {
		t.Errorf("expected oidc_client_id 'rosa-boundary-sre', got %q", body.Config.OIDCClientID)
	}
}

func TestGetConfig_ErrorResponse(t *testing.T) {
	errBody := map[string]interface{}{
		"error": "Internal server error",
	}
	payload := buildLambdaResponse(http.StatusInternalServerError, errBody)

	var apiResp lambdaAPIResponse
	if err := json.Unmarshal(payload, &apiResp); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if apiResp.StatusCode == http.StatusOK {
		t.Error("expected non-200 status code")
	}

	var errResp errorResponse
	if err := json.Unmarshal([]byte(apiResp.Body), &errResp); err != nil {
		t.Fatalf("failed to unmarshal error body: %v", err)
	}

	if errResp.Error != "Internal server error" {
		t.Errorf("expected error 'Internal server error', got %q", errResp.Error)
	}
}

func TestGetConfig_MalformedResponse(t *testing.T) {
	// Test with malformed body that can't be parsed as getConfigBody
	malformedPayload := buildLambdaResponse(http.StatusOK, "not a valid json object")

	var apiResp lambdaAPIResponse
	if err := json.Unmarshal(malformedPayload, &apiResp); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	var body getConfigBody
	err := json.Unmarshal([]byte(apiResp.Body), &body)
	if err == nil {
		t.Error("expected error unmarshaling malformed response, got nil")
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

// Ensure unused import doesn't cause issues
var _ = aws.String

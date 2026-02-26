package lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
)

// InvestigationRequest is the payload sent to the create-investigation Lambda.
type InvestigationRequest struct {
	ClusterID       string `json:"cluster_id"`
	InvestigationID string `json:"investigation_id"`
	OCVersion       string `json:"oc_version"`
	TaskTimeout     int    `json:"task_timeout"`
	SkipTask        bool   `json:"skip_task,omitempty"`
}

// InvestigationResponse is the JSON response from a successful Lambda invocation.
type InvestigationResponse struct {
	Message           string `json:"message"`
	RoleARN           string `json:"role_arn"`
	TaskARN           string `json:"task_arn"`
	AccessPointID     string `json:"access_point_id"`
	InvestigationID   string `json:"investigation_id"`
	ClusterID         string `json:"cluster_id"`
	Owner             string `json:"owner"`
	OCVersion         string `json:"oc_version"`
	TaskTimeout       int    `json:"task_timeout"`
	TaskDefinitionArn string `json:"task_definition_arn,omitempty"`
}

// errorResponse is returned by the Lambda on error.
type errorResponse struct {
	Error string `json:"error"`
}

// lambdaEventPayload mimics the API Gateway / function URL event format that the
// Lambda handler expects, so the same handler works for both function URL and direct
// SDK invocation.
type lambdaEventPayload struct {
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// lambdaAPIResponse is the object returned by the Lambda handler (statusCode + body).
type lambdaAPIResponse struct {
	StatusCode int    `json:"statusCode"`
	Body       string `json:"body"`
}

// truncate returns s truncated to n bytes with "..." appended if longer.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Client invokes the create-investigation Lambda function directly via the SDK.
type Client struct {
	functionName string
	sdk          *awslambda.Client
}

// New returns a Lambda Client that invokes the function directly (bypasses function URL).
// Using sdk invocation avoids SCP restrictions that target lambda:InvokeFunctionUrl.
func New(functionName, region string, credentials aws.CredentialsProvider) *Client {
	sdk := awslambda.New(awslambda.Options{
		Region:      region,
		Credentials: credentials,
	})
	return &Client{functionName: functionName, sdk: sdk}
}

// invoke sends the request to the Lambda function and returns the parsed response.
func (c *Client) invoke(ctx context.Context, idToken string, req InvestigationRequest) (*InvestigationResponse, error) {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal request: %w", err)
	}

	event := lambdaEventPayload{
		Headers: map[string]string{"x-oidc-token": idToken},
		Body:    string(bodyBytes),
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal Lambda event: %w", err)
	}

	out, err := c.sdk.Invoke(ctx, &awslambda.InvokeInput{
		FunctionName: aws.String(c.functionName),
		Payload:      payload,
	})
	if err != nil {
		return nil, fmt.Errorf("lambda invocation failed: %w", err)
	}

	// Check for function-level error (unhandled exception in the Lambda runtime).
	if out.FunctionError != nil {
		return nil, fmt.Errorf("lambda function error (%s): %s", *out.FunctionError, truncate(string(out.Payload), 200))
	}

	// The handler always returns an API Gateway-style response: {statusCode, headers, body}.
	var apiResp lambdaAPIResponse
	if err := json.Unmarshal(out.Payload, &apiResp); err != nil {
		return nil, fmt.Errorf("cannot decode Lambda response: %w", err)
	}

	if apiResp.StatusCode != http.StatusOK {
		var errResp errorResponse
		if jsonErr := json.Unmarshal([]byte(apiResp.Body), &errResp); jsonErr == nil && errResp.Error != "" {
			return nil, fmt.Errorf("lambda returned %d: %s", apiResp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("lambda returned %d: %s", apiResp.StatusCode, truncate(apiResp.Body, 200))
	}

	var result InvestigationResponse
	if err := json.Unmarshal([]byte(apiResp.Body), &result); err != nil {
		return nil, fmt.Errorf("cannot decode Lambda response body: %w", err)
	}

	return &result, nil
}

// CreateInvestigation invokes the Lambda function to create an investigation task.
// The OIDC token is passed in the event headers so the handler can validate it.
func (c *Client) CreateInvestigation(ctx context.Context, idToken string, req InvestigationRequest) (*InvestigationResponse, error) {
	result, err := c.invoke(ctx, idToken, req)
	if err != nil {
		return nil, err
	}
	if result.TaskARN == "" {
		return nil, fmt.Errorf("lambda response missing task_arn")
	}
	return result, nil
}

// CreateInvestigationOnly invokes the Lambda with skip_task=true, creating only the EFS
// access point without launching an ECS task.
func (c *Client) CreateInvestigationOnly(ctx context.Context, idToken string, req InvestigationRequest) (*InvestigationResponse, error) {
	req.SkipTask = true
	result, err := c.invoke(ctx, idToken, req)
	if err != nil {
		return nil, err
	}
	if result.AccessPointID == "" {
		return nil, fmt.Errorf("lambda response missing access_point_id")
	}
	return result, nil
}

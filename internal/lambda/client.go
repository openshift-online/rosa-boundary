package lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	boundaryaws "github.com/openshift-online/rosa-boundary/internal/aws"

	"github.com/aws/aws-sdk-go-v2/aws"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
)

// ConfigRequest is the payload for the get_config action.
type ConfigRequest struct {
	Action string `json:"action"`
}

// ConfigResponse is the config returned by the Lambda's get_config action.
type ConfigResponse struct {
	LambdaFunctionName string `json:"lambda_function_name"`
	InvokerRoleARN     string `json:"invoker_role_arn"`
	SRERoleARN         string `json:"sre_role_arn"`
	EFSFilesystemID    string `json:"efs_filesystem_id"`
	ECSClusterName     string `json:"ecs_cluster_name"`
	AWSRegion          string `json:"aws_region"`
	KeycloakURL        string `json:"keycloak_url"`
	KeycloakRealm      string `json:"keycloak_realm"`
	OIDCClientID       string `json:"oidc_client_id"`
}

// getConfigBody is the intermediate struct to unwrap the config field from
// the Lambda's get_config response body.
type getConfigBody struct {
	Action string         `json:"action"`
	Config ConfigResponse `json:"config"`
}

// InvestigationRequest is the payload sent to the create-investigation Lambda.
type InvestigationRequest struct {
	ClusterID       string `json:"cluster_id"`
	InvestigationID string `json:"investigation_id"`
	TaskTimeout     int    `json:"task_timeout,omitempty"`
	// TaskTimeoutSet distinguishes an explicit zero (no expiry where permitted)
	// from an omitted timeout (use the deployment's default).
	TaskTimeoutSet bool `json:"-"`
	SkipTask       bool `json:"skip_task,omitempty"`
}

func (r InvestigationRequest) MarshalJSON() ([]byte, error) {
	type request InvestigationRequest
	if r.TaskTimeoutSet && r.TaskTimeout == 0 {
		return json.Marshal(struct {
			request
			TaskTimeout int `json:"task_timeout"`
		}{request: request(r), TaskTimeout: 0})
	}
	return json.Marshal(request(r))
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
	TaskTimeout       int    `json:"task_timeout"`
	TaskDefinitionArn string `json:"task_definition_arn,omitempty"`
}

// Close service action names, stop scopes, triggers and status values. These
// mirror the Python contract in lambda/create-investigation/close_requests.py
// and lambda/reap-investigations/boundary_close_records.py.
const (
	actionRequestClose     = "request_close"
	actionCloseStatus      = "close_status"
	actionRegisterAutoClos = "register_auto_close"
	actionCancelAutoClose  = "cancel_auto_close"

	// StopScopeNone withholds consent to stop anything: the close waits while
	// tasks are running. StopScopeSessionTask consents to stopping only the
	// named tasks. StopScopeInvestigation consents to stopping every task of
	// the investigation.
	StopScopeNone          = "none"
	StopScopeSessionTask   = "session_task"
	StopScopeInvestigation = "investigation"

	TriggerCLIClose          = "cli_close"
	TriggerSessionExitPrompt = "session_exit_prompt"
	TriggerAutoClose         = "auto_close"

	// Close status values are deliberately distinguishable: an accepted
	// request is not a completed close, and a retained workspace is not a
	// silent failure.
	CloseStatusAccepted          = "accepted"
	CloseStatusWaitingForTasks   = "waiting_for_tasks"
	CloseStatusVerifying         = "verifying"
	CloseStatusRetained          = "retained"
	CloseStatusCleanupIncomplete = "cleanup_incomplete"
	CloseStatusCompleted         = "completed"
	CloseStatusNone              = "none"
	CloseStatusUnknown           = "unknown"
)

// CloseWaitEndStatuses are the outcomes a waiting client should stop at. It is
// deliberately not the service's own terminal set: cleanup_incomplete is a
// finished pass that needs attention, so a waiter must report it rather than
// poll a status that will not change by itself.
var CloseWaitEndStatuses = []string{
	CloseStatusCompleted,
	CloseStatusRetained,
	CloseStatusCleanupIncomplete,
}

// CloseActionRequest is the payload for every close service action.
type CloseActionRequest struct {
	Action          string   `json:"action"`
	ClusterID       string   `json:"cluster_id"`
	InvestigationID string   `json:"investigation_id"`
	StopScope       string   `json:"stop_scope,omitempty"`
	StopTaskIDs     []string `json:"stop_task_ids,omitempty"`
	Trigger         string   `json:"trigger,omitempty"`
	TaskID          string   `json:"task_id,omitempty"`
}

// CloseActionResponse is returned by request_close, register_auto_close and
// cancel_auto_close.
type CloseActionResponse struct {
	Action        string `json:"action"`
	RequestToken  string `json:"request_token"`
	Duplicate     bool   `json:"duplicate"`
	Status        string `json:"status"`
	State         string `json:"state"`
	AccessPointID string `json:"access_point_id"`
	StopScope     string `json:"stop_scope"`
	TaskID        string `json:"task_id"`
	Registered    bool   `json:"registered"`
	Cancelled     bool   `json:"cancelled"`
	Message       string `json:"message"`
}

// CloseStatusResponse reports finalization progress. It stays answerable after
// the access point is deleted because it is keyed by cluster and investigation
// rather than by access point.
type CloseStatusResponse struct {
	Action             string `json:"action"`
	ClusterID          string `json:"cluster_id"`
	InvestigationID    string `json:"investigation_id"`
	Status             string `json:"status"`
	Phase              string `json:"phase"`
	Reason             string `json:"reason"`
	RequestToken       string `json:"request_token"`
	AttemptID          string `json:"attempt_id"`
	DirectoryRetained  bool   `json:"directory_retained"`
	AccessPointDeleted bool   `json:"access_point_deleted"`
	AccessPointPath    string `json:"access_point_path"`
	// Retryable says whether the scheduled reaper will pick this up again by
	// itself. A client must not promise a retry the service will not make.
	Retryable          bool   `json:"retryable"`
	AccessPointPresent bool   `json:"access_point_present"`
	JoinAccessPointID  string `json:"join_access_point_id"`
	OpenRequests       int    `json:"open_requests"`
	Seal               string `json:"seal"`
	UpdatedAt          string `json:"updated_at"`
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

// lambdaInvoker is the subset of the Lambda SDK client used by Client, enabling
// test mocks without depending on the concrete *awslambda.Client type.
type lambdaInvoker interface {
	Invoke(ctx context.Context, input *awslambda.InvokeInput, opts ...func(*awslambda.Options)) (*awslambda.InvokeOutput, error)
}

// Client invokes the create-investigation Lambda function directly via the SDK.
type Client struct {
	functionName string
	sdk          lambdaInvoker
}

// New returns a Lambda Client that invokes the function directly (bypasses function URL).
// Using sdk invocation avoids SCP restrictions that target lambda:InvokeFunctionUrl.
func New(functionName, region string, credentials aws.CredentialsProvider) *Client {
	sdk := awslambda.New(awslambda.Options{
		BaseEndpoint: boundaryaws.IntegrationEndpoint(),
		Region:       region,
		Credentials:  credentials,
	})
	return &Client{functionName: functionName, sdk: sdk}
}

// invokeRaw handles event marshaling, Lambda invocation, FunctionError handling,
// response decoding, and status/error handling common to all Lambda calls. It
// returns the raw response body string on success.
func (c *Client) invokeRaw(ctx context.Context, headers map[string]string, body []byte) (string, error) {
	event := lambdaEventPayload{
		Headers: headers,
		Body:    string(body),
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("cannot marshal Lambda event: %w", err)
	}

	out, err := c.sdk.Invoke(ctx, &awslambda.InvokeInput{
		FunctionName: aws.String(c.functionName),
		Payload:      payload,
	})
	if err != nil {
		return "", fmt.Errorf("lambda invocation failed: %w", err)
	}

	// Check for function-level error (unhandled exception in the Lambda runtime).
	if out.FunctionError != nil {
		return "", fmt.Errorf("lambda function error (%s): %s", *out.FunctionError, truncate(string(out.Payload), 200))
	}

	// The handler always returns an API Gateway-style response: {statusCode, headers, body}.
	var apiResp lambdaAPIResponse
	if err := json.Unmarshal(out.Payload, &apiResp); err != nil {
		return "", fmt.Errorf("cannot decode Lambda response: %w", err)
	}

	if apiResp.StatusCode != http.StatusOK {
		var errResp errorResponse
		if jsonErr := json.Unmarshal([]byte(apiResp.Body), &errResp); jsonErr == nil && errResp.Error != "" {
			return "", fmt.Errorf("lambda returned %d: %s", apiResp.StatusCode, errResp.Error)
		}
		return "", fmt.Errorf("lambda returned %d: %s", apiResp.StatusCode, truncate(apiResp.Body, 200))
	}

	return apiResp.Body, nil
}

// invoke sends the request to the Lambda function and returns the parsed response.
func (c *Client) invoke(ctx context.Context, idToken string, req InvestigationRequest) (*InvestigationResponse, error) {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal request: %w", err)
	}

	respBody, err := c.invokeRaw(ctx, map[string]string{"x-oidc-token": idToken}, bodyBytes)
	if err != nil {
		return nil, err
	}

	var result InvestigationResponse
	if err := json.Unmarshal([]byte(respBody), &result); err != nil {
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

// invokeClose sends one close action and decodes its response. The OIDC token
// travels in the event headers exactly as it does for investigation creation;
// the service derives the requester's identity from the validated claims and
// never from the body.
func (c *Client) invokeClose(ctx context.Context, idToken, action string, req CloseActionRequest, out any) error {
	req.Action = action
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("cannot marshal %s request: %w", action, err)
	}
	respBody, err := c.invokeRaw(ctx, map[string]string{"x-oidc-token": idToken}, bodyBytes)
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(respBody), out); err != nil {
		return fmt.Errorf("cannot decode %s response body: %w", action, err)
	}
	return nil
}

// RequestClose records an authenticated close request. A successful call means
// the request is persisted, not that the investigation is closed: the
// scheduled reaper revalidates authorization and performs finalization.
func (c *Client) RequestClose(ctx context.Context, idToken string, req CloseActionRequest) (*CloseActionResponse, error) {
	var result CloseActionResponse
	if err := c.invokeClose(ctx, idToken, actionRequestClose, req, &result); err != nil {
		return nil, err
	}
	if result.RequestToken == "" {
		return nil, fmt.Errorf("close service accepted the request without returning its identity; look up the status before retrying")
	}
	return &result, nil
}

// RegisterAutoClose persists auto-close intent for one session's task before
// the CLI attaches, so a lost CLI still leaves the intent recorded.
func (c *Client) RegisterAutoClose(ctx context.Context, idToken string, req CloseActionRequest) (*CloseActionResponse, error) {
	var result CloseActionResponse
	if err := c.invokeClose(ctx, idToken, actionRegisterAutoClos, req, &result); err != nil {
		return nil, err
	}
	if !result.Registered {
		return nil, fmt.Errorf("close service did not confirm the auto-close intent")
	}
	return &result, nil
}

// CancelAutoClose withdraws a previously recorded auto-close intent.
func (c *Client) CancelAutoClose(ctx context.Context, idToken string, req CloseActionRequest) (*CloseActionResponse, error) {
	var result CloseActionResponse
	if err := c.invokeClose(ctx, idToken, actionCancelAutoClose, req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CloseStatus reports the current finalization status of an investigation.
func (c *Client) CloseStatus(ctx context.Context, idToken string, req CloseActionRequest) (*CloseStatusResponse, error) {
	var result CloseStatusResponse
	if err := c.invokeClose(ctx, idToken, actionCloseStatus, req, &result); err != nil {
		return nil, err
	}
	if result.Status == "" {
		return nil, fmt.Errorf("close service returned no status")
	}
	return &result, nil
}

// GetConfig invokes the Lambda with the get_config action to retrieve CLI
// configuration values. Unlike other methods, this does not send an OIDC
// token in the payload. AWS authorizes the SDK invocation; config init uses
// credentials obtained by exchanging its OIDC token for an invoker role session.
func (c *Client) GetConfig(ctx context.Context) (*ConfigResponse, error) {
	configReq := ConfigRequest{Action: "get_config"}
	bodyBytes, err := json.Marshal(configReq)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal config request: %w", err)
	}

	respBody, err := c.invokeRaw(ctx, map[string]string{}, bodyBytes)
	if err != nil {
		return nil, err
	}

	var body getConfigBody
	if err := json.Unmarshal([]byte(respBody), &body); err != nil {
		return nil, fmt.Errorf("cannot decode get_config response body: %w", err)
	}

	return &body.Config, nil
}

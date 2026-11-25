//go:build localstack

package aws_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	"github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/lambda"
)

// Exercise the public constructors, not just endpoint parsing.
// Each stub speaks the SDK operation's protocol so success also proves that the
// request reached the loopback server and its response was consumed.
func TestIntegrationEndpointRequestDestinations(t *testing.T) {
	const (
		region       = "us-east-1"
		cluster      = "test-cluster"
		filesystemID = "fs-0123456789abcdef0"
	)
	creds := &aws.TemporaryCredentials{
		Expiry:      time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		AccessKeyID: "test-access-key", SecretAccessKey: "test-secret-key", SessionToken: "test-session-token",
	}
	provider := aws.StaticCredentialsProvider(creds)

	for _, tc := range []struct {
		name        string
		method      string
		path        string
		contentType string
		response    string
		check       func(*testing.T, *http.Request)
		call        func(context.Context) error
	}{
		{
			name: "ECS", method: http.MethodPost, path: "/",
			contentType: "application/x-amz-json-1.1", response: `{"taskArns":[]}`,
			check: func(t *testing.T, r *http.Request) {
				if got := r.Header.Get("X-Amz-Target"); got != "AmazonEC2ContainerServiceV20141113.ListTasks" {
					t.Errorf("unexpected ECS target %q", got)
				}
				var input struct {
					Cluster       string `json:"cluster"`
					DesiredStatus string `json:"desiredStatus"`
				}
				if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
					t.Errorf("decode ECS request: %v", err)
				} else if input.Cluster != cluster || input.DesiredStatus != "RUNNING" {
					t.Errorf("unexpected ECS input: %+v", input)
				}
			},
			call: func(ctx context.Context) error {
				_, err := aws.NewECSClient(region, cluster, provider).ListRunningTasks(ctx, "RUNNING")
				return err
			},
		},
		{
			name: "EFS", method: http.MethodGet, path: "/2015-02-01/access-points",
			contentType: "application/json", response: `{"AccessPoints":[]}`,
			check: func(t *testing.T, r *http.Request) {
				if got := r.URL.Query().Get("FileSystemId"); got != filesystemID {
					t.Errorf("unexpected EFS filesystem %q", got)
				}
			},
			call: func(ctx context.Context) error {
				_, err := aws.NewEFSClient(region, filesystemID, provider).ListInvestigations(ctx, cluster)
				return err
			},
		},
		{
			name: "Lambda", method: http.MethodPost, path: "/2015-03-31/functions/test-function/invocations",
			contentType: "application/json", response: `{"statusCode":200,"body":"{\"config\":{\"ecs_cluster_name\":\"stub-cluster\"}}"}`,
			check: func(t *testing.T, r *http.Request) {
				var event struct{ Body string }
				if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
					t.Errorf("decode Lambda event: %v", err)
					return
				}
				var input lambda.ConfigRequest
				if err := json.Unmarshal([]byte(event.Body), &input); err != nil || input.Action != "get_config" {
					t.Errorf("unexpected Lambda action %q (decode error: %v)", input.Action, err)
				}
			},
			call: func(ctx context.Context) error {
				got, err := lambda.New("test-function", region, provider).GetConfig(ctx)
				if err == nil && (got == nil || got.ECSClusterName != "stub-cluster") {
					return fmt.Errorf("Lambda did not return the stub config")
				}
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != tc.method || r.URL.Path != tc.path {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				tc.check(t, r)
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = w.Write([]byte(tc.response))
			}))
			defer server.Close()
			t.Setenv("LOCALSTACK_ENDPOINT", server.URL)
			// Bound failures if a regression sends a request somewhere else.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := tc.call(ctx); err != nil {
				t.Errorf("call using %s: %v", server.URL, err)
			}
			if got := requests.Load(); got != 1 {
				t.Errorf("expected one request to %s, got %d", server.URL, got)
			}
		})
	}
}

func TestSTSWebIdentityDuration(t *testing.T) {
	const (
		roleARN     = "arn:aws:iam::123456789012:role/test-role"
		token       = "test-web-identity-token"
		sessionName = "endpoint-regression"
	)
	for _, tc := range []struct {
		name     string
		duration int32
		wantWire string
		reject   bool
	}{
		{"invoker", 900, "900", false},
		{"sre", 3600, "3600", false},
		{"sts_rejection", 3600, "3600", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/" {
					t.Errorf("unexpected STS request: %s %s", r.Method, r.URL.Path)
				}
				if err := r.ParseForm(); err != nil {
					t.Errorf("parse STS request: %v", err)
					return
				}
				for key, want := range map[string]string{
					"Action": "AssumeRoleWithWebIdentity", "Version": "2011-06-15",
					"RoleArn": roleARN, "RoleSessionName": sessionName, "WebIdentityToken": token,
					"DurationSeconds": tc.wantWire,
				} {
					if got := r.PostForm.Get(key); got != want {
						t.Errorf("unexpected STS %s: got %q, want %q", key, got, want)
					}
				}
				w.Header().Set("Content-Type", "text/xml")
				if tc.reject {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`<ErrorResponse><Error><Type>Sender</Type><Code>ValidationError</Code><Message>DurationSeconds exceeds the MaxSessionDuration</Message></Error><RequestId>test</RequestId></ErrorResponse>`))
					return
				}
				_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>test-access-key</AccessKeyId><SecretAccessKey>test-secret-key</SecretAccessKey><SessionToken>test-session-token</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`))
			}))
			defer server.Close()
			t.Setenv("LOCALSTACK_ENDPOINT", server.URL)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			got, err := aws.AssumeRoleWithWebIdentity(ctx, "us-east-1", roleARN, token, sessionName, tc.duration)
			if tc.reject {
				var apiErr smithy.APIError
				if got != nil || !errors.As(err, &apiErr) || apiErr.ErrorCode() != "ValidationError" {
					t.Fatalf("expected STS validation error with no credentials; got error %v", err)
				}
			} else {
				want := aws.TemporaryCredentials{
					AccessKeyID: "test-access-key", SecretAccessKey: "test-secret-key", SessionToken: "test-session-token",
					Expiry: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
				}
				if err != nil || got == nil || *got != want {
					t.Fatalf("STS did not return the stub credentials: %v", err)
				}
			}
			if got := requests.Load(); got != 1 {
				t.Errorf("STS requests = %d, want 1", got)
			}
		})
	}
}

func TestIntegrationEndpointLocalOnly(t *testing.T) {
	for _, endpoint := range []string{"http://localhost:4566", "http://127.0.0.1:4566", "http://[::1]:4566"} {
		t.Setenv("LOCALSTACK_ENDPOINT", endpoint)
		if got := aws.IntegrationEndpoint(); got == nil || *got != endpoint {
			t.Fatalf("expected loopback endpoint %q", endpoint)
		}
	}
}

func TestIntegrationEndpointRejectsFallbackAndRemote(t *testing.T) {
	for _, endpoint := range []string{"", "https://sts.amazonaws.com", "http://remote.invalid:4566", "http://user:password@localhost:4566", "http://localhost:4566?redirect=remote"} {
		t.Run(endpoint, func(t *testing.T) {
			t.Setenv("LOCALSTACK_ENDPOINT", endpoint)
			defer func() {
				if recover() == nil {
					t.Error("test build must reject missing or remote endpoints")
				}
			}()
			aws.IntegrationEndpoint()
		})
	}
}

//go:build localstack

package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the public constructors and STS exchange, not just endpoint parsing.
// Each stub speaks the SDK operation's protocol so success also proves that the
// request reached the loopback server and its response was consumed.
func TestIntegrationEndpointRequestDestinations(t *testing.T) {
	const (
		region       = "us-east-1"
		cluster      = "test-cluster"
		filesystemID = "fs-0123456789abcdef0"
		roleARN      = "arn:aws:iam::123456789012:role/test-role"
		token        = "test-web-identity-token"
		sessionName  = "endpoint-regression"
	)
	creds := &TemporaryCredentials{
		AccessKeyID: "test-access-key", SecretAccessKey: "test-secret-key", SessionToken: "test-session-token",
	}
	provider := StaticCredentialsProvider(creds)

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
				_, err := NewECSClient(region, cluster, provider).ListRunningTasks(ctx, "RUNNING")
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
				_, err := NewEFSClient(region, filesystemID, provider).ListInvestigations(ctx, cluster)
				return err
			},
		},
		{
			name: "STS", method: http.MethodPost, path: "/",
			contentType: "text/xml",
			response:    `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>test-access-key</AccessKeyId><SecretAccessKey>test-secret-key</SecretAccessKey><SessionToken>test-session-token</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`,
			check: func(t *testing.T, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Errorf("parse STS request: %v", err)
					return
				}
				for key, want := range map[string]string{
					"Action": "AssumeRoleWithWebIdentity", "Version": "2011-06-15",
					"RoleArn": roleARN, "RoleSessionName": sessionName, "WebIdentityToken": token,
				} {
					if got := r.PostForm.Get(key); got != want {
						t.Errorf("unexpected STS %s: got %q, want %q", key, got, want)
					}
				}
			},
			call: func(ctx context.Context) error {
				got, err := AssumeRoleWithWebIdentity(ctx, region, roleARN, token, sessionName)
				if err == nil && (got == nil || *got != *creds) {
					return fmt.Errorf("STS did not return the stub credentials")
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

func TestIntegrationEndpointLocalOnly(t *testing.T) {
	for _, endpoint := range []string{"http://localhost:4566", "http://127.0.0.1:4566", "http://[::1]:4566"} {
		t.Setenv("LOCALSTACK_ENDPOINT", endpoint)
		if got := integrationEndpoint(); got == nil || *got != endpoint {
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
			integrationEndpoint()
		})
	}
}

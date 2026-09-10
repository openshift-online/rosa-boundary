package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestAssumeRoleWithWebIdentity_400Error(t *testing.T) {
	// Start a local HTTP server that returns 400 Bad Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"Error": {"Code": "InvalidIdentityToken", "Message": "Bad Request"}}`))
	}))
	defer server.Close()

	// Override the sts client factory to point to our test server
	originalSTSClient := newSTSClient
	defer func() { newSTSClient = originalSTSClient }()
	
	newSTSClient = func(region string) *sts.Client {
		return sts.New(sts.Options{
			Region:       region,
			BaseEndpoint: aws.String(server.URL),
			Credentials:  aws.AnonymousCredentials{},
		})
	}

	_, err := AssumeRoleWithWebIdentity(context.Background(), "us-east-1", "arn:aws:iam::123:role/Fake", "token", "session")
	
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	expectedMsg := "You are not a member of the required realm roles"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Fatalf("expected error message to contain %q, but got: %v", expectedMsg, err)
	}
}

func TestAssumeRoleWithWebIdentity_Success(t *testing.T) {
	// Start a local HTTP server that returns a successful assume role response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
		<AssumeRoleWithWebIdentityResponse>
		  <AssumeRoleWithWebIdentityResult>
		    <Credentials>
		      <AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId>
		      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
		      <SessionToken>AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWj...</SessionToken>
		    </Credentials>
		  </AssumeRoleWithWebIdentityResult>
		</AssumeRoleWithWebIdentityResponse>
		`))
	}))
	defer server.Close()

	originalSTSClient := newSTSClient
	defer func() { newSTSClient = originalSTSClient }()
	
	newSTSClient = func(region string) *sts.Client {
		return sts.New(sts.Options{
			Region:       region,
			BaseEndpoint: aws.String(server.URL),
			Credentials:  aws.AnonymousCredentials{},
		})
	}

	creds, err := AssumeRoleWithWebIdentity(context.Background(), "us-east-1", "arn:aws:iam::123:role/Fake", "token", "session")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	
	if creds.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("unexpected access key id: %v", creds.AccessKeyID)
	}
}

func TestAssumeRoleWithWebIdentity_OtherError(t *testing.T) {
	// Start a local HTTP server that returns 500 Internal Server Error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`Internal Error`))
	}))
	defer server.Close()

	originalSTSClient := newSTSClient
	defer func() { newSTSClient = originalSTSClient }()
	
	newSTSClient = func(region string) *sts.Client {
		return sts.New(sts.Options{
			Region:       region,
			BaseEndpoint: aws.String(server.URL),
			Credentials:  aws.AnonymousCredentials{},
		})
	}

	_, err := AssumeRoleWithWebIdentity(context.Background(), "us-east-1", "arn:aws:iam::123:role/Fake", "token", "session")
	
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if strings.Contains(err.Error(), "You are not a member of the required realm roles") {
		t.Fatalf("did not expect realm role error message, got: %v", err)
	}

	if !strings.Contains(err.Error(), "AssumeRoleWithWebIdentity failed") {
		t.Fatalf("expected generic failure message, got: %v", err)
	}
}

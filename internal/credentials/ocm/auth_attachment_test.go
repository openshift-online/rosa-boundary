package ocm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
)

func TestAttachmentOnlineDeviceGrantRotatesAndErrorsAreSanitized(t *testing.T) {
	var refreshes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			t.Error("invalid OAuth form")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if strings.HasSuffix(req.URL.Path, "/auth/device") {
			if req.Form.Get("scope") != "openid" {
				t.Error("attachment requested a non-online scope")
			}
			writeDeviceChallenge(w, 10)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if req.Form.Get("grant_type") == "urn:ietf:params:oauth:grant-type:device_code" {
			_, _ = io.WriteString(w, `{"access_token":"initial-canary","refresh_token":"grant-0","expires_in":900}`)
			return
		}
		call := refreshes.Add(1)
		if req.Form.Get("grant_type") != "refresh_token" || req.Form.Get("client_id") != ClientID || req.Form.Get("scope") != "" || req.Form.Get("refresh_token") != fmt.Sprintf("grant-%d", call-1) {
			t.Error("unexpected refresh exchange")
		}
		if call == 1 {
			_, _ = io.WriteString(w, `{"access_token":"renewed-canary","refresh_token":"grant-1","expires_in":900}`)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"untrusted-secret-canary"}`)
	}))
	defer server.Close()
	output := &challengeOutput{}
	a := newTestDeviceAuthenticator(server, output)
	token, grant, err := a.AcquireForAttachment(context.Background(), FlowDevice)
	if err != nil || token.AccessToken != "initial-canary" || !grant.Available() || token.Expiry.IsZero() {
		t.Fatalf("initial grant not available: %v", err)
	}
	if token, err = a.Refresh(context.Background(), grant); err != nil || token.AccessToken != "renewed-canary" || token.Expiry.IsZero() {
		t.Fatalf("refresh not confirmed: %v", err)
	}
	if _, err = a.Refresh(context.Background(), grant); err == nil || strings.Contains(err.Error(), "untrusted-secret-canary") {
		t.Fatalf("unsanitized or missing refresh rejection: %v", err)
	}
	grant.Release()
	if _, err = a.Refresh(context.Background(), grant); err == nil || refreshes.Load() != 2 {
		t.Fatal("refresh retried or reused a released grant")
	}
	for _, canary := range []string{"initial-canary", "renewed-canary", "grant-0", "grant-1"} {
		if strings.Contains(output.text(), canary) {
			t.Fatal("local status leaked OAuth material")
		}
	}
}

func TestAttachmentGrantIsOptional(t *testing.T) {
	grant := &AttachmentGrant{}
	access, err := attachmentToken(&oauth2.Token{AccessToken: "canary"}, grant)
	if err != nil || access.AccessToken != "canary" || grant.Available() || !access.Expiry.IsZero() {
		t.Fatal("must preserve an access-only result without inventing expiry or a refresh grant")
	}
}

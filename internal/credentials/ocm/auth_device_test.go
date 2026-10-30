package ocm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/authstatus"
)

type redirectOCMTransport struct{ server *httptest.Server }

func (transport redirectOCMTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.URL.Scheme = "http"
	copy.URL.Host = strings.TrimPrefix(transport.server.URL, "http://")
	return http.DefaultTransport.RoundTrip(copy)
}

type authEventOutput struct {
	mu    sync.Mutex
	lines []string
}

func (output *authEventOutput) Write(data []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	output.lines = append(output.lines, string(data))
	return len(data), nil
}

func (output *authEventOutput) events(t *testing.T) []map[string]any {
	t.Helper()
	output.mu.Lock()
	defer output.mu.Unlock()
	var events []map[string]any
	for _, line := range output.lines {
		if !strings.HasPrefix(line, authstatus.Prefix) || !strings.HasSuffix(line, "\n") {
			t.Fatalf("malformed authentication event: %q", line)
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, authstatus.Prefix)), &event); err != nil {
			t.Fatal(err)
		}
		if event["provider"] != "ocm" || event["version"] != float64(1) {
			t.Fatalf("event missing OCM provider/version: %#v", event)
		}
		events = append(events, event)
	}
	return events
}

func newTestDeviceAuthenticator(server *httptest.Server, output io.Writer) *Authenticator {
	a := NewAuthenticator(nil)
	a.HTTPClient = &http.Client{Transport: redirectOCMTransport{server: server}}
	a.Reporter = &authstatus.Reporter{Format: "json", Writer: output}
	a.OpenBrowser = func(string) error { panic("device mode launched browser") }
	a.Listen = func(string, string) (net.Listener, error) { panic("device mode started callback listener") }
	return a
}

func writeDeviceChallenge(w http.ResponseWriter, expiry int) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"device_code": "device-secret-canary", "user_code": "CODE-1234",
		"verification_uri": "https://sso.test/device", "verification_uri_complete": "https://sso.test/device?user_code=CODE-1234",
		"interval": 1, "expires_in": expiry,
	})
}

func TestAcquireDeviceEmitsChallengeBeforePollingAndNeverStartsBrowser(t *testing.T) {
	output := &authEventOutput{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/auth/realms/redhat-external/protocol/openid-connect/auth/device":
			body, _ := io.ReadAll(request.Body)
			values, _ := url.ParseQuery(string(body))
			if values.Get("client_id") != ClientID || values.Get("scope") != "openid" || values.Get("code_challenge_method") != "S256" {
				t.Errorf("OCM device authorization omitted public client / PKCE")
			}
			writeDeviceChallenge(w, 10)
		case "/auth/realms/redhat-external/protocol/openid-connect/token":
			if events := output.events(t); len(events) != 1 || events[0]["event"] != "device_authorization" || events[0]["user_code"] != "CODE-1234" || events[0]["verification_uri"] != "https://sso.test/device?user_code=CODE-1234" || events[0]["expires_in"].(float64) <= 0 {
				t.Errorf("challenge not emitted before poll: %#v", events)
			}
			body, _ := io.ReadAll(request.Body)
			values, _ := url.ParseQuery(string(body))
			if values.Get("device_code") != "device-secret-canary" || values.Get("code_verifier") == "" {
				t.Errorf("device exchange omitted code / PKCE")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"access-secret-canary","refresh_token":"refresh-secret-canary","token_type":"Bearer","expires_in":900}`)
		default:
			t.Errorf("unexpected OAuth endpoint: %s", request.URL.Path)
		}
	}))
	defer server.Close()
	a := newTestDeviceAuthenticator(server, output)
	var text strings.Builder
	a.Status = func(format string, args ...any) { _, _ = fmt.Fprintf(&text, format, args...) }
	token, err := a.Acquire(context.Background(), FlowDevice)
	if err != nil || token.AccessToken != "access-secret-canary" {
		t.Fatalf("device acquisition failed: %v", err)
	}
	events := output.events(t)
	if len(events) != 2 || events[1]["event"] != "authenticated" || events[1]["source"] != "device" {
		t.Fatalf("unexpected terminal event: %#v", events)
	}
	if text.Len() != 0 {
		t.Fatalf("JSON mode emitted duplicate human challenge: %q", text.String())
	}
	for _, secret := range []string{"device-secret-canary", "access-secret-canary", "refresh-secret-canary"} {
		for _, line := range output.lines {
			if strings.Contains(line, secret) {
				t.Fatalf("auth status leaked %s", secret)
			}
		}
	}
}

func TestAcquireDeviceErrorsAreSanitizedAndCategorized(t *testing.T) {
	for _, tc := range []struct {
		name, oauthError, reason string
	}{
		{"denied", "access_denied", "denied"},
		{"expired", "expired_token", "expired"},
		{"invalid", "invalid_grant", "invalid_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := &authEventOutput{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if strings.HasSuffix(request.URL.Path, "/auth/device") {
					writeDeviceChallenge(w, 5)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintf(w, `{"error":%q,"error_description":"upstream-secret-canary"}`, tc.oauthError)
			}))
			defer server.Close()
			_, err := newTestDeviceAuthenticator(server, output).Acquire(context.Background(), FlowDevice)
			if err == nil || strings.Contains(err.Error(), "upstream-secret-canary") {
				t.Fatalf("unsanitized device failure: %v", err)
			}
			events := output.events(t)
			if len(events) != 2 || events[1]["event"] != "authentication_failed" || events[1]["reason"] != tc.reason {
				t.Fatalf("unexpected failure events: %#v", events)
			}
		})
	}
}

func TestAcquireDeviceCanceledWithoutPolling(t *testing.T) {
	output := &authEventOutput{}
	ctx, cancel := context.WithCancel(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/auth/device") {
			writeDeviceChallenge(w, 20)
			cancel()
			return
		}
		t.Error("polling should not continue after cancellation")
	}))
	defer server.Close()
	_, err := newTestDeviceAuthenticator(server, output).Acquire(ctx, FlowDevice)
	if err == nil {
		t.Fatal("canceled device acquisition succeeded")
	}
	events := output.events(t)
	if len(events) < 1 || len(events) > 2 || events[len(events)-1]["reason"] != "canceled" {
		t.Fatalf("unexpected cancellation events: %#v", events)
	}
}

type failingAuthWriter struct{}

func (failingAuthWriter) Write([]byte) (int, error) { return 0, errors.New("event writer unavailable") }

func TestAcquireDeviceStopsBeforePollingWhenEventWriteFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !strings.HasSuffix(request.URL.Path, "/auth/device") {
			t.Error("polled despite failed challenge event")
		}
		writeDeviceChallenge(w, 30)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := newTestDeviceAuthenticator(server, failingAuthWriter{}).Acquire(ctx, FlowDevice)
	if err == nil || !strings.Contains(err.Error(), "authentication status") {
		t.Fatalf("event write failure = %v", err)
	}
}

func TestAcquireDeviceTextModeIncludesCodeWithCompleteURL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		writeDeviceChallenge(w, 30)
	}))
	defer server.Close()
	var text strings.Builder
	a := newTestDeviceAuthenticator(server, nil)
	a.Reporter.Format = "text"
	a.Status = func(format string, args ...any) { _, _ = fmt.Fprintf(&text, format+"\n", args...); cancel() }
	_, _ = a.Acquire(ctx, FlowDevice)
	if !strings.Contains(text.String(), "CODE-1234") || !strings.Contains(text.String(), "Waiting") {
		t.Fatalf("device text omitted code or waiting status: %q", text.String())
	}
}

func TestAcquireDeviceRejectsMalformedAndSecretBearingChallenges(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response string
	}{
		{"missing code", `{"device_code":"device-secret-canary","expires_in":30}`},
		{"missing expiry", `{"device_code":"device-secret-canary","user_code":"CODE-1234"}`},
		{"secret in URL", `{"device_code":"device-secret-canary","user_code":"CODE-1234","verification_uri_complete":"https://sso.test/device?device_code=device-secret-canary","expires_in":30}`},
		{"invalid scheme", `{"device_code":"device-secret-canary","user_code":"CODE-1234","verification_uri_complete":"javascript://sso.test/device","expires_in":30}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := &authEventOutput{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if !strings.HasSuffix(request.URL.Path, "/auth/device") {
					t.Error("polled malformed challenge")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.response)
			}))
			defer server.Close()
			_, err := newTestDeviceAuthenticator(server, output).Acquire(context.Background(), FlowDevice)
			if err == nil || strings.Contains(err.Error(), "device-secret-canary") {
				t.Fatalf("malformed challenge was accepted or leaked: %v", err)
			}
			events := output.events(t)
			if len(events) != 1 || events[0]["event"] != "authentication_failed" || events[0]["reason"] != "invalid_response" {
				t.Fatalf("unexpected malformed-challenge status: %#v", events)
			}
		})
	}
}

type failingOCMTransport struct{}

func (failingOCMTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport-internal-secret-canary")
}

func TestAcquireDeviceNetworkFailureDoesNotExposeTransportError(t *testing.T) {
	output := &authEventOutput{}
	a := NewAuthenticator(nil)
	a.HTTPClient = &http.Client{Transport: failingOCMTransport{}}
	a.Reporter = &authstatus.Reporter{Format: "json", Writer: output}
	_, err := a.Acquire(context.Background(), FlowDevice)
	if err == nil || strings.Contains(err.Error(), "transport-internal-secret-canary") {
		t.Fatalf("network failure leaked transport message: %v", err)
	}
	events := output.events(t)
	if len(events) != 1 || events[0]["reason"] != "network" {
		t.Fatalf("unexpected network status: %#v", events)
	}
}

func TestAcquireAuthCodeReportsBrowserSuccess(t *testing.T) {
	output := &authEventOutput{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !strings.HasSuffix(request.URL.Path, "/token") {
			t.Errorf("unexpected OCM endpoint %s", request.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"access-secret-canary","token_type":"Bearer","expires_in":900}`)
	}))
	defer server.Close()
	a := newTestDeviceAuthenticator(server, output)
	var listener net.Listener
	a.Listen = func(network, address string) (net.Listener, error) {
		var err error
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		return listener, err
	}
	a.OpenBrowser = func(authorizationURL string) error {
		parsed, err := url.Parse(authorizationURL)
		if err != nil {
			return err
		}
		if parsed.Query().Get("code_challenge_method") != "S256" {
			t.Error("browser flow omitted PKCE")
		}
		callback := "http://" + listener.Addr().String() + "/oauth/callback?state=" + url.QueryEscape(parsed.Query().Get("state")) + "&code=callback-code"
		go func() {
			response, requestErr := http.Get(callback) //nolint:gosec // localhost test callback
			if requestErr == nil {
				_ = response.Body.Close()
			}
		}()
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	token, err := a.Acquire(ctx, FlowAuthCode)
	if err != nil || token.AccessToken != "access-secret-canary" {
		t.Fatalf("browser auth failed: %v", err)
	}
	events := output.events(t)
	if len(events) != 1 || events[0]["event"] != "authenticated" || events[0]["source"] != "browser" {
		t.Fatalf("browser success event = %#v", events)
	}
}

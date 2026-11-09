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
)

type redirectOCMTransport struct{ server *httptest.Server }

func (transport redirectOCMTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.URL.Scheme = "http"
	copy.URL.Host = strings.TrimPrefix(transport.server.URL, "http://")
	return http.DefaultTransport.RoundTrip(copy)
}

type challengeOutput struct {
	mu    sync.Mutex
	lines []string
}

func (output *challengeOutput) status(format string, args ...any) {
	output.mu.Lock()
	defer output.mu.Unlock()
	output.lines = append(output.lines, fmt.Sprintf(format, args...))
}

func (output *challengeOutput) text() string {
	output.mu.Lock()
	defer output.mu.Unlock()
	return strings.Join(output.lines, "\n")
}

func newTestDeviceAuthenticator(server *httptest.Server, output *challengeOutput) *Authenticator {
	a := NewAuthenticator(nil)
	a.HTTPClient = &http.Client{Transport: redirectOCMTransport{server: server}}
	a.Status = output.status
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

func TestAcquireDeviceShowsChallengeBeforePollingAndNeverStartsBrowser(t *testing.T) {
	output := &challengeOutput{}
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
			if text := output.text(); !strings.Contains(text, "CODE-1234") || !strings.Contains(text, "https://sso.test/device?user_code=CODE-1234") || !strings.Contains(text, "Waiting") {
				t.Errorf("challenge not shown before poll: %q", text)
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
	token, err := a.Acquire(context.Background(), FlowDevice)
	if err != nil || token.AccessToken != "access-secret-canary" {
		t.Fatalf("device acquisition failed: %v", err)
	}
	if text := output.text(); !strings.Contains(text, "Enter code: CODE-1234") || strings.Contains(text, "ROSA_BOUNDARY_AUTH_EVENT") {
		t.Fatalf("missing human challenge or unexpected protocol: %q", text)
	}
	for _, secret := range []string{"device-secret-canary", "access-secret-canary", "refresh-secret-canary"} {
		if strings.Contains(output.text(), secret) {
			t.Fatalf("auth status leaked %s", secret)
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
			output := &challengeOutput{}
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
			var failure authFailure
			if !errors.As(err, &failure) || failure.Reason() != tc.reason || !strings.Contains(output.text(), "CODE-1234") || strings.Contains(output.text(), "upstream-secret-canary") {
				t.Fatalf("unexpected failure or challenge: %v, %q", err, output.text())
			}
		})
	}
}

func TestAcquireDeviceCanceledWithoutPolling(t *testing.T) {
	output := &challengeOutput{}
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
	var failure authFailure
	if !errors.As(err, &failure) || failure.Reason() != "canceled" {
		t.Fatalf("unexpected cancellation: %v", err)
	}
}

func TestAcquireDeviceChallengePrecedesPollEvenWhenCanceled(t *testing.T) {
	output := &challengeOutput{}
	ctx, cancel := context.WithCancel(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !strings.HasSuffix(request.URL.Path, "/auth/device") {
			t.Error("polled despite canceled challenge")
		}
		writeDeviceChallenge(w, 30)
		cancel()
	}))
	defer server.Close()
	defer cancel()
	_, err := newTestDeviceAuthenticator(server, output).Acquire(ctx, FlowDevice)
	if err == nil || (!strings.Contains(output.text(), "CODE-1234") && !errors.Is(err, context.Canceled)) {
		t.Fatalf("canceled challenge = %v, %q", err, output.text())
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
	a := newTestDeviceAuthenticator(server, &challengeOutput{})
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
			output := &challengeOutput{}
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
			if output.text() != "" {
				t.Fatalf("displayed malformed challenge: %q", output.text())
			}
		})
	}
}

type failingOCMTransport struct{}

func (failingOCMTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport-internal-secret-canary")
}

func TestAcquireDeviceNetworkFailureDoesNotExposeTransportError(t *testing.T) {
	output := &challengeOutput{}
	a := NewAuthenticator(nil)
	a.HTTPClient = &http.Client{Transport: failingOCMTransport{}}
	a.Status = output.status
	_, err := a.Acquire(context.Background(), FlowDevice)
	if err == nil || strings.Contains(err.Error(), "transport-internal-secret-canary") {
		t.Fatalf("network failure leaked transport message: %v", err)
	}
	var failure authFailure
	if !errors.As(err, &failure) || failure.Reason() != "network" || output.text() != "" {
		t.Fatalf("unexpected network status: %v, %q", err, output.text())
	}
}

func TestAcquireAuthCodeShowsBrowserGuidance(t *testing.T) {
	output := &challengeOutput{}
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
	if text := output.text(); !strings.Contains(text, "Open this URL to authorize OCM:") || !strings.Contains(text, "Waiting for OCM authorization callback") || strings.Contains(text, "access-secret-canary") {
		t.Fatalf("browser guidance = %q", text)
	}
}

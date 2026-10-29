package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/authstatus"
)

func TestDeviceAuthorizationPKCEPollingAndCache(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	token := testJWT(t, time.Now().Add(time.Hour))
	var challenge string
	var verifier string
	var waits []time.Duration
	polls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("unexpected device endpoint request")
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/auth/device"):
			if r.Form.Get("client_id") != "boundary-client" || r.Form.Get("scope") != "openid profile email" || r.Form.Get("code_challenge_method") != "S256" {
				t.Error("invalid device authorization parameters")
			}
			challenge = r.Form.Get("code_challenge")
			_, _ = io.WriteString(w, `{"device_code":"secret-device","user_code":"ABCD-EFGH","verification_uri":"https://verify.example/device","expires_in":600,"interval":5}`)
		case strings.HasSuffix(r.URL.Path, "/token"):
			polls++
			if r.Form.Get("grant_type") != deviceGrant || r.Form.Get("device_code") != "secret-device" || r.Form.Get("client_id") != "boundary-client" {
				t.Error("invalid device token request")
			}
			verifier = r.Form.Get("code_verifier")
			if polls == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"slow_down"}`)
			} else if polls == 2 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"authorization_pending"}`)
			} else {
				_, _ = fmt.Fprintf(w, `{"id_token":%q,"access_token":"not-the-id-token"}`, token)
			}
		default:
			t.Errorf("unexpected endpoint: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	var out bytes.Buffer
	reporter := &authstatus.Reporter{Format: "json", Writer: &out}
	cfg := PKCEConfig{KeycloakURL: server.URL + "/auth", Realm: "test", ClientID: "boundary-client"}
	opts := Options{UseDeviceCode: true, Reporter: reporter, wait: func(_ context.Context, duration time.Duration) error {
		waits = append(waits, duration)
		return nil
	}}
	deps := oidcDependencies{
		browserOpener: func(string) error { t.Error("device flow opened a browser"); return nil },
		callbackServerStarter: func(context.Context, string) (string, error) {
			t.Error("device flow started a local callback listener")
			return "", nil
		},
	}
	got, err := getTokenWithOptionsAndDeps(context.Background(), cfg, false, opts, deps)
	if err != nil || got != token {
		t.Fatalf("device login failed: token match=%t, err=%v", got == token, err)
	}
	if len(waits) != 3 || waits[0] != 5*time.Second || waits[1] != 10*time.Second || waits[2] != 10*time.Second {
		t.Errorf("poll intervals = %v", waits)
	}
	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != expected || verifier == "" {
		t.Error("device PKCE challenge did not match the exchanged verifier")
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("auth events = %d, want 2", len(lines))
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, authstatus.Prefix) || strings.Contains(line, "secret-device") || strings.Contains(line, token) || strings.Contains(line, verifier) {
			t.Error("auth event malformed or includes sensitive material")
		}
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[0], authstatus.Prefix)), &event); err != nil {
		t.Fatal(err)
	}
	if event["event"] != "device_authorization" || event["provider"] != "boundary" || event["user_code"] != "ABCD-EFGH" || event["verification_uri"] != "https://verify.example/device" {
		t.Errorf("unexpected challenge event: %v", event)
	}
	if _, err := GetTokenWithOptions(context.Background(), cfg, false, opts); err != nil {
		t.Fatal(err)
	}
	if polls != 3 || len(waits) != 3 || !strings.Contains(out.String(), `"source":"cache"`) {
		t.Error("cache was not reused independently of selected flow")
	}
	if _, err := GetTokenWithOptions(context.Background(), cfg, true, opts); err != nil || polls != 4 {
		t.Errorf("forced device login: polls=%d err=%v", polls, err)
	}
}

func TestDeviceFailuresDoNotCacheOrLeak(t *testing.T) {
	for _, tc := range []struct {
		name, reply, reason string
		status              int
	}{
		{"denied", `{"error":"access_denied","error_description":"SECRET-body"}`, "denied", 400},
		{"expired", `{"error":"expired_token"}`, "expired", 400},
		{"invalid", `{"access_token":"SECRET-body"}`, "invalid_response", 200},
		{"unexpected", `{"error":"SECRET-body"}`, "invalid_response", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CACHE_HOME", t.TempDir())
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/auth/device") {
					_, _ = io.WriteString(w, `{"device_code":"SECRET-device","user_code":"CODE","verification_uri":"https://verify.example","expires_in":60,"interval":1}`)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.reply)
			}))
			defer server.Close()
			var out bytes.Buffer
			cfg := PKCEConfig{KeycloakURL: server.URL, Realm: "test", ClientID: "client"}
			_, err := GetTokenWithOptions(context.Background(), cfg, false, Options{UseDeviceCode: true, Reporter: &authstatus.Reporter{Format: "json", Writer: &out}, wait: func(context.Context, time.Duration) error { return nil }})
			if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(out.String(), "SECRET") {
				t.Errorf("error/event leaked provider data or missed failure: err=%v", err)
			}
			if !strings.Contains(out.String(), `"reason":"`+tc.reason+`"`) {
				t.Errorf("missing %s reason", tc.reason)
			}
			if cached, err := CachedTokenForConfig(cfg); err != nil || cached != "" {
				t.Errorf("failed login cached a token: err=%v", err)
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("status stream closed") }

func TestDeviceEventWriteFailureStopsBeforePolling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			t.Error("polled after event stream failure")
		}
		_, _ = io.WriteString(w, `{"device_code":"secret","user_code":"CODE","verification_uri":"https://verify.example","expires_in":60}`)
	}))
	defer server.Close()
	_, err := GetTokenWithOptions(context.Background(), PKCEConfig{KeycloakURL: server.URL, Realm: "test", ClientID: "client"}, true, Options{UseDeviceCode: true, Reporter: &authstatus.Reporter{Format: "json", Writer: failingWriter{}}})
	if err == nil || !strings.Contains(err.Error(), "status write failed") {
		t.Errorf("missing event write error: %v", err)
	}
}

func TestScopedCacheRejectsOtherClientIssuerAndLegacy(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	cfg := PKCEConfig{KeycloakURL: "https://issuer.example/auth", Realm: "employee", ClientID: "client"}
	token := testJWT(t, time.Now().Add(time.Hour))
	if err := SaveToken(token); err != nil {
		t.Fatal(err)
	}
	if got, _ := CachedTokenForConfig(cfg); got != "" {
		t.Error("accepted unscoped legacy cache")
	}
	if err := SaveTokenForConfig(token, cfg); err != nil {
		t.Fatal(err)
	}
	for _, other := range []PKCEConfig{{KeycloakURL: cfg.KeycloakURL, Realm: cfg.Realm, ClientID: "other"}, {KeycloakURL: cfg.KeycloakURL, Realm: "other", ClientID: cfg.ClientID}, {KeycloakURL: "https://other.example/auth", Realm: cfg.Realm, ClientID: cfg.ClientID}} {
		if got, _ := CachedTokenForConfig(other); got != "" {
			t.Error("reused token for another issuer/client")
		}
	}
	if got, err := CachedTokenForConfig(cfg); err != nil || got != token {
		t.Errorf("cache lookup failed: err=%v", err)
	}
	cacheDir := os.Getenv("XDG_CACHE_HOME") + "/rosa-boundary/token-cache"
	if stat, err := os.Stat(cacheDir); err != nil || stat.Mode().Perm() != 0o600 {
		t.Errorf("cache permissions: %v %v", stat, err)
	}
}

func TestDeviceCancellationAndExpiry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"device_code":"secret","user_code":"CODE","verification_uri":"https://verify.example","expires_in":60,"interval":1}`)
	}))
	defer server.Close()
	cfg := PKCEConfig{KeycloakURL: server.URL, Realm: "test", ClientID: "client"}
	for _, tc := range []struct {
		name, reason string
		wait         func(context.Context, time.Duration) error
	}{
		{"canceled", "canceled", func(context.Context, time.Duration) error { return context.Canceled }},
		{"expired", "expired", func(context.Context, time.Duration) error { return context.DeadlineExceeded }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CACHE_HOME", t.TempDir())
			var out bytes.Buffer
			_, err := GetTokenWithOptions(context.Background(), cfg, false, Options{UseDeviceCode: true, Reporter: &authstatus.Reporter{Format: "json", Writer: &out}, wait: tc.wait})
			if err == nil || !strings.Contains(out.String(), `"reason":"`+tc.reason+`"`) {
				t.Errorf("missing %s failure: %v", tc.reason, err)
			}
		})
	}
}

func TestDeviceNetworkAndMalformedChallenge(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		handler      http.HandlerFunc
	}{
		{"network", "network", func(w http.ResponseWriter, r *http.Request) {
			// Force the next token request to fail before reading any response.
			if strings.HasSuffix(r.URL.Path, "/token") {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			_, _ = io.WriteString(w, `{"device_code":"secret","user_code":"CODE","verification_uri":"https://verify.example","expires_in":60,"interval":1}`)
		}},
		{"malformed", "invalid_response", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"device_code":"secret","user_code":"CODE","verification_uri":"https://verify.example/?device_code=secret","expires_in":60}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CACHE_HOME", t.TempDir())
			server := httptest.NewServer(tc.handler)
			defer server.Close()
			var out bytes.Buffer
			_, err := GetTokenWithOptions(context.Background(), PKCEConfig{KeycloakURL: server.URL, Realm: "test", ClientID: "client"}, true, Options{UseDeviceCode: true, Reporter: &authstatus.Reporter{Format: "json", Writer: &out}, wait: func(context.Context, time.Duration) error { return nil }})
			if err == nil || !strings.Contains(out.String(), `"reason":"`+tc.reason+`"`) {
				t.Errorf("missing %s failure: %v", tc.reason, err)
			}
		})
	}
}

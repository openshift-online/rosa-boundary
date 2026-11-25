package ocm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSaveLocalConfig(t *testing.T) {
	t.Run("one shot", func(t *testing.T) { testSaveLocalConfig(t, false) })
	t.Run("renew and cancel", func(t *testing.T) { testSaveLocalConfig(t, true) })
}

func testSaveLocalConfig(t *testing.T, renew bool) {
	t.Helper()
	var exchanges atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		exchanges.Add(1)
		if err := req.ParseForm(); err != nil {
			t.Error("invalid OAuth form")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if renew && req.Form.Get("grant_type") == "refresh_token" && req.Form.Get("refresh_token") == "refresh-canary" {
			_, _ = io.WriteString(w, `{"access_token":"renewed-access","refresh_token":"rotated-refresh","expires_in":900}`)
			return
		}
		if req.Form.Get("grant_type") != "authorization_code" || req.Form.Get("code_verifier") == "" {
			t.Error("unexpected exchange")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"access-canary","refresh_token":"refresh-canary","expires_in":900}`)
	}))
	defer server.Close()
	status := &challengeOutput{}
	a := newTestDeviceAuthenticator(server, status)
	var listener net.Listener
	a.Listen = func(_, _ string) (net.Listener, error) {
		var err error
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		return listener, err
	}
	a.OpenBrowser = func(ctx context.Context, authURL string) error {
		parsed, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		callback := url.URL{Scheme: "http", Host: listener.Addr().String(), Path: "/oauth/callback", RawQuery: url.Values{
			"state": {parsed.Query().Get("state")}, "code": {"test-code"},
		}.Encode()}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, callback.String(), nil)
		if err != nil {
			return err
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		return res.Body.Close()
	}
	path := filepath.Join(t.TempDir(), "custom.json")
	if err := os.WriteFile(path, []byte(`{"url":"https://api.openshift.com"}`), 0644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	environment := Environment{URL: IntegrationURL}
	if !renew {
		if err := a.SaveLocalConfig(ctx, path, environment, FlowAuthCode); err != nil {
			t.Fatal(err)
		}
		if exchanges.Load() != 1 {
			t.Fatal("expected one authorization exchange and no renewal")
		}
		assertLocalConfig(t, path, "access-canary", "refresh-canary")
	} else {
		ctx, stop := context.WithCancel(ctx)
		defer stop()
		if err := a.saveLocalConfig(ctx, path, environment, FlowAuthCode, func(ctx context.Context, delay time.Duration) error {
			if delay < 835*time.Second || delay > 840*time.Second {
				t.Fatalf("expected renewal about one minute before expiry, got delay %v", delay)
			}
			if exchanges.Load() == 1 {
				assertLocalConfig(t, path, "access-canary", "refresh-canary")
				return nil
			}
			stop()
			return waitForLocalRefresh(ctx, delay)
		}); err != nil {
			t.Fatal(err)
		}
		if exchanges.Load() != 2 {
			t.Fatal("expected one renewal exchange before cancellation")
		}
		assertLocalConfig(t, path, "renewed-access", "rotated-refresh")
	}
	if strings.Contains(status.text(), "access-canary") || strings.Contains(status.text(), "refresh-canary") || strings.Contains(status.text(), "renewed-access") || strings.Contains(status.text(), "rotated-refresh") {
		t.Fatal("status leaked a credential")
	}
}

func assertLocalConfig(t *testing.T, path, access, refresh string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]string
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal("invalid OCM config")
	}
	if cfg["access_token"] != access || cfg["refresh_token"] != refresh || cfg["url"] != IntegrationURL || cfg["token_url"] != TokenURL || cfg["client_id"] != ClientID {
		t.Fatal("incorrect credentials or endpoint settings")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("config is not owner-only: %v", err)
	}
}

func TestLocalConfigRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "config")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeLocalConfig(link, StagingURL, "access", "refresh"); err == nil {
		t.Fatal("accepted symlink as config destination")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("writing through symlink created its target")
	}
}

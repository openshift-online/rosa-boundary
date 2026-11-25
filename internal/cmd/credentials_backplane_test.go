package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	ocm "github.com/openshift-online/rosa-boundary/internal/credentials/ocm"
)

func TestConfigureBackplaneValidatesBeforeBoundaryAuth(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "specify a session ID"},
		{[]string{"--refresh"}, "specify a session ID"},
		{[]string{"task", "--cluster-id", "cluster"}, "--cluster-id requires --local"},
		{[]string{"--local", "out"}, "--local requires --cluster-id"},
		{[]string{"task", "--local", "out"}, "--local cannot be combined"},
		{[]string{"--local", "out", "--ecs-cluster", "other"}, "--local cannot be combined"},
		{[]string{"--local", "out", "--cluster-id", "cluster", "--ocm-url", "https://example.invalid"}, "unsupported OCM environment"},
		{[]string{"--local", t.TempDir(), "--cluster-id", "cluster"}, "set --ocm-url"},
		{[]string{"--refresh", "--local", t.TempDir(), "--cluster-id", "cluster", "--ocm-url", "production"}, "must be a regular file"},
	} {
		args := append([]string{"--profile", "does-not-exist", "session", "credentials", "configure", "backplane"}, tc.args...)
		if _, err := runTestCLI(t, args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: expected %q, got %v", tc.args, tc.want, err)
		}
	}
}

func TestConfigureLocalCredentialsUseWorkstationOCMURL(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	ocmDir := filepath.Join(configHome, "ocm")
	if err := os.Mkdir(ocmDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ocmDir, "ocm.json"), []byte(`{"url":"https://api.openshift.com"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"ocm", "backplane"} {
		// A directory is rejected only after successfully resolving the OCM URL.
		args := []string{"session", "credentials", "configure", provider, "--local", t.TempDir()}
		if provider == "backplane" {
			args = append(args, "--cluster-id", "cluster")
		}
		if _, err := runTestCLI(t, args...); err == nil || !strings.Contains(err.Error(), "must be a regular file") {
			t.Errorf("%s: expected local path error after resolving OCM URL, got %v", provider, err)
		}
	}
}

func TestWriteLocalBackplaneIsolatesFilesAndPreservesLastConfigOnFailure(t *testing.T) {
	dir := t.TempDir()
	path, binary := filepath.Join(dir, "config"), filepath.Join(dir, "ocm-backplane")
	t.Setenv("OCM_CONFIG", "not-this-ocm-config")
	t.Setenv("KUBECONFIG", "not-this-kubeconfig")
	t.Setenv("OCM_URL", "https://example.invalid")
	staging, err := ocm.ResolveEnvironment("staging")
	if err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
set -eu
[ "$#" -eq 3 ]
[ "$1" = login ]
[ "$2" = -- ]
[ "$OCM_URL" = https://api.stage.openshift.com ]
[ "$KUBECONFIG" != not-this-kubeconfig ]
grep -q '"access_token":"fake-access"' "$OCM_CONFIG"
if grep -q 'refresh_token' "$OCM_CONFIG"; then exit 2; fi
printf 'new kubeconfig' > "$KUBECONFIG"
if [ "$3" != '-test-cluster' ]; then
    echo secret-canary >&2
    exit 1
fi
`
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeLocalBackplane(context.Background(), binary, path, "-test-cluster", staging, "fake-access"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("want owner-only kubeconfig, got %v, %v", info, err)
	}
	if err := writeLocalBackplane(context.Background(), binary, path, "fail", staging, "fake-access"); err == nil || strings.Contains(err.Error(), "secret-canary") {
		t.Fatalf("expected a sanitized login error, got %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "new kubeconfig" {
		t.Fatalf("last config changed: %q, %v", data, err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 2 {
		t.Fatalf("temporary files left behind: %v, %v", files, err)
	}
}

func TestRenewLocalBackplaneReinstallsThenStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Unix(1000, 0)
	installs := 0
	err := renewLocalBackplane(ctx, ocm.Token{Expiry: now.Add(time.Hour)}, func() time.Time { return now },
		func(_ context.Context, delay time.Duration) bool {
			if delay != 45*time.Minute {
				t.Fatalf("unexpected delay %s", delay)
			}
			return true
		}, func(context.Context) (ocm.Token, error) {
			return ocm.Token{AccessToken: "replacement", Expiry: now.Add(time.Hour)}, nil
		}, func(_ context.Context, token ocm.Token) error {
			installs++
			if token.AccessToken != "replacement" {
				t.Fatal("did not install the new token")
			}
			cancel()
			return nil
		})
	if err != nil || installs != 1 {
		t.Fatalf("installs=%d, err=%v", installs, err)
	}
}

func TestBackplaneRenewalRunsOnlyAfterConfirmedOCMReplacement(t *testing.T) {
	for _, failUpload := range []bool{false, true} {
		now := time.Unix(1000, 0)
		logins := 0
		r := &ocmRenewal{
			expiry: now.Add(time.Hour),
			refresh: func(context.Context, *ocm.AttachmentGrant) (ocm.Token, error) {
				return ocm.Token{Expiry: now.Add(time.Hour)}, nil
			},
			install: func(context.Context, *awsclient.TemporaryCredentials, ocm.Token, string, string) error {
				if failUpload {
					return errors.New("generation conflict")
				}
				return nil
			},
			afterInstall: func(context.Context, *awsclient.TemporaryCredentials) error {
				logins++
				return errors.New("Backplane rejected login")
			},
		}
		waits := 0
		err := r.runUntilStopped(context.Background(), func() time.Time { return now }, func(context.Context, time.Duration) bool {
			waits++
			if waits > 1 {
				t.Fatal("retried after a failed replacement or login")
			}
			return true
		})
		if failUpload && (logins != 0 || err == nil || !strings.Contains(err.Error(), "replacement was not confirmed")) {
			t.Fatalf("login must not run after an upload conflict: logins=%d err=%v", logins, err)
		}
		if !failUpload && (logins != 1 || err == nil || !strings.Contains(err.Error(), "Backplane login failed")) {
			t.Fatalf("login failure must stop renewal: logins=%d err=%v", logins, err)
		}
	}
}

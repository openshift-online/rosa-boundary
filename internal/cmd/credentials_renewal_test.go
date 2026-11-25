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
	"github.com/openshift-online/rosa-boundary/internal/output"
)

func TestRenewalDelay(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, tc := range []struct {
		expiry time.Time
		want   time.Duration
	}{
		{time.Time{}, 0}, {now.Add(-time.Second), 0}, {now.Add(time.Minute), 0},
		{now.Add(2 * time.Minute), 0}, {now.Add(3 * time.Minute), 50 * time.Second},
		{now.Add(time.Hour), 55 * time.Minute},
	} {
		if delay, ok := (&ocmRenewal{}).delay(tc.expiry, now); delay != tc.want || ok != (tc.want > 0) {
			t.Errorf("expiry %v: delay=%s, schedulable=%t", tc.expiry, delay, ok)
		}
	}
}

func TestRenewalStopsOnConflictAndUsesConfirmedGeneration(t *testing.T) {
	stderr, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	oldStderr, oldVerbose := os.Stderr, output.Verbose
	os.Stderr, output.Verbose = stderr, false
	t.Cleanup(func() {
		os.Stderr, output.Verbose = oldStderr, oldVerbose
		_ = stderr.Close()
	})
	now := time.Unix(1000, 0)
	var installed string
	refreshes, installs := 0, 0
	r := ocmRenewal{
		expiry: now.Add(time.Hour), generation: "initial",
		refresh: func(context.Context, *ocm.AttachmentGrant) (ocm.Token, error) {
			refreshes++
			return ocm.Token{AccessToken: "fake", Expiry: now.Add(40 * time.Minute)}, nil
		},
		install: func(_ context.Context, _ *awsclient.TemporaryCredentials, token ocm.Token, next, expected string) error {
			installs++
			if token.AccessToken != "fake" || next == "" || next == expected {
				t.Fatal("invalid replacement")
			}
			if installs == 1 {
				if expected != "initial" {
					t.Fatal("did not use installed initial generation")
				}
				installed = next
				return nil
			}
			if expected != installed {
				t.Fatal("did not use last confirmed generation")
			}
			return errors.New("conflict")
		},
	}
	r.run(context.Background(), func() time.Time { return now }, func(_ context.Context, d time.Duration) bool {
		if refreshes >= 2 {
			t.Fatal("retried after conflict")
		}
		want := 55 * time.Minute
		if refreshes != 0 {
			want = 35 * time.Minute
		}
		if d != want {
			t.Fatalf("wait = %s, want %s", d, want)
		}
		now = now.Add(d)
		return true
	})
	if refreshes != 2 || installs != 2 || r.generation != installed {
		t.Fatal("did not stop at the last confirmed generation")
	}
	messages, err := os.ReadFile(stderr.Name())
	if err != nil {
		t.Fatal(err)
	}
	if line := strings.TrimSuffix(string(messages), "\n"); !strings.HasPrefix(line, "Warning: OCM renewal stopped:") || strings.Contains(line, "\n") {
		t.Fatalf("expected only the failure warning on stderr, got %q", messages)
	}
}

func TestStandaloneRenewalReturnsRefreshFailure(t *testing.T) {
	now := time.Unix(1000, 0)
	r := ocmRenewal{
		expiry: now.Add(15 * time.Minute),
		refresh: func(context.Context, *ocm.AttachmentGrant) (ocm.Token, error) {
			return ocm.Token{}, errors.New("secret canary in provider error")
		},
		install: func(context.Context, *awsclient.TemporaryCredentials, ocm.Token, string, string) error {
			t.Fatal("installed after a failed refresh")
			return nil
		},
	}
	err := r.runUntilStopped(context.Background(), func() time.Time { return now }, func(context.Context, time.Duration) bool { return true })
	if err == nil || !strings.Contains(err.Error(), "online refresh failed") || strings.Contains(err.Error(), "secret canary") {
		t.Fatalf("expected a sanitized failure, got %v", err)
	}
}

func TestRenewalDoesNotInstallMissingExpiryOrOnCancellation(t *testing.T) {
	for _, cancelDuringRefresh := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		now := time.Unix(1000, 0)
		r := ocmRenewal{
			expiry: now.Add(time.Hour),
			refresh: func(context.Context, *ocm.AttachmentGrant) (ocm.Token, error) {
				if cancelDuringRefresh {
					cancel()
					return ocm.Token{Expiry: now.Add(time.Hour)}, nil
				}
				return ocm.Token{}, nil
			},
			install: func(context.Context, *awsclient.TemporaryCredentials, ocm.Token, string, string) error {
				t.Fatal("installed after cancellation or without expiry")
				return nil
			},
		}
		r.run(ctx, func() time.Time { return now }, func(context.Context, time.Duration) bool { return true })
		cancel()
	}
}

func TestAttachmentExitCancelsAndJoinsInFlightRefresh(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	r := &ocmRenewal{
		expiry: time.Now().Add(time.Hour),
		refresh: func(ctx context.Context, _ *ocm.AttachmentGrant) (ocm.Token, error) {
			close(started)
			<-ctx.Done()
			close(stopped)
			return ocm.Token{}, ctx.Err()
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pluginErr := errors.New("plugin disconnected")
	worker := func(ctx context.Context) {
		r.run(ctx, time.Now, func(context.Context, time.Duration) bool { return true })
	}
	err := withAttachmentRenewal(ctx, worker, func(ctx context.Context) error {
		select {
		case <-started:
			return pluginErr
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if err != pluginErr || ctx.Err() != nil {
		t.Fatalf("plugin error=%v; command context=%v", err, ctx.Err())
	}
	select {
	case <-stopped:
	default:
		t.Fatal("attachment returned before refresh stopped")
	}
}

func TestRenewalBudgetsBoundaryLoginBeforeRefreshingOCM(t *testing.T) {
	now := time.Unix(1000, 0)
	oldExpiry := now.Add(10 * time.Minute)
	old := &awsclient.TemporaryCredentials{Expiry: now.Add(6 * time.Minute)}
	fresh := &awsclient.TemporaryCredentials{Expiry: now.Add(time.Hour)}
	signedIn, installed := false, false
	r := &ocmRenewal{
		expiry: oldExpiry,
		authorization: &renewalAWS{creds: old, reassume: func(context.Context) (*awsclient.TemporaryCredentials, error) {
			now = now.Add(renewalLoginTimeout)
			signedIn = true
			return fresh, nil
		}},
		refresh: func(context.Context, *ocm.AttachmentGrant) (ocm.Token, error) {
			if !signedIn {
				t.Fatal("started OCM refresh before Boundary login completed")
			}
			now = now.Add(ocm.RefreshTimeout)
			return ocm.Token{Expiry: now.Add(time.Hour)}, nil
		},
		install: func(_ context.Context, creds *awsclient.TemporaryCredentials, _ ocm.Token, _, _ string) error {
			now = now.Add(renewalUploadTimeout)
			if creds != fresh || !now.Before(oldExpiry) {
				t.Fatal("replacement did not finish with fresh STS credentials before old OCM expiry")
			}
			installed = true
			return nil
		},
	}
	if delay, ok := r.delay(now.Add(7*time.Minute), now.Add(2*time.Minute)); ok || delay != 0 {
		t.Fatalf("scheduled a short-lived token: %s", delay)
	}
	r.run(context.Background(), func() time.Time { return now }, func(_ context.Context, delay time.Duration) bool {
		if installed {
			return false
		}
		if delay != 10*time.Minute-renewalLead-renewalLoginTimeout {
			t.Fatalf("renewal delay = %s", delay)
		}
		now = now.Add(delay)
		return true
	})
	if !installed {
		t.Fatal("replacement was not installed")
	}
}

func TestRenewalAWSReassumesNearExpiryAndReusesFreshCredentials(t *testing.T) {
	now := time.Unix(1000, 0)
	old := &awsclient.TemporaryCredentials{Expiry: now.Add(3 * time.Minute)}
	fresh := &awsclient.TemporaryCredentials{Expiry: now.Add(time.Hour)}
	calls := 0
	a := renewalAWS{creds: old, reassume: func(context.Context) (*awsclient.TemporaryCredentials, error) {
		calls++
		return fresh, nil
	}}
	for _, tc := range []struct {
		offset time.Duration
		want   *awsclient.TemporaryCredentials
	}{{0, old}, {time.Minute, fresh}, {30 * time.Minute, fresh}} {
		if got, err := a.credentials(context.Background(), func() time.Time { return now.Add(tc.offset) }); err != nil || got != tc.want {
			t.Fatalf("unexpected credential selection: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("role assumptions = %d", calls)
	}
}

func TestStartOCMRenewalEnabled(t *testing.T) {
	if !startOCMRenewalEnabled(true, true, false, false) {
		t.Fatal("default attached create should renew")
	}
	for _, flags := range [][4]bool{{false, true, false, false}, {true, false, false, false}, {true, true, true, false}, {true, true, false, true}} {
		if startOCMRenewalEnabled(flags[0], flags[1], flags[2], flags[3]) {
			t.Fatalf("renewal should be disabled for %v", flags)
		}
	}
}

func TestValidateJoinOCM(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags map[string]string
		valid bool
	}{
		{"plain", nil, true},
		{"opt in", map[string]string{"renew-ocm": "true", "ocm-auth-flow": "device", "ocm-url": "staging"}, true},
		{"no opt in", map[string]string{"ocm-auth-flow": "device"}, false},
		{"sidecar", map[string]string{"renew-ocm": "true", "container": "sidecar"}, false},
		{"custom command", map[string]string{"renew-ocm": "true", "command": "ls"}, false},
		{"no wait", map[string]string{"renew-ocm": "true", "no-wait": "true"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := commandAtPath(t, buildRootCommand(), "session", "join")
			for flag, value := range tc.flags {
				if err := cmd.Flags().Set(flag, value); err != nil {
					t.Fatal(err)
				}
			}
			if err := validateJoinOCM(cmd); (err == nil) != tc.valid {
				t.Fatalf("validation: %v", err)
			}
		})
	}
}

package cmd

import (
	"context"
	"errors"
	"testing"
	"time"

	ocmcredentials "github.com/openshift-online/rosa-boundary/internal/credentials/ocm"
)

type fakeOCMAcquirer func(context.Context, ocmcredentials.Flow) (ocmcredentials.Token, error)

func (f fakeOCMAcquirer) Acquire(ctx context.Context, flow ocmcredentials.Flow) (ocmcredentials.Token, error) {
	return f(ctx, flow)
}

func stubOCMAcquirer(t *testing.T, acquire fakeOCMAcquirer) {
	t.Helper()
	previous := newOCMTokenAcquirer
	t.Cleanup(func() { newOCMTokenAcquirer = previous })
	newOCMTokenAcquirer = func() ocmTokenAcquirer { return acquire }
}

func TestPendingOCMTokenOverlapsCallerWork(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	stubOCMAcquirer(t, func(_ context.Context, flow ocmcredentials.Flow) (ocmcredentials.Token, error) {
		if flow != ocmcredentials.FlowDevice {
			t.Errorf("unexpected flow %q", flow)
		}
		close(started)
		<-release
		return ocmcredentials.Token{AccessToken: "token"}, nil
	})

	// Returning before the approval completes is what lets the task start
	// while the human approves.
	pending := startOCMTokenAcquisition(context.Background(), ocmcredentials.Environment{Name: "staging"}, ocmcredentials.FlowDevice)
	defer pending.Discard()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("acquisition did not start in the background")
	}
	close(release)

	token, err := pending.Wait(context.Background())
	if err != nil || token.AccessToken != "token" {
		t.Fatalf("token=%+v err=%v", token, err)
	}
	if pending.token.AccessToken != "" {
		t.Fatal("pending token retained after handover")
	}
}

func TestPendingOCMTokenDiscardCancelsApproval(t *testing.T) {
	canceled := make(chan struct{})
	stubOCMAcquirer(t, func(ctx context.Context, _ ocmcredentials.Flow) (ocmcredentials.Token, error) {
		<-ctx.Done()
		close(canceled)
		return ocmcredentials.Token{}, ctx.Err()
	})

	pending := startOCMTokenAcquisition(context.Background(), ocmcredentials.Environment{Name: "staging"}, ocmcredentials.FlowAuthCode)
	pending.Discard()
	select {
	case <-canceled:
	default:
		t.Fatal("Discard returned before the approval was canceled")
	}
	pending.Discard() // safe to repeat on deferred cleanup paths
}

func TestPendingOCMTokenWaitReportsFailureAndCancellation(t *testing.T) {
	failure := errors.New("denied")
	stubOCMAcquirer(t, func(context.Context, ocmcredentials.Flow) (ocmcredentials.Token, error) {
		return ocmcredentials.Token{}, failure
	})
	pending := startOCMTokenAcquisition(context.Background(), ocmcredentials.Environment{Name: "staging"}, ocmcredentials.FlowDevice)
	defer pending.Discard()
	if _, err := pending.Wait(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("expected acquisition failure, got %v", err)
	}

	stubOCMAcquirer(t, func(ctx context.Context, _ ocmcredentials.Flow) (ocmcredentials.Token, error) {
		<-ctx.Done()
		return ocmcredentials.Token{}, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	blocked := startOCMTokenAcquisition(ctx, ocmcredentials.Environment{Name: "staging"}, ocmcredentials.FlowDevice)
	defer blocked.Discard()
	cancel()
	if _, err := blocked.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestOCMTokenNearExpiry(t *testing.T) {
	now := time.Now()
	for name, tc := range map[string]struct {
		expiry time.Time
		want   bool
	}{
		"no expiry supplied": {time.Time{}, false},
		"ample lifetime":     {now.Add(10 * time.Minute), false},
		"almost expired":     {now.Add(30 * time.Second), true},
		"already expired":    {now.Add(-time.Minute), true},
	} {
		if got := ocmTokenNearExpiry(ocmcredentials.Token{Expiry: tc.expiry}, now); got != tc.want {
			t.Errorf("%s: got %t, want %t", name, got, tc.want)
		}
	}
}

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/lambda"
)

func TestReadOnlyCloseStatus(t *testing.T) {
	previous, oldWait := closeOutputFormat, closeWait
	closeOutputFormat, closeWait = "json", false
	t.Cleanup(func() { closeOutputFormat, closeWait = previous, oldWait })
	for _, tc := range []struct {
		name, status, phase string
		ap                  bool
		err                 error
	}{
		{"open", "none", "", true, nil},
		{"queued", "accepted", "queued", true, nil},
		{"completed after AP deletion", "completed", "complete", false, nil},
		{"missing workspace and no record", "none", "", false, nil},
		{"unavailable", "", "", false, errors.New("transport unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := lambda.CloseStatusResponse{ClusterID: "cluster", InvestigationID: "inv", Status: tc.status, Phase: tc.phase, AccessPointPresent: tc.ap}
			service := &fakeCloseService{statuses: []*lambda.CloseStatusResponse{&want}, statusErr: tc.err}
			var out bytes.Buffer
			err := showRecordedCloseStatus(context.Background(), &out, service.service(), "cluster", "inv")
			if len(service.requests)+len(service.intents)+len(service.cancellation) != 0 {
				t.Fatal("status performed a mutation")
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("error: %v", err)
			}
			if tc.err != nil {
				if out.Len() != 0 {
					t.Fatal("reported status on transport failure")
				}
				return
			}
			var got lambda.CloseStatusResponse
			if err := json.Unmarshal(out.Bytes(), &got); err != nil || got != want || service.calls != 1 {
				t.Fatalf("unexpected status: %s", out.String())
			}
		})
	}
}

func TestCloseStatusWaitIsReadOnly(t *testing.T) {
	oldWait, oldFormat, oldPoll := closeWait, closeOutputFormat, closeStatusPoll
	t.Cleanup(func() { closeWait, closeOutputFormat, closeStatusPoll = oldWait, oldFormat, oldPoll })
	closeWait, closeOutputFormat, closeStatusPoll = true, "json", time.Millisecond

	for _, tc := range []struct {
		name     string
		statuses []*lambda.CloseStatusResponse
		wantErr  string
	}{
		{"wait through cleanup", []*lambda.CloseStatusResponse{
			{Status: lambda.CloseStatusVerifying, RequestToken: testRequest, AccessPointPresent: true},
			{Status: lambda.CloseStatusCompleted, RequestToken: testRequest},
		}, ""},
		{"close already completed", []*lambda.CloseStatusResponse{
			{Status: lambda.CloseStatusCompleted, RequestToken: testRequest},
		}, ""},
		{"nothing to wait for", []*lambda.CloseStatusResponse{
			{Status: lambda.CloseStatusNone},
		}, "no request submitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeCloseService{statuses: tc.statuses}
			var out bytes.Buffer
			err := showRecordedCloseStatus(context.Background(), &out, service.service(), "cluster", "inv")
			if service.calls != len(tc.statuses) || len(service.requests)+len(service.intents)+len(service.cancellation) != 0 {
				t.Fatalf("expected %d status polls and no mutations, got %d polls and %d submissions", len(tc.statuses), service.calls, len(service.requests))
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || out.Len() != 0 {
					t.Fatalf("expected %q without status output, got %v and %s", tc.wantErr, err, out.String())
				}
				return
			}
			var got lambda.CloseStatusResponse
			if err != nil || json.Unmarshal(out.Bytes(), &got) != nil || got != *tc.statuses[len(tc.statuses)-1] {
				t.Fatalf("unexpected status %s: %v", out.String(), err)
			}
		})
	}
}

func TestCloseStatusWaitFlags(t *testing.T) {
	for _, tc := range []struct {
		flags    []string
		conflict bool
	}{
		{[]string{"--status", "--wait"}, false},
		{[]string{"--status", "--wait", "--force"}, true},
		{[]string{"--status", "--wait", "--yes"}, true},
		{[]string{"--status", "--wait", "--dry-run"}, true},
	} {
		cmd, _, err := buildInvestigationCommand().Find([]string{"close"})
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.ParseFlags(tc.flags); err != nil {
			t.Fatal(err)
		}
		if err := cmd.ValidateFlagGroups(); (err != nil) != tc.conflict {
			t.Fatalf("flag validation for %v: %v", tc.flags, err)
		}
	}
}

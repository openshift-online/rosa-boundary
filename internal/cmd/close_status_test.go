package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openshift-online/rosa-boundary/internal/lambda"
)

func TestReadOnlyCloseStatus(t *testing.T) {
	previous := closeOutputFormat
	closeOutputFormat = "json"
	t.Cleanup(func() { closeOutputFormat = previous })
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

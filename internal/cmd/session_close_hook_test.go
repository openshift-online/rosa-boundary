package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/openshift-online/rosa-boundary/internal/lambda"
)

func hookTarget() sessionCloseTarget {
	return sessionCloseTarget{ClusterID: "cluster", InvestigationID: "inv", SessionID: "task-1", AccessPointID: "fsap-1"}
}

func TestJoinRequiresOpenInvestigation(t *testing.T) {
	target := hookTarget()
	open := lambda.CloseStatusResponse{ClusterID: target.ClusterID, InvestigationID: target.InvestigationID, Status: lambda.CloseStatusNone, Seal: "none", AccessPointPresent: true, JoinAccessPointID: target.AccessPointID}
	for _, tc := range []struct {
		name   string
		change func(*lambda.CloseStatusResponse)
	}{
		{"open", func(*lambda.CloseStatusResponse) {}},
		{"accepted", func(s *lambda.CloseStatusResponse) { s.Status = lambda.CloseStatusAccepted }},
		{"completed", func(s *lambda.CloseStatusResponse) { s.Status = lambda.CloseStatusCompleted }},
		{"unknown", func(s *lambda.CloseStatusResponse) { s.Status = lambda.CloseStatusUnknown }},
		{"queued", func(s *lambda.CloseStatusResponse) { s.OpenRequests = 1 }},
		{"manual seal", func(s *lambda.CloseStatusResponse) { s.Seal = "legacy" }},
		{"old service", func(s *lambda.CloseStatusResponse) { s.JoinAccessPointID = "" }},
		{"replacement AP", func(s *lambda.CloseStatusResponse) { s.JoinAccessPointID = "fsap-2" }},
		{"missing AP", func(s *lambda.CloseStatusResponse) { s.AccessPointPresent = false }},
		{"wrong investigation", func(s *lambda.CloseStatusResponse) { s.InvestigationID = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := open
			tc.change(&s)
			f := &fakeCloseService{statuses: []*lambda.CloseStatusResponse{&s}}
			err := requireOpenForJoin(context.Background(), f.service(), target)
			if (err == nil) != (tc.name == "open") {
				t.Fatalf("join admission: %v", err)
			}
		})
	}
	f := &fakeCloseService{statusErr: errors.New("status unavailable")}
	if err := requireOpenForJoin(context.Background(), f.service(), target); err == nil {
		t.Fatal("joined without status")
	}
}

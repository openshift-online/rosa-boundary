package cmd

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestPrintCloseInvestigationSummary(t *testing.T) {
	cluster := "test-cluster-1"
	investigationID := "inv-test-123"
	accessPointID := "fsap-12345"
	tasksStopped := 2
	taskDefsRemoved := 1

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}

	t.Cleanup(func() {
		os.Stdout = old
	})
	os.Stdout = w

	if err := printCloseInvestigationSummary(cluster, investigationID, accessPointID, tasksStopped, taskDefsRemoved); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("failed to read from pipe: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "test-cluster-1/inv-test-123") {
		t.Errorf("expected Cluster to show %q, got output:\n%s", cluster, output)
	}
	if !strings.Contains(output, "Investigation") {
		t.Errorf("expected Investigation to show %q, got output:\n%s", investigationID, output)
	}
	if !strings.Contains(output, "Sessions stopped: 2") {
		t.Errorf("expected Tasks Stopped to show 2, got output:\n%s", output)
	}
}

func TestInvestigationTaskDefinitionsDoNotMatchOtherInvestigations(t *testing.T) {
	base := "rosa-boundary-stage-cluster-incident-42"
	arns := []string{
		"arn:aws:ecs:us-east-1:123:task-definition/" + base + "-20261105T210000:1",
		"arn:aws:ecs:us-east-1:123:task-definition/" + base + "-other-20261105T210000:1",
		"arn:aws:ecs:us-east-1:123:task-definition/" + base + "-20261105T210000-extra:1",
	}
	selected := investigationTaskDefinitions(arns, base)
	if len(selected) != 1 || selected[0] != arns[0] {
		t.Fatalf("unsafe investigation definition selection: %v", selected)
	}
}

func TestSameClosePlanDetectsNewSession(t *testing.T) {
	a := closePlan{AccessPointID: "fsap-1", ClusterID: "c", InvestigationID: "i", SessionIDs: []string{"task-1"}}
	b := a
	b.SessionIDs = []string{"task-1", "task-2"}
	if sameClosePlan(a, b) {
		t.Fatal("a changed plan cannot be executed")
	}
}

func TestSameClosePlanDetectsSessionEnteringShutdown(t *testing.T) {
	a := closePlan{AccessPointID: "fsap-1", ClusterID: "c", InvestigationID: "i", SessionIDs: []string{"task-1"}, SessionsWaiting: []string{}}
	b := a
	b.SessionIDs = []string{}
	b.SessionsWaiting = []string{"task-1"}
	if sameClosePlan(a, b) {
		t.Fatal("changing desired status must require a new close plan")
	}
}

func TestCloseRejectsOtherOwnerOrMissingSubject(t *testing.T) {
	for _, tags := range []map[string]string{{"oidc_sub": "other-user"}, {"username": "same-name"}, {"oidc_sub": ""}} {
		if err := checkInvestigationOwner(tags, "current-user"); err == nil {
			t.Fatalf("accepted non-owned investigation tags: %v", tags)
		}
	}
	if err := checkInvestigationOwner(map[string]string{"oidc_sub": "current-user"}, "current-user"); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticatedSubjectRejectsMissingOrMalformedClaims(t *testing.T) {
	for _, token := range []string{"bad", "header." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + ".signature", "header.!invalid.signature"} {
		if subject, err := authenticatedSubject(token); err == nil {
			t.Fatalf("accepted subject %q from malformed token", subject)
		}
	}
	good := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-1"}`)) + ".signature"
	if subject, err := authenticatedSubject(good); err != nil || subject != "user-1" {
		t.Fatalf("subject = %q, error %v", subject, err)
	}
}

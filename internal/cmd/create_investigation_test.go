package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func captureInvestigationResult(t *testing.T, region, format string) (string, string) {
	t.Helper()
	stdout, err := os.CreateTemp(t.TempDir(), "stdout-")
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderr, err := os.CreateTemp(t.TempDir(), "stderr-")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdout, stderr
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	if err := printCreateInvestigationResult("rosa-cluster", "INV-123", "fsap-123", region, format); err != nil {
		t.Fatal(err)
	}
	if _, err := stdout.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := stderr.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	diagnostics, err := io.ReadAll(stderr)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), string(diagnostics)
}

func TestCreateInvestigationTextResult(t *testing.T) {
	savedStartProfile(t)
	wantBody := "\nInvestigation created.\nCluster: rosa-cluster\nInvestigation: INV-123\nAccess point ID: fsap-123\n\nTo create a session, run:\n  rosa-boundary --profile \"stage-east\" session create \"rosa-cluster\" --investigation-id \"INV-123\""
	for _, tt := range []struct {
		name, region, env, suffix string
	}{
		{"saved profile", "us-east-1", "", ""},
		{"unsaved flag override", "us-west-2", "", " --region \"us-west-2\""},
		{"environment override", "eu-west-1", "eu-west-1", " --region \"eu-west-1\""},
		{"environment differs from selected flag", "us-east-1", "eu-west-1", " --region \"us-east-1\""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv("ROSA_BOUNDARY_AWS_REGION", tt.env)
			} else {
				t.Setenv("ROSA_BOUNDARY_AWS_REGION", "us-east-1")
			}
			out, stderr := captureInvestigationResult(t, tt.region, "text")
			if out != wantBody+tt.suffix+"\n" {
				t.Errorf("text = %q, want %q", out, wantBody+tt.suffix+"\n")
			}
			if strings.Count(out, "created") != 1 || stderr != "" {
				t.Errorf("duplicate creation or unexpected diagnostics: stdout=%q stderr=%q", out, stderr)
			}
		})
	}
}

func TestCreateInvestigationJSONResultUnchanged(t *testing.T) {
	previous := selectedProfile
	selectedProfile = "stage-east"
	t.Cleanup(func() { selectedProfile = previous })
	out, stderr := captureInvestigationResult(t, "us-west-2", "json")
	if stderr != "" {
		t.Errorf("unexpected stderr: %q", stderr)
	}
	decoder := json.NewDecoder(strings.NewReader(out))
	var got map[string]string
	if err := decoder.Decode(&got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"profile": "stage-east", "cluster_id": "rosa-cluster", "investigation_id": "INV-123", "access_point_id": "fsap-123"}
	if len(got) != len(want) {
		t.Errorf("JSON fields = %v, want %v", got, want)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %q, want %q", key, got[key], value)
		}
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Errorf("JSON stdout is not one document: %q (next decode: %v)", out, err)
	}
	if bytes.Contains([]byte(out), []byte("To create a session")) {
		t.Errorf("text suggestion leaked into JSON: %q", out)
	}
}

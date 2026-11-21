package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/openshift-online/rosa-boundary/internal/lambda"
)

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

// Stop consent is separate from authorization: without --force the service is
// asked to wait rather than to stop anyone's session.
func TestCloseStopScopeRequiresForce(t *testing.T) {
	old := closeForce
	t.Cleanup(func() { closeForce = old })
	closeForce = false
	if scope := closeStopScope(); scope != lambda.StopScopeNone {
		t.Fatalf("default close must not consent to stopping tasks: %q", scope)
	}
	closeForce = true
	if scope := closeStopScope(); scope != lambda.StopScopeInvestigation {
		t.Fatalf("--force must consent to stopping the investigation: %q", scope)
	}
}

func TestReceiptEvidenceMustNameItsOwnAttempt(t *testing.T) {
	// The real layout the reaper writes. The `evidence/` segment matters: a
	// copy directly under _boundary-close/<ap>/ would fall inside the SRE
	// role's receipt read grant.
	const bucket, ap = "bucket", "fsap-1"
	attempt := "3b5c9f2e-8a41-4d7b-9c0e-1f2a3b4c5d6e"
	prefix := "s3://" + bucket + "/_boundary-close/evidence/" + ap + "/attempts/"
	good := prefix + attempt + "/source-manifest.json"
	verification := strings.Replace(good, "source-manifest", "verification", 1)
	other := prefix + "7a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d/verification.json"

	if !receiptEvidenceMatches(bucket, ap, good, verification, attempt) {
		t.Fatal("matching evidence references rejected")
	}
	for name, tc := range map[string][5]string{
		"a second attempt":        {bucket, ap, good, other, attempt},
		"no manifest reference":   {bucket, ap, "", verification, attempt},
		"no verification":         {bucket, ap, good, "", attempt},
		"no attempt":              {bucket, ap, good, verification, ""},
		"an unstructured key":     {bucket, ap, "s3://bucket/manifest.json", verification, attempt},
		"one reference for both":  {bucket, ap, good, good, attempt},
		"another access point":    {bucket, "fsap-2", good, verification, attempt},
		"another bucket":          {"other-bucket", ap, good, verification, attempt},
		"no bucket to bind to":    {"", ap, good, verification, attempt},
		"the pre-isolation shape": {bucket, ap, strings.Replace(good, "evidence/", "", 1), verification, attempt},
	} {
		if receiptEvidenceMatches(tc[0], tc[1], tc[2], tc[3], tc[4]) {
			t.Fatalf("accepted mismatched evidence (%s): %v", name, tc)
		}
	}
}

func TestReportCloseStatusDistinguishesAcceptedFromClosed(t *testing.T) {
	oldFormat, oldWait := closeOutputFormat, closeWait
	t.Cleanup(func() { closeOutputFormat, closeWait = oldFormat, oldWait })
	closeOutputFormat, closeWait = "json", false

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Stdout = old })
	os.Stdout = w

	err = reportCloseStatus("cluster", "inv",
		&lambda.CloseActionResponse{RequestToken: "token-1", StopScope: lambda.StopScopeNone},
		&lambda.CloseStatusResponse{Status: lambda.CloseStatusAccepted, Phase: "accepted", DirectoryRetained: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	var summary map[string]any
	if err := json.Unmarshal(buf.Bytes(), &summary); err != nil {
		t.Fatalf("close output is not JSON: %s", buf.String())
	}
	if summary["status"] != lambda.CloseStatusAccepted {
		t.Fatalf("accepted status lost: %v", summary)
	}
	if summary["access_point_deleted"] != false {
		t.Fatalf("cleanup disposition must be reported: %v", summary)
	}
	if summary["directory_retained"] != true {
		t.Fatalf("retained directory must be reported: %v", summary)
	}
	if summary["request_token"] != "token-1" {
		t.Fatalf("request identity must be reported: %v", summary)
	}
}

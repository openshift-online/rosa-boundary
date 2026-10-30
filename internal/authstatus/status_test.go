package authstatus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestReporterWritesOnePrefixedEventPerLine(t *testing.T) {
	var buf bytes.Buffer
	r := &Reporter{Format: "json", Writer: &buf}
	if err := r.Emit("boundary", "device_authorization", map[string]any{"user_code": "ABCD", "verification_uri": "https://example.invalid/device", "expires_in": 600}); err != nil {
		t.Fatal(err)
	}
	if err := r.Failure("ocm", context.Canceled); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("events = %d", len(lines))
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, Prefix) {
			t.Fatal("missing event prefix")
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, Prefix)), &event); err != nil {
			t.Fatal(err)
		}
		if event["version"] != float64(1) {
			t.Errorf("version = %v", event["version"])
		}
	}
	if strings.Contains(lines[1], "context canceled") || !strings.Contains(lines[1], `"reason":"canceled"`) {
		t.Fatal("failure reason not sanitized")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestReporterPropagatesWriteError(t *testing.T) {
	r := &Reporter{Format: "json", Writer: failingWriter{}}
	if err := r.Emit("boundary", "device_authorization", nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("error = %v", err)
	}
}

type typedFailure struct {
	reason string
	text   string
}

func (e typedFailure) Error() string  { return e.text }
func (e typedFailure) Reason() string { return e.reason }

func TestReasonPrefersBoundedTypedCategory(t *testing.T) {
	err := fmt.Errorf("OIDC authentication failed: %w", typedFailure{"invalid_response", "OIDC provider returned an invalid or expired ID token"})
	if got := Reason(err); got != "invalid_response" {
		t.Fatalf("Reason() = %q, want invalid_response", got)
	}
	var events bytes.Buffer
	if err := (&Reporter{Format: "json", Writer: &events}).Failure("boundary", err); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(events.String(), `"reason":"invalid_response"`) {
		t.Fatalf("wrong failure reason: %s", events.String())
	}
	if got := Reason(typedFailure{"untrusted", "opaque error"}); got != "other" {
		t.Fatalf("unbounded reason = %q", got)
	}
}

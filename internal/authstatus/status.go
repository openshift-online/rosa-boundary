// Package authstatus writes script-readable authentication status separately
// from command results. Authentication challenges are short-lived sensitive data.
package authstatus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

const Prefix = "ROSA_BOUNDARY_AUTH_EVENT "

// Reporter serializes complete event lines to one stream. The caller should
// supply stderr and must propagate write errors rather than waiting for approval.
type Reporter struct {
	Format string
	Writer io.Writer
	mu     sync.Mutex
}

// Emit writes a versioned event in JSON mode. Text-mode challenge and status
// messages are provided by the authentication implementations themselves.
func (r *Reporter) Emit(provider, event string, fields map[string]any) error {
	if r == nil || r.Format != "json" {
		return nil
	}
	data := map[string]any{"version": 1, "provider": provider, "event": event}
	for key, value := range fields {
		data[key] = value
	}
	line, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode authentication event: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Writer == nil {
		return errors.New("authentication event stream is unavailable")
	}
	n, err := r.Writer.Write(append(append([]byte(Prefix), line...), '\n'))
	if err != nil {
		return fmt.Errorf("write authentication event: %w", err)
	}
	if n != len(Prefix)+len(line)+1 {
		return io.ErrShortWrite
	}
	return nil
}

// Failure reports a bounded reason only, never an upstream response body.
func (r *Reporter) Failure(provider string, err error) error {
	return r.Emit(provider, "authentication_failed", map[string]any{"reason": Reason(err)})
}

// Reason maps authentication errors to safe, stable script-facing categories.
func Reason(err error) string {
	var typed interface{ Reason() string }
	if errors.As(err, &typed) {
		switch reason := typed.Reason(); reason {
		case "denied", "expired", "canceled", "network", "invalid_response", "other":
			return reason
		}
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "expired"
	}
	if err == nil {
		return "other"
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "access_denied"), strings.Contains(s, "denied"):
		return "denied"
	case strings.Contains(s, "expired"), strings.Contains(s, "timeout"), strings.Contains(s, "timed out"):
		return "expired"
	case strings.Contains(s, "cancel"):
		return "canceled"
	case strings.Contains(s, "network"), strings.Contains(s, "connection"), strings.Contains(s, "http request"):
		return "network"
	case strings.Contains(s, "invalid"), strings.Contains(s, "missing"), strings.Contains(s, "decode"):
		return "invalid_response"
	default:
		return "other"
	}
}

package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

const callbackPort = "8400"

// callbackResult holds the result from the OAuth callback.
type callbackResult struct {
	code  string
	state string
	err   error
}

// writeHTML writes an HTML response to the http.ResponseWriter, ignoring write errors
// (the connection may already be closing).
func writeHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(body))
}

// startCallbackServer starts a local HTTP server that handles the OAuth callback.
// It returns the authorization code and state, or an error.
// The server shuts down after the first successful callback or after timeout.
func startCallbackServer(ctx context.Context, expectedState string) (string, error) {
	resultCh := make(chan callbackResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		if errMsg := q.Get("error"); errMsg != "" {
			desc := q.Get("error_description")
			resultCh <- callbackResult{err: fmt.Errorf("auth error: %s: %s", errMsg, desc)}
			writeHTML(w, "<html><body><h2>Authentication failed</h2><p>"+errMsg+": "+desc+"</p><p>You may close this tab.</p></body></html>")
			return
		}

		code := q.Get("code")
		state := q.Get("state")

		if code == "" {
			resultCh <- callbackResult{err: fmt.Errorf("no authorization code in callback")}
			writeHTML(w, "<html><body><h2>Authentication failed</h2><p>No code received.</p><p>You may close this tab.</p></body></html>")
			return
		}

		if state != expectedState {
			resultCh <- callbackResult{err: fmt.Errorf("state mismatch (possible CSRF)")}
			writeHTML(w, "<html><body><h2>Authentication failed</h2><p>State mismatch.</p><p>You may close this tab.</p></body></html>")
			return
		}

		resultCh <- callbackResult{code: code, state: state}
		writeHTML(w, "<html><body><h2>Authentication successful</h2><p>You may close this tab and return to the terminal.</p></body></html>")
	})

	server := &http.Server{
		Addr:              "127.0.0.1:" + callbackPort,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return "", fmt.Errorf("cannot start callback server on port %s: %w", callbackPort, err)
	}

	go func() {
		_ = server.Serve(listener)
	}()

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	select {
	case result := <-resultCh:
		if result.err != nil {
			return "", result.err
		}
		return result.code, nil
	case <-ctx.Done():
		return "", fmt.Errorf("authentication timed out waiting for callback")
	}
}

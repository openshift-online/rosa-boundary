package ocm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
)

var testCredentials = &awsclient.TemporaryCredentials{AccessKeyID: "key", SecretAccessKey: "secret", SessionToken: "session"}

func TestTransferCancellationUnblocksPluginStdinCopier(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	reading := make(chan struct{})
	exited := make(chan struct{})
	transfer := &Transfer{
		RunPlugin: func(_ context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, stdin io.Reader, stdout, _ io.Writer) error {
			defer close(exited)
			_, _ = io.WriteString(stdout, readyMarker)
			in := bufio.NewReader(stdin)
			if _, err := in.ReadString('\n'); err != nil {
				return err
			}
			close(reading)
			// Like exec.Cmd's stdin copier, this read is not context-aware.
			_, err := io.Copy(io.Discard, in)
			return err
		},
	}
	done := make(chan error, 1)
	go func() {
		done <- transfer.Configure(ctx, "us-east-1", &awsclient.ExecuteCommandSession{}, testCredentials, []byte("canary"))
	}()
	select {
	case <-reading:
		cancel()
	case <-ctx.Done():
		t.Fatal("plugin failed to read payload")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled transfer returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled transfer did not return")
	}
	select {
	case <-exited:
	default:
		t.Fatal("transfer returned before plugin exit")
	}
}

func TestTransferConfigureAttachmentNegotiatesRequestFormat(t *testing.T) {
	legacy := []byte(`{"access_token":"canary","url":"https://api.openshift.com"}`)
	attachment := []byte(`{"access_token":"canary","url":"https://api.openshift.com","generation":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	for _, tc := range []struct {
		name   string
		prefix []string
		want   []byte
	}{
		{"old helper", nil, legacy},
		{"renewal helper", []string{renewalMarker[:12], renewalMarker[12:] + "\n"}, attachment},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transfer := &Transfer{
				Timeout: time.Second,
				RunPlugin: func(_ context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, stdin io.Reader, stdout, _ io.Writer) error {
					for _, frame := range tc.prefix {
						_, _ = io.WriteString(stdout, frame)
					}
					_, _ = io.WriteString(stdout, readyMarker)
					reader := bufio.NewReader(stdin)
					line, err := reader.ReadString('\n')
					if err != nil || strings.TrimSpace(line) != base64.StdEncoding.EncodeToString(tc.want) {
						return errors.New("unexpected request format")
					}
					_, _ = io.WriteString(stdout, successMarker)
					if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
						return errors.New("expected exactly one request")
					}
					return nil
				},
			}
			builds := 0
			got, err := transfer.ConfigureAttachment(context.Background(), "us-east-1", &awsclient.ExecuteCommandSession{}, testCredentials, func(supported bool) ([]byte, error) {
				builds++
				if supported {
					return bytes.Clone(attachment), nil
				}
				return bytes.Clone(legacy), nil
			})
			if err != nil || got != (tc.prefix != nil) || builds != 1 {
				t.Fatalf("generation confirmed=%t, requests built=%d: %v", got, builds, err)
			}
		})
	}
}

func TestTransferDeadlineWhileWritingRequest(t *testing.T) {
	transfer := &Transfer{
		Timeout: 100 * time.Millisecond,
		RunPlugin: func(ctx context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, _ io.Reader, stdout, _ io.Writer) error {
			_, _ = io.WriteString(stdout, readyMarker)
			// Do not consume stdin: cancellation must unblock the request write.
			<-ctx.Done()
			return ctx.Err()
		},
	}
	err := transfer.Configure(context.Background(), "us-east-1", &awsclient.ExecuteCommandSession{}, testCredentials, []byte("canary"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked write returned %v", err)
	}
}

func TestTransferConfigureHandlesFramedMarkersAndClosesStdinAfterSuccess(t *testing.T) {
	request := []byte(`{"access_token":"raw-token-canary","url":"https://api.openshift.com"}`)
	encoded := base64.StdEncoding.EncodeToString(request)
	runner := func(ctx context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, stdin io.Reader, stdout, _ io.Writer) error {
		_, _ = io.WriteString(stdout, "frame-prefix"+readyMarker[:12])
		_, _ = io.WriteString(stdout, readyMarker[12:]+"frame-suffix")
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) != encoded {
			return errors.New("unexpected payload")
		}
		readFinished := make(chan struct{})
		go func() {
			_, _ = io.ReadAll(stdin)
			close(readFinished)
		}()
		select {
		case <-readFinished:
			return errors.New("stdin closed before helper exit")
		case <-time.After(20 * time.Millisecond):
		}
		_, _ = io.WriteString(stdout, "frame:"+successMarker+":end")
		select {
		case <-readFinished:
			return nil
		case <-ctx.Done():
			return errors.New("stdin remained open after helper success")
		}
	}

	var debugLog strings.Builder
	transfer := &Transfer{
		RunPlugin: runner,
		Debug: func(format string, args ...any) error {
			_, err := fmt.Fprintf(&debugLog, format+"\n", args...)
			return err
		},
		Timeout:   time.Second,
		MaxOutput: 4096,
	}
	if err := transfer.Configure(context.Background(), "us-east-1", &awsclient.ExecuteCommandSession{}, testCredentials, request); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"plugin", "readiness marker", "request sent", "success marker", "closed plugin stdin", "exited successfully"} {
		if !strings.Contains(strings.ToLower(debugLog.String()), stage) {
			t.Fatalf("debug log does not contain %q: %q", stage, debugLog.String())
		}
	}
	if strings.Contains(debugLog.String(), "raw-token-canary") || strings.Contains(debugLog.String(), encoded) {
		t.Fatalf("debug log leaked credential material: %q", debugLog.String())
	}
}

func TestTransferRejectsProtocolFailuresWithoutLeakingPayload(t *testing.T) {
	secret := "raw-token-canary-protocol"
	request := []byte(`{"access_token":"` + secret + `"}`)
	tests := map[string]PluginRunner{
		"early EOF": func(_ context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, _ io.Reader, _ io.Writer, _ io.Writer) error {
			return nil
		},
		"duplicate ready": func(_ context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, _ io.Reader, stdout, _ io.Writer) error {
			_, _ = io.WriteString(stdout, readyMarker+readyMarker)
			return nil
		},
		"success before ready": func(_ context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, _ io.Reader, stdout, _ io.Writer) error {
			_, _ = io.WriteString(stdout, successMarker+readyMarker)
			return nil
		},
		"missing success": func(_ context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, stdin io.Reader, stdout, _ io.Writer) error {
			_, _ = io.WriteString(stdout, readyMarker)
			_, _ = bufio.NewReader(stdin).ReadString('\n')
			return nil
		},
	}
	for name, runner := range tests {
		t.Run(name, func(t *testing.T) {
			transfer := &Transfer{RunPlugin: runner, Timeout: time.Second, MaxOutput: 4096}
			err := transfer.Configure(context.Background(), "us-east-1", &awsclient.ExecuteCommandSession{}, testCredentials, request)
			if err == nil {
				t.Fatal("protocol failure succeeded")
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(request)) {
				t.Fatalf("error leaked payload: %v", err)
			}
		})
	}
}

func TestTransferBoundsOutputAndCancellation(t *testing.T) {
	outputClosed := make(chan struct{})
	runner := func(_ context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, _ io.Reader, stdout, _ io.Writer) error {
		_, _ = io.WriteString(stdout, strings.Repeat("x", 128))
		_, err := io.WriteString(stdout, "blocked until the output reader closes")
		if errors.Is(err, io.ErrClosedPipe) {
			close(outputClosed)
			return nil
		}
		return fmt.Errorf("output remained writable after the safety limit: %w", err)
	}
	transfer := &Transfer{RunPlugin: runner, Timeout: 100 * time.Millisecond, MaxOutput: 64}
	if err := transfer.Configure(context.Background(), "us-east-1", &awsclient.ExecuteCommandSession{}, testCredentials, []byte("request")); err == nil {
		t.Fatal("unbounded output succeeded")
	}
	select {
	case <-outputClosed:
	default:
		t.Fatal("output reader was not closed before waiting for the plugin")
	}
}

func TestTransferClearRequiresOnlySuccess(t *testing.T) {
	runner := func(ctx context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, stdin io.Reader, stdout, _ io.Writer) error {
		_, _ = io.WriteString(stdout, successMarker)
		readFinished := make(chan struct{})
		go func() {
			_, _ = io.ReadAll(stdin)
			close(readFinished)
		}()
		select {
		case <-readFinished:
			return nil
		case <-ctx.Done():
			return errors.New("stdin remained open after helper success")
		}
	}
	transfer := &Transfer{RunPlugin: runner, Timeout: time.Second, MaxOutput: 1024}
	if err := transfer.Clear(context.Background(), "us-east-1", &awsclient.ExecuteCommandSession{}, testCredentials); err != nil {
		t.Fatal(err)
	}
}

func TestBackplaneLoginCommand(t *testing.T) {
	command, err := BackplaneLoginCommand("2abc.d-e_1")
	if err != nil || command != backplaneLoginCommandPrefix+"2abc.d-e_1" {
		t.Fatalf("command = %q, %v", command, err)
	}
	for _, bad := range []string{"", "-x", "a b", "a;rm", "a'b", "$(x)", "a\nb", strings.Repeat("a", 129)} {
		if _, err := BackplaneLoginCommand(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestTransferLoginFailsWithoutSuccessMarker(t *testing.T) {
	runner := func(_ context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, _ io.Reader, _, _ io.Writer) error {
		return nil
	}
	transfer := &Transfer{RunPlugin: runner, Timeout: time.Second, MaxOutput: 1024}
	if err := transfer.Login(context.Background(), "us-east-1", &awsclient.ExecuteCommandSession{}, testCredentials); err == nil {
		t.Fatal("login without success marker succeeded")
	}
}

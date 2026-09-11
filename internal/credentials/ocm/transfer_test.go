package ocm

import (
	"bufio"
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

func TestTransferConfigureHandlesFramedMarkersAndKeepsStdinOpen(t *testing.T) {
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
		return nil
	}

	var debugLog strings.Builder
	transfer := &Transfer{
		RunPlugin: runner,
		Debug: func(format string, args ...any) {
			_, _ = fmt.Fprintf(&debugLog, format+"\n", args...)
		},
		Timeout:   time.Second,
		MaxOutput: 4096,
	}
	if err := transfer.Configure(context.Background(), "us-east-1", &awsclient.ExecuteCommandSession{}, testCredentials, request); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"plugin", "readiness marker", "request sent", "success marker", "exited successfully"} {
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
	runner := func(ctx context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, _ io.Reader, stdout, _ io.Writer) error {
		_, _ = io.WriteString(stdout, strings.Repeat("x", 128))
		<-ctx.Done()
		return ctx.Err()
	}
	transfer := &Transfer{RunPlugin: runner, Timeout: 100 * time.Millisecond, MaxOutput: 64}
	if err := transfer.Configure(context.Background(), "us-east-1", &awsclient.ExecuteCommandSession{}, testCredentials, []byte("request")); err == nil {
		t.Fatal("unbounded output succeeded")
	}
}

func TestTransferClearRequiresOnlySuccess(t *testing.T) {
	runner := func(_ context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, stdin io.Reader, stdout, _ io.Writer) error {
		_, _ = io.WriteString(stdout, successMarker)
		return nil
	}
	transfer := &Transfer{RunPlugin: runner, Timeout: time.Second, MaxOutput: 1024}
	if err := transfer.Clear(context.Background(), "us-east-1", &awsclient.ExecuteCommandSession{}, testCredentials); err != nil {
		t.Fatal(err)
	}
}

func TestTransferCheckRequiresAvailabilityMarker(t *testing.T) {
	runner := func(_ context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, _ io.Reader, stdout, _ io.Writer) error {
		_, _ = io.WriteString(stdout, "frame:"+helperReadyMarker+":end")
		return nil
	}
	transfer := &Transfer{RunPlugin: runner, Timeout: time.Second, MaxOutput: 1024}
	if err := transfer.Check(context.Background(), "us-east-1", &awsclient.ExecuteCommandSession{}, testCredentials); err != nil {
		t.Fatal(err)
	}

	transfer.RunPlugin = func(_ context.Context, _ string, _ *awsclient.ExecuteCommandSession, _ *awsclient.TemporaryCredentials, _ io.Reader, _ io.Writer, _ io.Writer) error {
		return nil
	}
	if err := transfer.Check(context.Background(), "us-east-1", &awsclient.ExecuteCommandSession{}, testCredentials); err == nil {
		t.Fatal("helper check succeeded without availability marker")
	}
}

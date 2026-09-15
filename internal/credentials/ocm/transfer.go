package ocm

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
)

const (
	ConfigureCommand = "runuser --user=sre -- /usr/local/bin/rosa-boundary-credential-helper configure ocm"
	ClearCommand     = "runuser --user=sre -- /usr/local/bin/rosa-boundary-credential-helper clear ocm"
	readyMarker      = "__ROSA_BOUNDARY_CREDENTIAL_OCM_READY__"
	successMarker    = "__ROSA_BOUNDARY_CREDENTIAL_OCM_SUCCESS__"
	defaultMaxOutput = 1024 * 1024
)

// PluginRunner launches Session Manager with explicit protocol streams.
type PluginRunner func(context.Context, string, *awsclient.ExecuteCommandSession, *awsclient.TemporaryCredentials, io.Reader, io.Writer, io.Writer) error

// Transfer performs the bounded helper protocol over an ECS Exec session.
type Transfer struct {
	RunPlugin PluginRunner
	Debug     func(format string, args ...any)
	Timeout   time.Duration
	MaxOutput int
}

// NewTransfer returns the production stream transfer implementation.
func NewTransfer() *Transfer {
	return &Transfer{
		RunPlugin: awsclient.RunSessionManagerPluginWithStreams,
		Timeout:   time.Minute,
		MaxOutput: defaultMaxOutput,
	}
}

// Configure waits until terminal echo is disabled, sends one request, and
// keeps stdin open until the task-side helper and plugin have exited.
func (t *Transfer) Configure(ctx context.Context, region string, session *awsclient.ExecuteCommandSession, credentials *awsclient.TemporaryCredentials, request []byte) error {
	if len(request) == 0 {
		return errors.New("credential request is empty")
	}
	payload := base64.StdEncoding.EncodeToString(request) + "\n"
	err := t.run(ctx, region, session, credentials, payload, true)
	payload = ""
	return err
}

// Clear requires helper success but sends no credential payload.
func (t *Transfer) Clear(ctx context.Context, region string, session *awsclient.ExecuteCommandSession, credentials *awsclient.TemporaryCredentials) error {
	return t.run(ctx, region, session, credentials, "", false)
}

func (t *Transfer) run(ctx context.Context, region string, session *awsclient.ExecuteCommandSession, credentials *awsclient.TemporaryCredentials, payload string, requireReady bool) error {
	runner := t.RunPlugin
	if runner == nil {
		return errors.New("credential session runner is not configured")
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = time.Minute
	}
	maxOutput := t.MaxOutput
	if maxOutput <= 0 {
		maxOutput = defaultMaxOutput
	}

	protocolCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	t.debug("Starting Session Manager plugin for credential operation")
	pluginInput, inputWriter := io.Pipe()
	pluginOutput, outputWriter := io.Pipe()
	pluginResult := make(chan error, 1)
	go func() {
		err := runner(protocolCtx, region, session, credentials, pluginInput, outputWriter, io.Discard)
		_ = outputWriter.CloseWithError(nil)
		pluginResult <- err
	}()
	defer func() {
		_ = inputWriter.Close()
		_ = pluginInput.Close()
		_ = pluginOutput.Close()
	}()

	var received strings.Builder
	buffer := make([]byte, 4096)
	readyCount := 0
	successCount := 0
	protocolErr := error(nil)
	for {
		count, readErr := pluginOutput.Read(buffer)
		if count > 0 {
			if received.Len()+count > maxOutput {
				protocolErr = errors.New("credential helper output exceeded the safety limit")
				cancel()
				break
			}
			_, _ = received.Write(buffer[:count])
			current := received.String()
			newReadyCount := strings.Count(current, readyMarker)
			newSuccessCount := strings.Count(current, successMarker)
			if newReadyCount > 1 || newSuccessCount > 1 {
				protocolErr = errors.New("credential helper sent duplicate protocol markers")
				cancel()
				break
			}
			if requireReady && newSuccessCount == 1 && (newReadyCount == 0 || strings.Index(current, successMarker) < strings.Index(current, readyMarker)) {
				protocolErr = errors.New("credential helper confirmed success before accepting the request")
				cancel()
				break
			}
			if requireReady && readyCount == 0 && newReadyCount == 1 {
				t.debug("Credential helper readiness marker received")
				if _, err := io.WriteString(inputWriter, payload); err != nil {
					protocolErr = errors.New("credential helper stopped before accepting the request")
					cancel()
					break
				}
				payload = ""
				t.debug("Credential request sent; keeping plugin stdin open until helper exit")
			}
			if successCount == 0 && newSuccessCount == 1 {
				t.debug("Credential helper success marker received")
			}
			readyCount = newReadyCount
			successCount = newSuccessCount
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				protocolErr = errors.New("credential helper output could not be read")
			}
			break
		}
	}

	pluginErr := <-pluginResult
	if pluginErr != nil {
		t.debug("Session Manager plugin exited unsuccessfully")
	} else {
		t.debug("Session Manager plugin exited successfully")
	}
	if protocolErr != nil {
		return protocolErr
	}
	if protocolCtx.Err() != nil {
		return fmt.Errorf("credential operation timed out or was canceled: %w", protocolCtx.Err())
	}
	if pluginErr != nil {
		return errors.New("credential session exited unsuccessfully")
	}
	if requireReady && readyCount != 1 {
		return errors.New("credential helper did not become ready")
	}
	if successCount != 1 {
		return errors.New("credential helper did not confirm success")
	}
	return nil
}

func (t *Transfer) debug(format string, args ...any) {
	if t.Debug != nil {
		t.Debug(format, args...)
	}
}

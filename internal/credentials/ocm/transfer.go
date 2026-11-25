package ocm

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
)

const (
	ConfigureCommand            = "runuser --user=sre -- /usr/local/bin/rosa-boundary-credential-helper configure ocm"
	RenewCommand                = "runuser --user=sre -- /usr/local/bin/rosa-boundary-credential-helper renew ocm"
	ClearCommand                = "runuser --user=sre -- /usr/local/bin/rosa-boundary-credential-helper clear ocm"
	readyMarker                 = "__ROSA_BOUNDARY_CREDENTIAL_OCM_READY__"
	renewalMarker               = "__ROSA_BOUNDARY_CREDENTIAL_OCM_GENERATIONS_V1__"
	successMarker               = "__ROSA_BOUNDARY_CREDENTIAL_OCM_SUCCESS__"
	backplaneMessageMarker      = "__ROSA_BOUNDARY_BACKPLANE_MESSAGE__"
	maxClusterIDLength          = 512
	maxHelperMessageRunes       = 400
	defaultMaxOutput            = 1024 * 1024
	backplaneLoginCommandPrefix = "runuser --user=sre -- /usr/local/bin/rosa-boundary-credential-helper login backplane "
)

// PluginRunner launches Session Manager with explicit protocol streams.
type PluginRunner func(context.Context, string, *awsclient.ExecuteCommandSession, *awsclient.TemporaryCredentials, io.Reader, io.Writer, io.Writer) error

// Transfer performs the bounded helper protocol over an ECS Exec session.
type Transfer struct {
	RunPlugin PluginRunner
	Debug     func(format string, args ...any) error
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
// closes stdin after the task-side helper confirms successful validation.
func (t *Transfer) Configure(ctx context.Context, region string, session *awsclient.ExecuteCommandSession, credentials *awsclient.TemporaryCredentials, request []byte) error {
	payload, err := encodeRequest(request)
	if err != nil {
		return err
	}
	return t.run(ctx, region, session, credentials, func(bool) (string, error) { return payload, nil })
}

// ConfigureAttachment sends exactly one request. An older helper advertises
// only readiness, so send the original access-token-and-URL request instead.
func (t *Transfer) ConfigureAttachment(ctx context.Context, region string, session *awsclient.ExecuteCommandSession, credentials *awsclient.TemporaryCredentials, requestFor func(bool) ([]byte, error)) (bool, error) {
	usesGeneration := false
	err := t.run(ctx, region, session, credentials, func(supported bool) (string, error) {
		usesGeneration = supported
		request, err := requestFor(supported)
		if err != nil {
			return "", err
		}
		defer clear(request)
		return encodeRequest(request)
	})
	return usesGeneration && err == nil, err
}

func encodeRequest(request []byte) (string, error) {
	if len(request) == 0 {
		return "", errors.New("credential request is empty")
	}
	if base64.StdEncoding.EncodedLen(len(request)) > 65536 {
		return "", errors.New("credential request exceeded the safety limit")
	}
	return base64.StdEncoding.EncodeToString(request) + "\n", nil
}

// BackplaneLoginCommand returns the helper command for a cluster ID. Backplane
// decides whether the ID is valid; this only rejects values that cannot be
// carried safely in one command-line argument and quotes the rest.
func BackplaneLoginCommand(clusterID string) (string, error) {
	if clusterID == "" || len(clusterID) > maxClusterIDLength || strings.ContainsFunc(clusterID, unicode.IsControl) {
		return "", fmt.Errorf("cluster ID must be 1-%d characters without control characters", maxClusterIDLength)
	}
	return backplaneLoginCommandPrefix + "'" + strings.ReplaceAll(clusterID, "'", `'\''`) + "'", nil
}

// HelperMessageError reports a failed helper operation together with the
// sanitized, size-limited message the helper chose to share (for Backplane
// login, the last lines of Backplane's own output).
type HelperMessageError struct {
	Message string
}

func (e *HelperMessageError) Error() string {
	return "credential helper did not confirm success: " + e.Message
}

// helperMessage extracts marker-prefixed lines from helper output.
func helperMessage(received string) string {
	var lines []string
	for _, line := range strings.Split(received, "\n") {
		line = strings.TrimRight(line, "\r")
		_, text, found := strings.Cut(line, backplaneMessageMarker)
		if !found {
			continue
		}
		text = ansiEscape.ReplaceAllString(text, "")
		text = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, text)
		if text = strings.TrimSpace(text); text != "" {
			lines = append(lines, text)
		}
	}
	message := strings.Join(lines, " | ")
	if runes := []rune(message); len(runes) > maxHelperMessageRunes {
		message = string(runes[:maxHelperMessageRunes]) + "..."
	}
	return message
}

var ansiEscape = regexp.MustCompile("\x1b\\[[0-9;?]*[A-Za-z]")

// Login requires helper success but sends no credential payload.
func (t *Transfer) Login(ctx context.Context, region string, session *awsclient.ExecuteCommandSession, credentials *awsclient.TemporaryCredentials) error {
	return t.run(ctx, region, session, credentials, nil)
}

// Clear requires helper success but sends no credential payload.
func (t *Transfer) Clear(ctx context.Context, region string, session *awsclient.ExecuteCommandSession, credentials *awsclient.TemporaryCredentials) error {
	return t.run(ctx, region, session, credentials, nil)
}

func (t *Transfer) run(ctx context.Context, region string, session *awsclient.ExecuteCommandSession, credentials *awsclient.TemporaryCredentials, payloadFor func(supportsGeneration bool) (string, error)) error {
	requireReady := payloadFor != nil
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
	if err := t.debug("Starting Session Manager plugin for credential operation"); err != nil {
		return err
	}
	pluginInput, inputWriter := io.Pipe()
	pluginOutput, outputWriter := io.Pipe()
	// exec.Cmd waits for its stdin copier. Closing both pipes on cancellation
	// also unblocks the protocol if a helper stops reading or writing.
	stopClosing := context.AfterFunc(protocolCtx, func() {
		_ = inputWriter.CloseWithError(protocolCtx.Err())
		_ = pluginOutput.CloseWithError(protocolCtx.Err())
	})
	defer stopClosing()
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
	inputClosed := false
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
				if err := t.debug("Credential helper readiness marker received"); err != nil {
					protocolErr = err
					cancel()
					break
				}
				// Capability must precede READY, including when the plugin
				// splits the markers across arbitrary read boundaries.
				ready := strings.Index(current, readyMarker)
				supportsGeneration := strings.Contains(current[:ready], renewalMarker)
				payload, err := payloadFor(supportsGeneration)
				if err != nil {
					protocolErr = err
					cancel()
					break
				}
				if _, err := io.WriteString(inputWriter, payload); err != nil {
					protocolErr = credentialPipeError(protocolCtx, "credential helper stopped before accepting the request")
					cancel()
					break
				}
				if err := t.debug("Credential request sent; keeping plugin stdin open until helper exit"); err != nil {
					protocolErr = err
					cancel()
					break
				}
			}
			if successCount == 0 && newSuccessCount == 1 {
				if err := t.debug("Credential helper success marker received"); err != nil {
					protocolErr = err
					cancel()
					break
				}
				// ECS Exec keeps the session alive while plugin stdin remains open.
				// Wait for helper success before closing it so validation cannot be
				// interrupted, then let Session Manager terminate normally.
				if err := inputWriter.Close(); err != nil {
					protocolErr = errors.New("credential session input could not be closed")
					cancel()
					break
				}
				inputClosed = true
				if err := t.debug("Credential helper succeeded; closed plugin stdin"); err != nil {
					protocolErr = err
					cancel()
					break
				}
			}
			readyCount = newReadyCount
			successCount = newSuccessCount
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				protocolErr = credentialPipeError(protocolCtx, "credential helper output could not be read")
			}
			break
		}
	}

	if !inputClosed {
		if err := inputWriter.CloseWithError(io.ErrClosedPipe); err != nil && protocolErr == nil {
			protocolErr = errors.New("credential session input could not be closed")
		}
	}
	_ = pluginOutput.CloseWithError(io.ErrClosedPipe)
	pluginErr := <-pluginResult
	if pluginErr != nil {
		if err := t.debug("Session Manager plugin exited unsuccessfully"); err != nil && protocolErr == nil {
			protocolErr = err
		}
	} else {
		if err := t.debug("Session Manager plugin exited successfully"); err != nil && protocolErr == nil {
			protocolErr = err
		}
	}
	if protocolErr != nil {
		return protocolErr
	}
	if successCount != 1 {
		if message := helperMessage(received.String()); message != "" {
			return &HelperMessageError{Message: message}
		}
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

func credentialPipeError(ctx context.Context, message string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("credential operation timed out or was canceled: %w", err)
	}
	return errors.New(message)
}

func (t *Transfer) debug(format string, args ...any) error {
	if t.Debug != nil {
		if err := t.Debug(format, args...); err != nil {
			return fmt.Errorf("write credential debug output: %w", err)
		}
	}
	return nil
}

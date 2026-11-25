package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// sessionManagerPlugin is the binary name for the AWS SSM Session Manager plugin.
const sessionManagerPlugin = "session-manager-plugin"

// execSessionManagerPlugin permits unit testing the process-replacement path.
var execSessionManagerPlugin = syscall.Exec

// StartSessionManagerPlugin launches the session-manager-plugin subprocess with the
// session details and assumed SRE credentials returned by ECS ExecuteCommand. This
// replaces the process entirely (via syscall.Exec) so the terminal is handed over.
func StartSessionManagerPlugin(region string, session *ExecuteCommandSession, creds *TemporaryCredentials) error {
	pluginPath, err := exec.LookPath(sessionManagerPlugin)
	if err != nil {
		return fmt.Errorf(
			"session-manager-plugin not found in PATH.\n"+
				"Install it from: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html\n"+
				"Original error: %w", err)
	}

	// The plugin expects the session JSON, region, and a "StartSession" operation type,
	// then an empty JSON object for "parameters", then the endpoint.
	// Format: session-manager-plugin <session-json> <region> StartSession <profile> <params-json> <endpoint>
	// For ECS Exec, the parameters must include "Target": "ecs:<cluster>_<taskId>_<runtimeId>"
	// without which the plugin panics on a nil interface conversion.

	ssmEndpoint := fmt.Sprintf("https://ssm.%s.amazonaws.com", region)

	paramsJSON := "{}"
	if session.Target != "" {
		params, _ := json.Marshal(map[string]string{"Target": session.Target})
		paramsJSON = string(params)
	}

	args := []string{
		pluginPath,
		string(session.RawSession),
		region,
		"StartSession",
		"",
		paramsJSON,
		ssmEndpoint,
	}

	env, err := sessionManagerPluginEnv(creds)
	if err != nil {
		return err
	}

	// Exec replaces the current process — signals (Ctrl-C, window resize) flow naturally.
	return execSessionManagerPlugin(pluginPath, args, env)
}

// RunSessionManagerPlugin runs the session-manager-plugin as a child process
// (non-replacing) using the assumed SRE credentials until ctx is canceled. Use
// this when cleanup is needed after the plugin exits.
func RunSessionManagerPlugin(ctx context.Context, region string, session *ExecuteCommandSession, creds *TemporaryCredentials) error {
	return RunSessionManagerPluginWithStreams(ctx, region, session, creds, os.Stdin, os.Stdout, os.Stderr)
}

// stdinPumpStopTimeout bounds the wait for the stdin forwarding goroutine after
// its reader has been closed.
const stdinPumpStopTimeout = 2 * time.Second

// RunSessionManagerPluginWithStreams runs the plugin as a child with caller-owned
// streams. The separate entry point lets credential transfers control stdin and
// permits complete subprocess testing without replacing the test process.
//
// An *os.File stdin is passed to the plugin directly, preserving terminal
// handling. Any other reader must be an io.ReadCloser whose Close unblocks a
// pending Read (as io.PipeReader does); it is forwarded through a pipe, owned by
// this call, and closed when the plugin exits so forwarding stops before return.
// A reader that cannot be interrupted is rejected before the plugin starts.
func RunSessionManagerPluginWithStreams(ctx context.Context, region string, session *ExecuteCommandSession, creds *TemporaryCredentials, stdin io.Reader, stdout, stderr io.Writer) error {
	pluginPath, err := exec.LookPath(sessionManagerPlugin)
	if err != nil {
		return fmt.Errorf(
			"session-manager-plugin not found in PATH.\n"+
				"Install it from: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html\n"+
				"Original error: %w", err)
	}

	ssmEndpoint := fmt.Sprintf("https://ssm.%s.amazonaws.com", region)

	paramsJSON := "{}"
	if session.Target != "" {
		params, _ := json.Marshal(map[string]string{"Target": session.Target})
		paramsJSON = string(params)
	}

	cmd := exec.CommandContext(ctx, pluginPath,
		string(session.RawSession),
		region,
		"StartSession",
		"",
		paramsJSON,
		ssmEndpoint,
	)
	env, err := sessionManagerPluginEnv(creds)
	if err != nil {
		return err
	}
	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// Pass a real file straight through: the plugin configures the terminal
	// with stty against its own stdin, which fails on a pipe.
	if file, ok := stdin.(*os.File); ok {
		cmd.Stdin = file
		return cmd.Run()
	}

	// A caller-owned io.Reader that stays open would otherwise be copied by an
	// exec goroutine that Wait cannot interrupt. Hand the plugin an *os.File so
	// Wait returns when the process exits.
	closer, ok := stdin.(io.ReadCloser)
	if !ok {
		return errors.New("plugin stdin must be an *os.File or an io.ReadCloser whose Close unblocks Read")
	}
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create plugin stdin pipe: %w", err)
	}
	pumpDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(stdinWrite, stdin)
		if closeErr := stdinWrite.Close(); copyErr == nil {
			copyErr = closeErr
		}
		pumpDone <- copyErr
	}()
	cmd.Stdin = stdinRead
	cmd.WaitDelay = 5 * time.Second

	runErr := cmd.Run()
	// Releasing both ends stops writes to the plugin. A reader that can be
	// closed is closed here so the forwarding goroutine stops before return.
	_ = stdinRead.Close()
	_ = stdinWrite.Close()
	closeErr := closer.Close()
	var pumpErr error
	select {
	case pumpErr = <-pumpDone:
	case <-time.After(stdinPumpStopTimeout):
		pumpErr = errors.New("stdin forwarding did not stop after its reader was closed")
	}
	if runErr != nil {
		return runErr
	}
	if pumpErr != nil && !expectedStdinShutdown(pumpErr) {
		return fmt.Errorf("forward plugin stdin: %w", pumpErr)
	}
	if closeErr != nil && !expectedStdinShutdown(closeErr) {
		return fmt.Errorf("close plugin stdin source: %w", closeErr)
	}
	return nil
}

// expectedStdinShutdown reports errors that only mean the plugin or caller
// closed its end of stdin first.
func expectedStdinShutdown(err error) bool {
	return errors.Is(err, os.ErrClosed) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, syscall.EPIPE)
}

// sessionManagerPluginEnv replaces ambient AWS credentials with the OIDC-derived
// SRE role credentials used to create the ECS Exec session.
func sessionManagerPluginEnv(creds *TemporaryCredentials) ([]string, error) {
	if creds == nil || creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SessionToken == "" {
		return nil, fmt.Errorf("assumed SRE credentials are required for session-manager-plugin")
	}

	// A key whose map value is true is excluded from env.
	credentialSourceKeys := map[string]bool{
		"AWS_ACCESS_KEY_ID":           true,
		"AWS_SECRET_ACCESS_KEY":       true,
		"AWS_SESSION_TOKEN":           true,
		"AWS_SECURITY_TOKEN":          true,
		"AWS_PROFILE":                 true,
		"AWS_DEFAULT_PROFILE":         true,
		"AWS_SHARED_CREDENTIALS_FILE": true,
		"AWS_CONFIG_FILE":             true,
	}

	env := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !credentialSourceKeys[key] {
			env = append(env, entry)
		}
	}

	return append(env,
		"AWS_ACCESS_KEY_ID="+creds.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY="+creds.SecretAccessKey,
		"AWS_SESSION_TOKEN="+creds.SessionToken,
	), nil
}

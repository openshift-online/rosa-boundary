package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
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
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	env, err := sessionManagerPluginEnv(creds)
	if err != nil {
		return err
	}
	cmd.Env = env

	return cmd.Run()
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

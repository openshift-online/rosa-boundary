package aws

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// sessionManagerPlugin is the binary name for the AWS SSM Session Manager plugin.
const sessionManagerPlugin = "session-manager-plugin"

// StartSessionManagerPlugin launches the session-manager-plugin subprocess with the
// session details returned by ECS ExecuteCommand. This replaces the process entirely
// (via syscall.Exec) so that the terminal is fully handed over to the plugin.
func StartSessionManagerPlugin(region string, session *ExecuteCommandSession) error {
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

	// Exec replaces the current process — signals (Ctrl-C, window resize) flow naturally.
	return syscall.Exec(pluginPath, args, os.Environ())
}

// RunSessionManagerPlugin runs the session-manager-plugin as a child process
// (non-replacing). Use this when you need to wait for the plugin to finish
// and then do cleanup.
func RunSessionManagerPlugin(region string, session *ExecuteCommandSession) error {
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

	cmd := exec.Command(pluginPath,
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

	return cmd.Run()
}

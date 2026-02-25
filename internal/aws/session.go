package aws

import (
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
	// When called from ECS Exec context, the AWS CLI passes it like this:
	//   session-manager-plugin '{"sessionId":"...","streamUrl":"...","tokenValue":"..."}' us-east-2 StartSession '' '{}' https://ssm.us-east-2.amazonaws.com

	ssmEndpoint := fmt.Sprintf("https://ssm.%s.amazonaws.com", region)

	// Prepare the target JSON (ECS Exec uses a different "Target" format internally,
	// but the plugin itself only needs the session JSON).
	args := []string{
		pluginPath,
		string(session.RawSession),
		region,
		"StartSession",
		"",
		"{}",
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

	cmd := exec.Command(pluginPath,
		string(session.RawSession),
		region,
		"StartSession",
		"",
		"{}",
		ssmEndpoint,
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

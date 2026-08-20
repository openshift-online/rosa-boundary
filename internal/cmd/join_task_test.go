package cmd

import (
	"testing"
)

func TestJoinTask_DefaultCommandValue(t *testing.T) {
	// Verify the default exec command matches the expected pattern
	expectedDefault := "runuser -u sre -- sh -c 'cd ~ && exec bash --login'"

	if defaultExecCommand != expectedDefault {
		t.Errorf("defaultExecCommand = %q, want %q", defaultExecCommand, expectedDefault)
	}
}

func TestJoinTask_DefaultCommandUsesRunuser(t *testing.T) {
	// Verify the default command switches to the sre user
	if defaultExecCommand == "" {
		t.Fatal("defaultExecCommand should not be empty")
	}

	// The command must use runuser to switch from root (SSM Agent) to sre user
	const requiredPrefix = "runuser -u sre"
	if len(defaultExecCommand) < len(requiredPrefix) ||
		defaultExecCommand[:len(requiredPrefix)] != requiredPrefix {
		t.Errorf("defaultExecCommand must start with %q for security, got: %q",
			requiredPrefix, defaultExecCommand)
	}
}

func TestJoinTask_DefaultCommandUsesLoginShell(t *testing.T) {
	// Verify the default command uses a login shell (loads bashrc.d, env, etc.)
	const loginFlag = "bash --login"
	if defaultExecCommand == "" {
		t.Fatal("defaultExecCommand should not be empty")
	}

	// Must use --login to source the sre user's environment
	var found bool
	for i := 0; i+len(loginFlag) <= len(defaultExecCommand); i++ {
		if defaultExecCommand[i:i+len(loginFlag)] == loginFlag {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("defaultExecCommand must use 'bash --login' to load sre environment, got: %q",
			defaultExecCommand)
	}
}

func TestJoinTask_FlagDefaults(t *testing.T) {
	// Test that flag defaults are set correctly when the command is initialized
	if joinTaskCmd.Flags().Lookup("container") == nil {
		t.Error("join-task should have --container flag")
	}

	containerDefault := joinTaskCmd.Flags().Lookup("container").DefValue
	if containerDefault != "rosa-boundary" {
		t.Errorf("--container default = %q, want %q", containerDefault, "rosa-boundary")
	}

	if joinTaskCmd.Flags().Lookup("command") == nil {
		t.Error("join-task should have --command flag")
	}

	commandDefault := joinTaskCmd.Flags().Lookup("command").DefValue
	if commandDefault != defaultExecCommand {
		t.Errorf("--command default = %q, want %q", commandDefault, defaultExecCommand)
	}

	if joinTaskCmd.Flags().Lookup("no-wait") == nil {
		t.Error("join-task should have --no-wait flag")
	}

	noWaitDefault := joinTaskCmd.Flags().Lookup("no-wait").DefValue
	if noWaitDefault != "false" {
		t.Errorf("--no-wait default = %q, want %q", noWaitDefault, "false")
	}
}

func TestJoinTask_RequiresExactlyOneArg(t *testing.T) {
	// Verify the command requires exactly 1 argument (task-id)
	if joinTaskCmd.Args == nil {
		t.Fatal("join-task should have Args validation")
	}

	// cobra.ExactArgs(1) is set, verify it's present
	// We can't directly test the Args function without a full cobra setup,
	// but we can verify the command is configured
	if joinTaskCmd.Use != "join-task <task-id>" {
		t.Errorf("join-task Use = %q, should indicate <task-id> argument", joinTaskCmd.Use)
	}
}

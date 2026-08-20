package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestRequiresAuth(t *testing.T) {
	tests := []struct {
		name           string
		cmdName        string
		parentName     string
		expectedResult bool
	}{
		// Commands that should NOT require auth
		{"version command", "version", "", false},
		{"configure command", "configure", "", false},
		{"login command", "login", "", false},
		{"create-investigation command", "create-investigation", "", false},
		{"start-task command", "start-task", "", false},
		{"help command", "help", "", false},

		// Completion commands should NOT require auth
		{"completion command", "completion", "", false},
		{"completion bash", "bash", "completion", false},
		{"completion zsh", "zsh", "completion", false},
		{"completion fish", "fish", "completion", false},
		{"completion powershell", "powershell", "completion", false},
		{"__complete hidden command", "__complete", "", false},
		{"__completeNoDesc hidden command", "__completeNoDesc", "", false},

		// Commands that SHOULD require auth
		{"list-tasks command", "list-tasks", "", true},
		{"list-investigations command", "list-investigations", "", true},
		{"stop-task command", "stop-task", "", true},
		{"join-task command", "join-task", "", true},
		{"close-investigation command", "close-investigation", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{
				Use: tt.cmdName,
			}

			// Set up parent if specified
			if tt.parentName != "" {
				parent := &cobra.Command{
					Use: tt.parentName,
				}
				parent.AddCommand(cmd)
			}

			result := requiresAuth(cmd)
			if result != tt.expectedResult {
				t.Errorf("requiresAuth(%s) = %v, want %v", tt.cmdName, result, tt.expectedResult)
			}
		})
	}
}

func TestRequiresAuthCompletionRegression(t *testing.T) {
	// Regression test: Ensure completion commands don't trigger auth
	// This prevents users from needing OIDC tokens just to generate shell completions

	t.Run("completion bash does not require auth", func(t *testing.T) {
		bashCmd := &cobra.Command{Use: "bash"}
		completionCmd := &cobra.Command{Use: "completion"}
		completionCmd.AddCommand(bashCmd)

		if requiresAuth(bashCmd) {
			t.Error("completion bash should not require authentication")
		}
	})

	t.Run("__complete does not require auth", func(t *testing.T) {
		completeCmd := &cobra.Command{Use: "__complete"}
		if requiresAuth(completeCmd) {
			t.Error("__complete should not require authentication")
		}
	})

	t.Run("__completeNoDesc does not require auth", func(t *testing.T) {
		completeNoDescCmd := &cobra.Command{Use: "__completeNoDesc"}
		if requiresAuth(completeNoDescCmd) {
			t.Error("__completeNoDesc should not require authentication")
		}
	})
}

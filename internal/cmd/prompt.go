package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"

	"github.com/openshift-online/rosa-boundary/internal/output"
)

func promptDisplay(current, def string) string {
	if current != "" {
		return current
	}
	return def
}

// promptText formats a prompt label and its optional default value.
func promptText(label, display string) string {
	if display != "" {
		return fmt.Sprintf("%s [%s]: ", label, display)
	}
	return fmt.Sprintf("%s: ", label)
}

// promptValue trims user input and falls back to the displayed value when it is empty.
func promptValue(input, display string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return display
	}
	return input
}

// newPrompt returns a prompt function that reads from the given scanner. It
// is used for piped input, where terminal line editing is not available.
func newPrompt(scanner *bufio.Scanner) func(label, current, def string) (string, error) {
	return func(label, current, def string) (string, error) {
		display := promptDisplay(current, def)
		fmt.Fprint(os.Stderr, promptText(label, display))
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", err
			}
			return "", io.EOF
		}
		return promptValue(scanner.Text(), display), nil
	}
}

// readWriter combines the terminal input and output streams expected by term.Terminal.
type readWriter struct {
	io.Reader
	io.Writer
}

// newTerminalPrompt creates a line-editing prompt for an interactive terminal.
// term.Terminal handles Backspace, cursor movement, and other control keys after
// the terminal is placed in raw mode by newConfigurePrompt.
func newTerminalPrompt(terminal *term.Terminal) func(label, current, def string) (string, error) {
	return func(label, current, def string) (string, error) {
		display := promptDisplay(current, def)
		terminal.SetPrompt(promptText(label, display))
		input, err := terminal.ReadLine()
		if err != nil {
			return "", err
		}
		return promptValue(input, display), nil
	}
}

// newConfigurePrompt selects terminal line editing for a TTY and scanner input
// for pipes and tests. The returned restore function is safe to call repeatedly.
func newConfigurePrompt() (func(label, current, def string) (string, error), func(), error) {
	stdinFD := int(os.Stdin.Fd())
	stderrFD := int(os.Stderr.Fd())
	if !term.IsTerminal(stdinFD) || !term.IsTerminal(stderrFD) {
		return newPrompt(bufio.NewScanner(os.Stdin)), func() {}, nil
	}

	state, err := term.MakeRaw(stdinFD)
	if err != nil {
		return nil, nil, fmt.Errorf("could not enable terminal input: %w", err)
	}

	terminal := term.NewTerminal(readWriter{Reader: os.Stdin, Writer: os.Stderr}, "")
	var restoreOnce sync.Once
	restore := func() {
		restoreOnce.Do(func() {
			if err := term.Restore(stdinFD, state); err != nil {
				output.Warning("could not restore terminal input: %v", err)
			}
		})
	}

	return newTerminalPrompt(terminal), restore, nil
}

// DeriveInvokerRoleARN constructs the invoker role ARN from naming convention.
func DeriveInvokerRoleARN(accountID, project, environment string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s-%s-lambda-invoker", accountID, project, environment)
}

// DeriveLambdaFunctionName constructs the Lambda function name from naming convention.
func DeriveLambdaFunctionName(project, environment string) string {
	return fmt.Sprintf("%s-%s-create-investigation", project, environment)
}

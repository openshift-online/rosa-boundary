package cmd

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/spf13/cobra"
)

type mockSessionCloser struct {
	tasks   []awsclient.TaskSummary
	listErr error
	stopErr string
	waitErr bool
	events  []string
}

func (m *mockSessionCloser) ListRunningTasks(_ context.Context, status string) ([]awsclient.TaskSummary, error) {
	if status != "RUNNING" {
		panic(status)
	}
	return m.tasks, m.listErr
}
func (m *mockSessionCloser) StopTask(_ context.Context, id, reason string) error {
	m.events = append(m.events, "stop:"+id)
	if id == m.stopErr {
		return errors.New("denied")
	}
	return nil
}
func (m *mockSessionCloser) WaitForStopped(_ context.Context, id string) error {
	m.events = append(m.events, "wait:"+id)
	if m.waitErr {
		return errors.New("timeout")
	}
	return nil
}
func TestCloseAllSessions(t *testing.T) {
	oldYes, oldWait, oldReason := stopYes, stopWait, stopReason
	t.Cleanup(func() { stopYes, stopWait, stopReason = oldYes, oldWait, oldReason })
	task := func(id, owner, status, desired string) awsclient.TaskSummary {
		return awsclient.TaskSummary{TaskID: id, Status: status, DesiredStatus: desired, Tags: map[string]string{"oidc_sub": owner}}
	}
	tasks := []awsclient.TaskSummary{task("one", "me", "RUNNING", "RUNNING"), task("two", "me", "PENDING", "RUNNING"), task("other", "other", "RUNNING", "RUNNING"), task("unknown", "", "RUNNING", "RUNNING"), task("stopping", "me", "RUNNING", "STOPPED"), task("stopped", "me", "STOPPED", "STOPPED")}
	for _, tc := range []struct {
		name                 string
		yes, wait            bool
		input, subject, fail string
		listErr, waitErr     bool
		want                 []string
		wantErr              bool
	}{
		{name: "owned including pending", yes: true, wait: true, subject: "me", want: []string{"stop:one", "stop:two", "wait:one", "wait:two"}},
		{name: "no wait", yes: true, subject: "me", want: []string{"stop:one", "stop:two"}},
		{name: "confirmed", input: "y\n", subject: "me", want: []string{"stop:one", "stop:two"}},
		{name: "declined", input: "n\n", subject: "me", wantErr: true},
		{name: "empty", yes: true, subject: "nobody"},
		{name: "missing subject", yes: true, wantErr: true},
		{name: "list failure", yes: true, subject: "me", listErr: true, wantErr: true},
		{name: "partial failure continues", yes: true, wait: true, subject: "me", fail: "one", want: []string{"stop:one", "stop:two", "wait:two"}, wantErr: true},
		{name: "wait failure continues", yes: true, wait: true, subject: "me", waitErr: true, want: []string{"stop:one", "stop:two", "wait:one", "wait:two"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stopYes, stopWait = tc.yes, tc.wait
			oldTerminal := requireTerminal
			requireTerminal = func() error { return nil }
			defer func() { requireTerminal = oldTerminal }()
			cmd := &cobra.Command{}
			cmd.Flags().String("output", "json", "")
			cmd.SetIn(strings.NewReader(tc.input))
			var stdout bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&bytes.Buffer{})
			mock := &mockSessionCloser{tasks: tasks, stopErr: tc.fail, waitErr: tc.waitErr}
			if tc.listErr {
				mock.listErr = errors.New("list failed")
			}
			err := closeAllSessions(cmd, mock, tc.subject, "account", "region")
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v", err)
			}
			if !reflect.DeepEqual(mock.events, tc.want) {
				t.Fatalf("events=%v want=%v", mock.events, tc.want)
			}
			if err == nil {
				assertOneJSON(t, stdout.String(), map[string]any{"investigations_closed": false, "waited": tc.wait})
			} else if stdout.Len() != 0 {
				t.Fatal("success JSON on failure")
			}
		})
	}
}

func TestSessionUXFlagsBeforeAuthentication(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	old := requireTerminal
	requireTerminal = func() error { return errors.New("no terminal") }
	defer func() { requireTerminal = old }()
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"session", "create", "cluster"}, "--no-connect"},
		{[]string{"session", "create", "cluster", "--no-connect"}, "no active profile"},
		{[]string{"session", "create", "cluster", "--no-wait"}, "no active profile"},
		{[]string{"session", "create", "cluster", "--connect"}, "unknown flag"},
		{[]string{"session", "close", "--all"}, "--yes"},
		{[]string{"session", "close", "--all", "--yes"}, "no active profile"},
		{[]string{"session", "close", "task", "--all", "--yes"}, "cannot be combined"},
	} {
		_, err := runTestCLI(t, tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v want %s", tc.args, err, tc.want)
		}
	}
}

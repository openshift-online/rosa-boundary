package output

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestDebugWritesVerboseMessage(t *testing.T) {
	oldVerbose := Verbose
	oldStderr := os.Stderr
	t.Cleanup(func() {
		Verbose = oldVerbose
		os.Stderr = oldStderr
	})

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stderr = writer
	Verbose = true

	if err := Debug("hello %s", "world"); err != nil {
		t.Fatalf("Debug() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("closing captured stderr writer: %v", err)
	}

	var output bytes.Buffer
	if _, err := io.Copy(&output, reader); err != nil {
		t.Fatalf("reading captured stderr: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("closing captured stderr reader: %v", err)
	}

	if got, want := output.String(), "[debug] hello world\n"; got != want {
		t.Errorf("Debug() output = %q, want %q", got, want)
	}
}

func TestDebugPropagatesWriteError(t *testing.T) {
	oldVerbose := Verbose
	oldStderr := os.Stderr
	t.Cleanup(func() {
		Verbose = oldVerbose
		os.Stderr = oldStderr
	})

	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatalf("os.CreateTemp() error = %v", err)
	}
	if err := stderrFile.Close(); err != nil {
		t.Fatalf("closing stderr file: %v", err)
	}
	os.Stderr = stderrFile
	Verbose = true

	if err := Debug("hello"); err == nil {
		t.Error("Debug() error = nil, want write error")
	}
}

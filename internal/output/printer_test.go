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

func TestDebugDoesNotWriteWithoutVerbose(t *testing.T) {
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
	os.Stderr = stderrFile
	Verbose = false

	if err := Debug("hidden message"); err != nil {
		t.Fatalf("Debug() error = %v", err)
	}
	if err := stderrFile.Close(); err != nil {
		t.Fatalf("closing captured stderr: %v", err)
	}

	contents, err := os.ReadFile(stderrFile.Name())
	if err != nil {
		t.Fatalf("reading captured stderr: %v", err)
	}
	if got := string(contents); got != "" {
		t.Errorf("Debug() output = %q, want no output", got)
	}
}

func TestWarningWritesWithoutVerbose(t *testing.T) {
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
	Verbose = false

	Warning("cache is unavailable: %s", "permission denied")
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

	if got, want := output.String(), "Warning: cache is unavailable: permission denied\n"; got != want {
		t.Errorf("Warning() output = %q, want %q", got, want)
	}
}

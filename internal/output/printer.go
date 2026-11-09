package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrJSONWrite distinguishes a failed result write from a command failure.
// In particular, callers must not append an error document to a partially
// written JSON result.
var ErrJSONWrite = errors.New("JSON result write failed")

// Status writes a status message to stderr.
func Status(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// Statusf writes a formatted status message to stderr without a trailing newline.
func Statusf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
}

// Warning writes a warning message to stderr.
func Warning(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Warning: "+format+"\n", args...)
}

// Verbose controls whether debug messages are printed.
var Verbose bool

// Debug writes a debug message to stderr if Verbose is true.
func Debug(format string, args ...any) error {
	if !Verbose {
		return nil
	}

	_, err := fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	return err
}

// Fatal writes an error message to stderr and exits with code 1.
func Fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}

// Data writes data to stdout.
func Data(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}

// JSON marshals v as indented JSON and writes it to stdout.
func JSON(v any) error {
	return JSONTo(os.Stdout, v)
}

// JSONTo marshals v as indented JSON and writes it to w.
func JSONTo(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("%w: %w", ErrJSONWrite, err)
	}
	return nil
}

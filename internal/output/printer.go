package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Status writes a status message to stderr.
func Status(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// Statusf writes a formatted status message to stderr without a trailing newline.
func Statusf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
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

// DebugNonFatal writes a debug message and reports write failures without
// making the operation that emitted the message fail.
func DebugNonFatal(format string, args ...any) {
	if err := Debug(format, args...); err != nil {
		Status("Warning: debug output failed: %v", err)
	}
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
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// JSONTo marshals v as indented JSON and writes it to w.
func JSONTo(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

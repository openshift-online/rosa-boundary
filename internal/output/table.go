package output

import (
	"io"
	"os"
	"strings"
	"text/tabwriter"
)

// Table renders a simple tabwriter-based table to stdout.
type Table struct {
	w       *tabwriter.Writer
	headers []string
}

// NewTable creates a new Table that writes to stdout.
func NewTable(headers ...string) *Table {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	return &Table{w: w, headers: headers}
}

// NewTableTo creates a new Table that writes to the given writer.
func NewTableTo(out io.Writer, headers ...string) *Table {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	return &Table{w: w, headers: headers}
}

// PrintHeader writes the header row and a separator.
func (t *Table) PrintHeader() {
	_, _ = io.WriteString(t.w, strings.Join(t.headers, "\t")+"\n")
	seps := make([]string, len(t.headers))
	for i, h := range t.headers {
		seps[i] = strings.Repeat("-", len(h))
	}
	_, _ = io.WriteString(t.w, strings.Join(seps, "\t")+"\n")
}

// PrintRow writes a data row to the table. Values are joined with tabs.
func (t *Table) PrintRow(values ...string) {
	_, _ = io.WriteString(t.w, strings.Join(values, "\t")+"\n")
}

// Flush flushes the tabwriter buffer. Must be called after all rows are added.
func (t *Table) Flush() {
	_ = t.w.Flush()
}

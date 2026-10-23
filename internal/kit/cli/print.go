package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
)

type Table struct {
	Columns []string
	Rows    [][]string
}

func JSONFlag(fs *flag.FlagSet) {
	fs.Bool("json", false, "print JSON instead of a table")
}

func WantsJSON(fs *flag.FlagSet) bool {
	f := fs.Lookup("json")
	return f != nil && f.Value.String() == "true"
}

func Print(w io.Writer, asJSON bool, t Table) error {
	for i, row := range t.Rows {
		if len(row) > len(t.Columns) {
			return fmt.Errorf("print: row %d has %d cells for %d columns", i, len(row), len(t.Columns))
		}
	}
	if asJSON {
		return printJSON(w, t)
	}
	return printText(w, t)
}

func printJSON(w io.Writer, t Table) error {
	var buf bytes.Buffer
	buf.WriteString("[")
	for i, row := range t.Rows {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString("\n  {")
		for j, col := range t.Columns {
			if j > 0 {
				buf.WriteString(", ")
			}
			key, err := json.Marshal(col)
			if err != nil {
				return fmt.Errorf("print: encode column: %w", err)
			}
			var cell string
			if j < len(row) {
				cell = row[j]
			}
			val, err := json.Marshal(cell)
			if err != nil {
				return fmt.Errorf("print: encode cell: %w", err)
			}
			buf.Write(key)
			buf.WriteString(": ")
			buf.Write(val)
		}
		buf.WriteString("}")
	}
	if len(t.Rows) > 0 {
		buf.WriteString("\n")
	}
	buf.WriteString("]\n")
	if _, err := w.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("print: %w", err)
	}
	return nil
}

func printText(w io.Writer, t Table) error {
	widths := make([]int, len(t.Columns))
	for i, c := range t.Columns {
		widths[i] = len(c)
	}
	for _, row := range t.Rows {
		for i, cell := range row {
			widths[i] = max(widths[i], len(cell))
		}
	}

	var b strings.Builder
	line := func(cells []string) {
		for i := range t.Columns {
			var cell string
			if i < len(cells) {
				cell = cells[i]
			}
			if i == len(t.Columns)-1 {
				b.WriteString(cell)
				continue
			}
			fmt.Fprintf(&b, "%-*s  ", widths[i], cell)
		}
		b.WriteString("\n")
	}
	line(t.Columns)
	for _, row := range t.Rows {
		line(row)
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("print: %w", err)
	}
	return nil
}

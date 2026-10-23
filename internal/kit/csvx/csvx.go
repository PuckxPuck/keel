// Package csvx writes CSV that spreadsheets open safely and reads CSV within size limits.
package csvx

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shopspring/decimal"

	"github.com/PuckxPuck/keel/internal/kit/dates"
)

var bom = []byte{0xEF, 0xBB, 0xBF}

// Number is a numeric cell written as is. A value that does not look like a number is neutralised like text.
type Number string

var numberPattern = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`)

// Neutralise prefixes a value a spreadsheet would read as a formula with a single quote (OWASP CSV injection),
// including the full-width and small forms some spreadsheets normalise.
func Neutralise(s string) string {
	r, _ := utf8.DecodeRuneInString(s)
	switch r {
	case '=', '+', '-', '@', '\t', '\r', '\n', '＝', '＋', '－', '＠', '\uFE62', '\uFE63', '\uFE66', '\uFE6B':
		return "'" + s
	}
	return s
}

// Writer writes UTF-8 with a BOM (so Excel detects the encoding), CRLF line ends and every field quoted.
type Writer struct {
	w      *bufio.Writer
	fields int
}

// NewWriter writes the BOM and the header row. Call Flush when done.
func NewWriter(w io.Writer, header ...string) (*Writer, error) {
	cw := &Writer{w: bufio.NewWriter(w), fields: len(header)}
	if _, err := cw.w.Write(bom); err != nil {
		return nil, err
	}
	if len(header) > 0 {
		cells := make([]any, len(header))
		for i, h := range header {
			cells[i] = h
		}
		if err := cw.Write(cells...); err != nil {
			return nil, err
		}
	}
	return cw, nil
}

// Write writes one row. Cells are strings (neutralised), Number, integers, decimal.Decimal, dates.Date
// or time.Time (RFC 3339 in UTC); nil is an empty cell.
func (cw *Writer) Write(cells ...any) error {
	if cw.fields > 0 && len(cells) != cw.fields {
		return fmt.Errorf("csvx: row has %d cells, header has %d", len(cells), cw.fields)
	}
	for i, c := range cells {
		s, err := text(c)
		if err != nil {
			return err
		}
		if i > 0 {
			if err := cw.w.WriteByte(','); err != nil {
				return err
			}
		}
		if err := cw.quoted(s); err != nil {
			return err
		}
	}
	_, err := cw.w.WriteString("\r\n")
	return err
}

func (cw *Writer) quoted(s string) error {
	if err := cw.w.WriteByte('"'); err != nil {
		return err
	}
	if _, err := cw.w.WriteString(strings.ReplaceAll(s, `"`, `""`)); err != nil {
		return err
	}
	return cw.w.WriteByte('"')
}

func (cw *Writer) Flush() error { return cw.w.Flush() }

func text(c any) (string, error) {
	switch v := c.(type) {
	case nil:
		return "", nil
	case string:
		return Neutralise(v), nil
	case Number:
		if numberPattern.MatchString(string(v)) {
			return string(v), nil
		}
		return Neutralise(string(v)), nil
	case int:
		return strconv.Itoa(v), nil
	case int32:
		return strconv.FormatInt(int64(v), 10), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case decimal.Decimal:
		return v.String(), nil
	case dates.Date:
		return v.String(), nil
	case time.Time:
		return v.UTC().Format(time.RFC3339), nil
	}
	return "", fmt.Errorf("csvx: cannot write a %T", c)
}

// Limits bound what a Reader accepts; zero fields take the defaults.
type Limits struct {
	MaxRowBytes   int // default 64 KiB
	MaxFieldBytes int // default 32 KiB
	MaxFields     int // default 256
	MaxRows       int // default 100000
}

func (l Limits) withDefaults() Limits {
	if l.MaxRowBytes <= 0 {
		l.MaxRowBytes = 64 << 10
	}
	if l.MaxFieldBytes <= 0 {
		l.MaxFieldBytes = 32 << 10
	}
	if l.MaxFields <= 0 {
		l.MaxFields = 256
	}
	if l.MaxRows <= 0 {
		l.MaxRows = 100000
	}
	return l
}

var (
	ErrRowTooLarge   = errors.New("csvx: row is too large")
	ErrFieldTooLarge = errors.New("csvx: field is too large")
	ErrTooManyFields = errors.New("csvx: row has too many fields")
	ErrTooManyRows   = errors.New("csvx: too many rows")
)

// Reader reads records, stripping a leading BOM, and refuses rows past the limits before buffering them.
type Reader struct {
	cr     *csv.Reader
	guard  *guard
	limits Limits
	rows   int
}

// guard stops the underlying reads once a record runs past its size limit, so a single huge record
// cannot grow csv.Reader's buffer without bound.
type guard struct {
	r     io.Reader
	read  int64
	limit int64
}

// csvReadAhead covers the bufio buffer csv.Reader reads through.
const csvReadAhead = 4096

func (g *guard) Read(p []byte) (int, error) {
	if g.read >= g.limit {
		return 0, ErrRowTooLarge
	}
	if room := g.limit - g.read; int64(len(p)) > room {
		p = p[:room]
	}
	n, err := g.r.Read(p)
	g.read += int64(n)
	return n, err
}

func NewReader(r io.Reader, limits Limits) (*Reader, error) {
	limits = limits.withDefaults()
	br := bufio.NewReader(r)
	if head, err := br.Peek(len(bom)); err == nil && bytes.Equal(head, bom) {
		_, _ = br.Discard(len(bom)) // cannot fail after a successful Peek
	}
	g := &guard{r: br, limit: int64(limits.MaxRowBytes) + csvReadAhead}
	cr := csv.NewReader(g)
	cr.FieldsPerRecord = -1
	return &Reader{cr: cr, guard: g, limits: limits}, nil
}

// Read returns the next record, or io.EOF after the last.
func (r *Reader) Read() ([]string, error) {
	if r.rows >= r.limits.MaxRows {
		if _, err := r.cr.Read(); errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, ErrTooManyRows
	}
	start := r.cr.InputOffset()
	rec, err := r.cr.Read()
	if err != nil {
		if errors.Is(err, ErrRowTooLarge) {
			return nil, ErrRowTooLarge
		}
		return nil, err
	}
	end := r.cr.InputOffset()
	r.guard.limit = end + int64(r.limits.MaxRowBytes) + csvReadAhead
	if end-start > int64(r.limits.MaxRowBytes) {
		return nil, ErrRowTooLarge
	}
	if len(rec) > r.limits.MaxFields {
		return nil, ErrTooManyFields
	}
	for _, f := range rec {
		if len(f) > r.limits.MaxFieldBytes {
			return nil, ErrFieldTooLarge
		}
	}
	r.rows++
	return rec, nil
}

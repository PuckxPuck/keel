// Package xlsx reads spreadsheets within limits and writes them as streams, over excelize.
package xlsx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/shopspring/decimal"
	"github.com/xuri/excelize/v2"

	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/csvx"
	"github.com/PuckxPuck/keel/internal/kit/dates"
)

// Config is the xlsx part of an app's configuration; field tags follow kit/config.
type Config struct {
	MaxBytes config.ByteSize `env:"MAX_BYTES" envDefault:"20MiB"`
	MaxRows  int             `env:"MAX_ROWS" envDefault:"100000"`
	MaxCells int             `env:"MAX_CELLS" envDefault:"2000000"`
}

func (c Config) Validate(bool) error {
	if c.MaxBytes <= 0 || c.MaxRows <= 0 || c.MaxCells <= 0 {
		return errors.New("max bytes, rows and cells must be positive")
	}
	return nil
}

func (c Config) Limits() Limits {
	return Limits{MaxBytes: int64(c.MaxBytes), MaxRows: c.MaxRows, MaxCells: c.MaxCells}
}

// Limits bound what a Reader accepts; zero fields take the defaults. Rows and cells count across the workbook.
type Limits struct {
	MaxBytes         int64 // default 20 MiB
	MaxSheets        int   // default 32
	MaxRows          int   // default 100000
	MaxCells         int   // default 2000000
	MaxUnzippedBytes int64 // default 16 times MaxBytes
}

func (l Limits) withDefaults() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = 20 << 20
	}
	if l.MaxSheets <= 0 {
		l.MaxSheets = 32
	}
	if l.MaxRows <= 0 {
		l.MaxRows = 100000
	}
	if l.MaxCells <= 0 {
		l.MaxCells = 2000000
	}
	if l.MaxUnzippedBytes <= 0 {
		l.MaxUnzippedBytes = 16 * l.MaxBytes
	}
	return l
}

var (
	ErrTooLarge      = errors.New("xlsx: workbook is too large")
	ErrTooManySheets = errors.New("xlsx: workbook has too many sheets")
	ErrTooManyRows   = errors.New("xlsx: workbook has too many rows")
	ErrTooManyCells  = errors.New("xlsx: workbook has too many cells")
	ErrInvalid       = errors.New("xlsx: not a readable workbook")
	ErrCell          = errors.New("xlsx: cell does not hold that type")
)

type Reader struct {
	f      *excelize.File
	limits Limits
	rows   int
	cells  int
}

// NewReader reads at most MaxBytes (excelize keeps the whole archive in memory) and opens the workbook.
func NewReader(r io.Reader, limits Limits) (*Reader, error) {
	limits = limits.withDefaults()
	data, err := io.ReadAll(io.LimitReader(r, limits.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limits.MaxBytes {
		return nil, ErrTooLarge
	}
	f, err := excelize.OpenReader(bytes.NewReader(data), excelize.Options{
		RawCellValue:      true,
		UnzipSizeLimit:    limits.MaxUnzippedBytes,
		UnzipXMLSizeLimit: min(limits.MaxUnzippedBytes, 16<<20),
	})
	if err != nil {
		if strings.Contains(err.Error(), "unzip size") { // excelize exports no error value for this
			return nil, ErrTooLarge
		}
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if len(f.GetSheetList()) > limits.MaxSheets {
		_ = f.Close() // refused before any read
		return nil, ErrTooManySheets
	}
	return &Reader{f: f, limits: limits}, nil
}

func (r *Reader) Close() error { return r.f.Close() }

func (r *Reader) Sheets() []string { return r.f.GetSheetList() }

// Rows streams a sheet's rows; empty rows come back with no cells.
func (r *Reader) Rows(sheet string) (*Rows, error) {
	it, err := r.f.Rows(sheet)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return &Rows{r: r, it: it}, nil
}

type Rows struct {
	r   *Reader
	it  *excelize.Rows
	cur Row
	err error
}

func (rs *Rows) Next() bool {
	if rs.err != nil || !rs.it.Next() {
		return false
	}
	rs.r.rows++
	if rs.r.rows > rs.r.limits.MaxRows {
		rs.err = ErrTooManyRows
		return false
	}
	cells, err := rs.it.Columns()
	if err != nil {
		rs.err = fmt.Errorf("%w: %w", ErrInvalid, err)
		return false
	}
	rs.r.cells += len(cells)
	if rs.r.cells > rs.r.limits.MaxCells {
		rs.err = ErrTooManyCells
		return false
	}
	rs.cur = Row{cells: cells, num: rs.cur.num + 1}
	return true
}

func (rs *Rows) Row() Row { return rs.cur }

func (rs *Rows) Err() error {
	if rs.err != nil {
		return rs.err
	}
	return rs.it.Error()
}

func (rs *Rows) Close() error { return rs.it.Close() }

// Row is one row's raw cell values; dates are spreadsheet serial numbers until read with Date.
type Row struct {
	cells []string
	num   int
}

func (r Row) Len() int { return len(r.cells) }

// Number is the row's position among the rows read from its sheet, from 1.
func (r Row) Number() int { return r.num }

// String is the cell's text, empty past the row's last cell.
func (r Row) String(i int) string {
	if i < 0 || i >= len(r.cells) {
		return ""
	}
	return strings.TrimSpace(r.cells[i])
}

func (r Row) Int(i int) (int64, error) {
	s := r.String(i)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	d, err := decimal.NewFromString(s)
	if err != nil || !d.IsInteger() || !d.Abs().LessThanOrEqual(decimal.NewFromInt(1<<53)) {
		return 0, fmt.Errorf("%w: row %d column %d is not a whole number", ErrCell, r.num, i+1)
	}
	return d.IntPart(), nil
}

func (r Row) Decimal(i int) (decimal.Decimal, error) {
	d, err := decimal.NewFromString(r.String(i))
	if err != nil {
		return decimal.Decimal{}, fmt.Errorf("%w: row %d column %d is not a number", ErrCell, r.num, i+1)
	}
	return d, nil
}

func (r Row) Bool(i int) (bool, error) {
	switch strings.ToLower(r.String(i)) {
	case "1", "true", "yes":
		return true, nil
	case "0", "false", "no":
		return false, nil
	}
	return false, fmt.Errorf("%w: row %d column %d is not true or false", ErrCell, r.num, i+1)
}

// Date reads a date cell (a serial number) or an ISO date written as text.
func (r Row) Date(i int) (dates.Date, error) {
	s := r.String(i)
	if serial, err := strconv.ParseFloat(s, 64); err == nil && serial >= 1 && serial < 2958466 {
		t, err := excelize.ExcelDateToTime(serial, false)
		if err == nil {
			return dates.FromTime(t), nil
		}
	}
	d, err := dates.Parse(s)
	if err != nil {
		return dates.Date{}, fmt.Errorf("%w: row %d column %d is not a date", ErrCell, r.num, i+1)
	}
	return d, nil
}

// Writer streams rows into sheets and writes the workbook on Close.
type Writer struct {
	out       io.Writer
	f         *excelize.File
	sw        *excelize.StreamWriter
	row       int
	sheets    int
	dateStyle int
	timeStyle int
}

func NewWriter(out io.Writer) (*Writer, error) {
	f := excelize.NewFile()
	date, err := f.NewStyle(&excelize.Style{CustomNumFmt: strPtr("yyyy-mm-dd")})
	if err != nil {
		return nil, err
	}
	stamp, err := f.NewStyle(&excelize.Style{CustomNumFmt: strPtr("yyyy-mm-dd hh:mm:ss")})
	if err != nil {
		return nil, err
	}
	return &Writer{out: out, f: f, dateStyle: date, timeStyle: stamp}, nil
}

func strPtr(s string) *string { return &s }

// Sheet starts a new sheet; rows written next go to it.
func (w *Writer) Sheet(name string) error {
	if err := w.flush(); err != nil {
		return err
	}
	if w.sheets == 0 {
		if err := w.f.SetSheetName("Sheet1", name); err != nil {
			return err
		}
	} else if _, err := w.f.NewSheet(name); err != nil {
		return err
	}
	w.sheets++
	sw, err := w.f.NewStreamWriter(name)
	if err != nil {
		return err
	}
	w.sw, w.row = sw, 0
	return nil
}

// Row writes one row. Cells are strings (formula-like text neutralised as in csvx), csvx.Number, integers,
// decimal.Decimal, bool, dates.Date or time.Time (UTC); nil is an empty cell.
func (w *Writer) Row(cells ...any) error {
	if w.sw == nil {
		if err := w.Sheet("Sheet1"); err != nil {
			return err
		}
	}
	values := make([]any, len(cells))
	for i, c := range cells {
		v, err := w.cell(c)
		if err != nil {
			return err
		}
		values[i] = v
	}
	w.row++
	ref, err := excelize.CoordinatesToCellName(1, w.row)
	if err != nil {
		return err
	}
	return w.sw.SetRow(ref, values)
}

func (w *Writer) cell(c any) (any, error) {
	switch v := c.(type) {
	case nil:
		return nil, nil
	case string:
		return csvx.Neutralise(v), nil
	case csvx.Number:
		d, err := decimal.NewFromString(string(v))
		if err != nil {
			return csvx.Neutralise(string(v)), nil //nolint:nilerr // text that is not a number is written as neutralised text
		}
		return d.InexactFloat64(), nil
	case int:
		return v, nil
	case int64:
		return v, nil
	case int32:
		return v, nil
	case bool:
		return v, nil
	case decimal.Decimal:
		return v.InexactFloat64(), nil
	case dates.Date:
		return excelize.Cell{StyleID: w.dateStyle, Value: time.Date(v.Year, v.Month, v.Day, 0, 0, 0, 0, time.UTC)}, nil
	case time.Time:
		return excelize.Cell{StyleID: w.timeStyle, Value: v.UTC()}, nil
	}
	return nil, fmt.Errorf("xlsx: cannot write a %T", c)
}

func (w *Writer) flush() error {
	if w.sw == nil {
		return nil
	}
	err := w.sw.Flush()
	w.sw = nil
	return err
}

// Close writes the workbook to out.
func (w *Writer) Close() error {
	err := w.flush()
	if err == nil {
		_, err = w.f.WriteTo(w.out)
	}
	return errors.Join(err, w.f.Close())
}

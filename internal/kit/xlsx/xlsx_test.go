package xlsx_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/csvx"
	"github.com/PuckxPuck/keel/internal/kit/dates"
	"github.com/PuckxPuck/keel/internal/kit/xlsx"
)

func workbook(t testing.TB, sheets, rows, cols int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := xlsx.NewWriter(&buf)
	require.NoError(t, err)
	for s := range sheets {
		require.NoError(t, w.Sheet("S"+string(rune('A'+s))))
		for range rows {
			cells := make([]any, cols)
			for c := range cells {
				cells[c] = c
			}
			require.NoError(t, w.Row(cells...))
		}
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func readAll(data []byte, limits xlsx.Limits) error {
	r, err := xlsx.NewReader(bytes.NewReader(data), limits)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	for _, sheet := range r.Sheets() {
		rows, err := r.Rows(sheet)
		if err != nil {
			return err
		}
		for rows.Next() {
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func TestReader_Limits(t *testing.T) {
	book := workbook(t, 3, 10, 4)
	cases := []struct {
		name   string
		limits xlsx.Limits
		want   error
	}{
		{"within limits", xlsx.Limits{MaxSheets: 3, MaxRows: 30, MaxCells: 120}, nil},
		{"bytes", xlsx.Limits{MaxBytes: int64(len(book) - 1)}, xlsx.ErrTooLarge},
		{"sheets", xlsx.Limits{MaxSheets: 2}, xlsx.ErrTooManySheets},
		{"rows across sheets", xlsx.Limits{MaxRows: 25}, xlsx.ErrTooManyRows},
		{"cells across sheets", xlsx.Limits{MaxCells: 100}, xlsx.ErrTooManyCells},
		{"unzipped size", xlsx.Limits{MaxUnzippedBytes: 1024}, xlsx.ErrTooLarge},
		{"not a workbook", xlsx.Limits{}, xlsx.ErrInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := book
			if errors.Is(c.want, xlsx.ErrInvalid) {
				data = []byte("PK\x03\x04 not really")
			}
			err := readAll(data, c.limits)
			if c.want == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, c.want)
		})
	}
}

func TestWriter_TypedCellsAndNeutralisedText(t *testing.T) {
	var buf bytes.Buffer
	w, err := xlsx.NewWriter(&buf)
	require.NoError(t, err)
	require.NoError(t, w.Sheet("Export"))
	due := dates.MustParse("2026-10-22")
	require.NoError(t, w.Row("=HYPERLINK(\"x\")", csvx.Number("-12.50"), decimal.RequireFromString("3.25"), 42, true, due))
	require.NoError(t, w.Close())

	r, err := xlsx.NewReader(&buf, xlsx.Limits{})
	require.NoError(t, err)
	defer func() { _ = r.Close() }()
	require.Equal(t, []string{"Export"}, r.Sheets())
	rows, err := r.Rows("Export")
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	require.True(t, rows.Next())
	row := rows.Row()
	assert.Equal(t, `'=HYPERLINK("x")`, row.String(0))
	n, err := row.Decimal(1)
	require.NoError(t, err)
	assert.True(t, n.Equal(decimal.RequireFromString("-12.5")))
	d, err := row.Decimal(2)
	require.NoError(t, err)
	assert.True(t, d.Equal(decimal.RequireFromString("3.25")))
	i, err := row.Int(3)
	require.NoError(t, err)
	assert.Equal(t, int64(42), i)
	b, err := row.Bool(4)
	require.NoError(t, err)
	assert.True(t, b)
	got, err := row.Date(5)
	require.NoError(t, err)
	assert.Equal(t, due, got)
	_, err = row.Int(0)
	require.ErrorIs(t, err, xlsx.ErrCell)
	require.NoError(t, rows.Err())
}

func FuzzReader(f *testing.F) {
	f.Add(workbook(f, 1, 2, 2))
	f.Add([]byte("PK\x03\x04"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = readAll(data, xlsx.Limits{MaxBytes: 1 << 20, MaxRows: 100, MaxCells: 1000}) // only panics and hangs matter here
	})
}

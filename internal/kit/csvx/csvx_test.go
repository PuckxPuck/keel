package csvx_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/csvx"
)

func TestWriter_NeutralisesFormulas(t *testing.T) {
	cases := []struct {
		name string
		cell any
		want string
	}{
		{"equals", "=1+2", `"'=1+2"`},
		{"plus", "+1", `"'+1"`},
		{"minus text", "-cmd", `"'-cmd"`},
		{"at", "@SUM(A1)", `"'@SUM(A1)"`},
		{"tab", "\tx", "\"'\tx\""},
		{"carriage return", "\rx", "\"'\rx\""},
		{"full-width equals", "＝1+2", "\"'＝1+2\""},
		{"full-width plus", "＋1", "\"'＋1\""},
		{"full-width minus", "－1", "\"'－1\""},
		{"full-width at", "＠x", "\"'＠x\""},
		{"small-form equals", "\uFE661+2", "\"'\uFE661+2\""},
		{"small-form at", "\uFE6Bx", "\"'\uFE6Bx\""},
		{"plain text", "hello", `"hello"`},
		{"quote doubled", `say "hi"`, `"say ""hi"""`},
		{"negative Number", csvx.Number("-12.50"), `"-12.50"`},
		{"Number that is a formula", csvx.Number("=1+2"), `"'=1+2"`},
		{"decimal", decimal.RequireFromString("-3.25"), `"-3.25"`},
		{"int", -7, `"-7"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			w, err := csvx.NewWriter(&buf)
			require.NoError(t, err)
			require.NoError(t, w.Write(c.cell))
			require.NoError(t, w.Flush())
			assert.Equal(t, "\xEF\xBB\xBF"+c.want+"\r\n", buf.String())
		})
	}
}

func TestReader_StripsBOMAndRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	w, err := csvx.NewWriter(&buf, "name", "note")
	require.NoError(t, err)
	require.NoError(t, w.Write("a", "line\r\nbreak"))
	require.NoError(t, w.Flush())

	r, err := csvx.NewReader(&buf, csvx.Limits{})
	require.NoError(t, err)
	header, err := r.Read()
	require.NoError(t, err)
	assert.Equal(t, []string{"name", "note"}, header)
	row, err := r.Read()
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "line\nbreak"}, row)
	_, err = r.Read()
	assert.ErrorIs(t, err, io.EOF)
}

// endless never ends a record, so only the limit can stop the reader.
type endless struct{ read int }

func (e *endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	e.read += len(p)
	return len(p), nil
}

func TestReader_Limits(t *testing.T) {
	limits := csvx.Limits{MaxRowBytes: 1024, MaxFieldBytes: 16, MaxFields: 3, MaxRows: 2}
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"field too large", strings.Repeat("y", 17) + "\n", csvx.ErrFieldTooLarge},
		{"too many fields", "a,b,c,d\n", csvx.ErrTooManyFields},
		{"too many rows", "a\nb\nc\n", csvx.ErrTooManyRows},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := csvx.NewReader(strings.NewReader(c.in), limits)
			require.NoError(t, err)
			var last error
			for last == nil {
				_, last = r.Read()
			}
			assert.ErrorIs(t, last, c.want)
		})
	}

	t.Run("row too large stops reading", func(t *testing.T) {
		src := &endless{}
		r, err := csvx.NewReader(src, limits)
		require.NoError(t, err)
		_, err = r.Read()
		require.ErrorIs(t, err, csvx.ErrRowTooLarge)
		assert.Less(t, src.read, 64<<10, "the reader buffered far past the row limit")
	})
}

func FuzzReader(f *testing.F) {
	f.Add([]byte("\xEF\xBB\xBFa,b\r\n\"c\"\"\",d\r\n"))
	f.Add([]byte("\"unterminated\n"))
	f.Add([]byte(strings.Repeat("x,", 300)))
	f.Fuzz(func(t *testing.T, in []byte) {
		r, err := csvx.NewReader(bytes.NewReader(in), csvx.Limits{MaxRowBytes: 512, MaxFieldBytes: 128, MaxFields: 16, MaxRows: 64})
		require.NoError(t, err)
		for range 100 {
			rec, err := r.Read()
			if err != nil {
				return
			}
			require.LessOrEqual(t, len(rec), 16)
		}
	})
}

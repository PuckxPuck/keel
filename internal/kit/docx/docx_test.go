package docx_test

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/docx"
)

func TestWrite_ProducesAValidSafeDocument(t *testing.T) {
	d := docx.New(docx.Styles{Font: "Inter", HeadingColor: "1F3864", A4: true})
	d.TableOfContents("Contents")
	d.Heading(1, "Report <Q3> & more")
	d.Paragraph(docx.Run{Text: "Bold ", Bold: true}, docx.Run{Text: "and italic\x01 text", Italic: true})
	d.List(false, "one", "two")
	d.List(true, "first", "second")
	d.PageBreak()
	d.Heading(2, "Figures")
	d.Table([]string{"Item", "Qty"}, [][]string{{"Widget", "3"}, {"Gadget"}})
	var buf bytes.Buffer
	require.NoError(t, d.Write(&buf))
	data := buf.Bytes()

	require.NoError(t, docx.Validate(bytes.NewReader(data), int64(len(data))))
	doc := part(t, data, "word/document.xml")
	assert.Contains(t, doc, "Report &lt;Q3&gt; &amp; more")
	assert.NotContains(t, doc, "\x01")
	assert.Contains(t, doc, `w:numId w:val="2"`)
}

func TestValidate_RefusesBrokenStructure(t *testing.T) {
	var buf bytes.Buffer
	d := docx.New(docx.Styles{})
	d.Text("x")
	require.NoError(t, d.Write(&buf))
	broken := rewrite(t, buf.Bytes(), "word/document.xml", func(s string) string {
		return strings.Replace(s, "<w:p>", `<w:p><w:pPr><w:pStyle w:val="Missing"/></w:pPr>`, 1)
	})
	err := docx.Validate(bytes.NewReader(broken), int64(len(broken)))
	assert.ErrorIs(t, err, docx.ErrInvalid)
}

func part(t *testing.T, data []byte, name string) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	f, err := zr.Open(name)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	require.NoError(t, err)
	return string(b)
}

func rewrite(t *testing.T, data []byte, name string, fn func(string) string) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, f := range zr.File {
		body := part(t, data, f.Name)
		if f.Name == name {
			body = fn(body)
		}
		w, err := zw.Create(f.Name)
		require.NoError(t, err)
		_, err = io.WriteString(w, body)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return out.Bytes()
}

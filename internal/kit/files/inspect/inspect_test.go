package inspect_test

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/color/palette"
	"image/gif"
	"image/jpeg"
	"image/png"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/files/inspect"
)

var testLimits = inspect.Limits{
	MaxEntries: 20, MaxDecoded: 1 << 20, MaxNestedBytes: 256 << 10, MaxPixels: 4_000_000, MaxDimension: 4000, MaxImageBytes: 1 << 20,
}

type entry struct {
	name string
	data []byte
}

func zipOf(t testing.TB, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		require.NoError(t, err)
		_, err = w.Write(e.data)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

const (
	contentTypes = `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`
	macroContentTypes = `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>`
	document = `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>`
)

func rels(rel string) []byte {
	return []byte(`<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + rel + `</Relationships>`)
}

func docx(t testing.TB, extra ...entry) []byte {
	t.Helper()
	base := []entry{{"[Content_Types].xml", []byte(contentTypes)}, {"word/document.xml", []byte(document)}}
	return zipOf(t, append(base, extra...)...)
}

func flate(t testing.TB, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, err := zw.Write(data)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func pdfWith(body string) []byte {
	return []byte("%PDF-1.7\n1 0 obj\n<< /Type /Catalog " + body + " >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n")
}

func pdfStream(dict string, data []byte) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n2 0 obj\n<< " + dict + " >>\nstream\n")
	b.Write(data)
	b.WriteString("\nendstream\nendobj\n%%EOF\n")
	return b.Bytes()
}

// objStm is the dictionary pdf.js parses as an object stream, whatever its /Type says.
const objStm = "/Type /ObjStm /N 1 /First 4 "

// jsPayload is large enough that zlib codes the name instead of storing it.
var jsPayload = []byte(strings.Repeat("<< /Type /Annot /Rect [0 0 10 10] >> ", 40) + "<< /S /JavaScript /JS (app.alert(1)) >>")

// pngSub applies the PNG Sub predictor, one byte per pixel, as a PDF writer does.
func pngSub(data []byte, columns int) []byte {
	var out []byte
	for len(data) > 0 {
		row := data[:min(columns, len(data))]
		data = data[len(row):]
		out = append(out, 1)
		for i := range row {
			var left byte
			if i > 0 {
				left = row[i-1]
			}
			out = append(out, row[i]-left)
		}
	}
	return out
}

// imageLengthSkip declares an image whose length covers a plain JavaScript object after it.
func imageLengthSkip() []byte {
	hidden := "\xff\xd8\xff\nendstream\nendobj\n3 0 obj\n<< /S /JavaScript >>\nendobj\n4 0 obj\n<< /Length 1 >>\nstream\nx"
	return []byte("%PDF-1.7\n2 0 obj\n<< /Subtype /Image /Filter /DCTDecode /Length " + strconv.Itoa(len(hidden)) +
		" >>\nstream\n" + hidden + "\nendstream\nendobj\n%%EOF\n")
}

// cleanPDF has the streams real writers produce: Flate content with an indirect length, a JPEG image and
// a cross-reference stream with a PNG predictor.
func cleanPDF(t testing.TB) []byte {
	t.Helper()
	var jpg bytes.Buffer
	require.NoError(t, jpeg.Encode(&jpg, image.NewGray(image.Rect(0, 0, 8, 8)), nil))
	content := flate(t, []byte("BT /F1 12 Tf 72 712 Td (Hello) Tj ET"))
	xref := flate(t, pngSub([]byte{1, 0, 15, 0, 1, 0, 90, 0, 1, 1, 10, 0}, 4))
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	b.WriteString("4 0 obj\n<< /Length 5 0 R /Filter /FlateDecode >>\nstream\n")
	b.Write(content)
	b.WriteString("\nendstream\nendobj\n5 0 obj\n" + strconv.Itoa(len(content)) + "\nendobj\n")
	b.WriteString("6 0 obj\n<< /Type /XObject /Subtype /Image /Width 8 /Height 8 /ColorSpace /DeviceGray /BitsPerComponent 8 " +
		"/Filter /DCTDecode /Length " + strconv.Itoa(jpg.Len()) + " >>\nstream\n")
	b.Write(jpg.Bytes())
	b.WriteString("\nendstream\nendobj\n7 0 obj\n<< /Type /XRef /Size 8 /W [1 2 1] /Root 1 0 R /Filter /FlateDecode " +
		"/DecodeParms << /Columns 4 /Predictor 12 >> /Length " + strconv.Itoa(len(xref)) + " >>\nstream\n")
	b.Write(xref)
	b.WriteString("\nendstream\nendobj\nstartxref\n9\n%%EOF\n")
	return b.Bytes()
}

func pngOf(t testing.TB, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 200, A: 255})
	var buf bytes.Buffer
	require.NoError(t, png.Encode(&buf, img))
	return buf.Bytes()
}

// claimPNG rewrites a PNG header to claim w by h pixels without the data to match.
func claimPNG(p []byte, w, h uint32) []byte {
	binary.BigEndian.PutUint32(p[16:], w)
	binary.BigEndian.PutUint32(p[20:], h)
	binary.BigEndian.PutUint32(p[29:], crc32.ChecksumIEEE(p[12:29]))
	return p
}

func png16(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, png.Encode(&buf, image.NewNRGBA64(image.Rect(0, 0, 1, 1))))
	return buf.Bytes()
}

func gifOf(t testing.TB, frames int) []byte {
	t.Helper()
	g := &gif.GIF{}
	for range frames {
		g.Image = append(g.Image, image.NewPaletted(image.Rect(0, 0, 100, 100), palette.Plan9[:2]))
		g.Delay = append(g.Delay, 1)
	}
	var buf bytes.Buffer
	require.NoError(t, gif.EncodeAll(&buf, g))
	return buf.Bytes()
}

// webpCanvas is a WebP whose extended header claims a w by h canvas.
func webpCanvas(w, h uint32) []byte {
	b := []byte("RIFF\x16\x00\x00\x00WEBPVP8X\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], w-1)
	copy(b[24:27], n[:3])
	binary.LittleEndian.PutUint32(n[:], h-1)
	copy(b[27:30], n[:3])
	return b
}

// zipDirectoryMismatch claims a central directory smaller than the one it has.
func zipDirectoryMismatch(t testing.TB) []byte {
	t.Helper()
	z := zipOf(t, entry{"a.txt", []byte("a")}, entry{"b.txt", []byte("b")})
	eocd := bytes.LastIndex(z, []byte("PK\x05\x06"))
	binary.LittleEndian.PutUint32(z[eocd+12:], binary.LittleEndian.Uint32(z[eocd+12:])-1)
	return z
}

func jpegWithEXIF(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, jpeg.Encode(&buf, image.NewGray(image.Rect(0, 0, 8, 8)), nil))
	const exif = "Exif\x00\x00GPS-SECRET"
	seg := append([]byte{0xFF, 0xE1, 0, byte(len(exif) + 2)}, exif...)
	raw := buf.Bytes()
	return append(append(append([]byte{}, raw[:2]...), seg...), raw[2:]...)
}

func inspectFile(t *testing.T, data []byte) (string, []byte, error) {
	t.Helper()
	in := inspect.New(testLimits, 2)
	mime, err := in.Detect(t.Context(), bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", nil, err
	}
	var out bytes.Buffer
	rewritten, err := in.Inspect(t.Context(), bytes.NewReader(data), int64(len(data)), mime, &out)
	if rewritten {
		return mime, out.Bytes(), err
	}
	return mime, nil, err
}

func TestInspect_Corpus(t *testing.T) {
	zeros := make([]byte, 4<<20)
	many := make([]entry, 21)
	for i := range many {
		many[i] = entry{name: strings.Repeat("f", i+1), data: []byte("x")}
	}
	inner := zipOf(t, entry{"inner.txt", []byte("ok")})
	half := zipOf(t, entry{"half.bin", make([]byte, 600<<10)})
	jsFlate := flate(t, jsPayload)
	require.NotContains(t, string(jsFlate), "JavaScript", "the compressed payload must not spell the name")
	jsPredicted := flate(t, pngSub(jsPayload, 16))
	require.NotContains(t, string(pngSub(jsPayload, 16)), "JavaScript")
	macroSheet := zipOf(t,
		entry{"[Content_Types].xml", []byte(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Override PartName="/xl/macrosheets/sheet1.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/></Types>`)},
		entry{"xl/workbook.xml", []byte("<workbook/>")},
		entry{"xl/_rels/workbook.xml.rels", rels(`<Relationship Id="r1" Type="http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet" Target="macrosheets/sheet1.xml"/>`)},
		entry{"xl/macrosheets/sheet1.xml", []byte("<xm:macrosheet/>")})
	intlMacroRel := zipOf(t,
		entry{"[Content_Types].xml", []byte(contentTypes)}, entry{"xl/workbook.xml", []byte("<workbook/>")},
		entry{"xl/_rels/workbook.xml.rels", rels(`<Relationship Id="r1" Type="http://schemas.microsoft.com/office/2006/relationships/xlIntlMacrosheet" Target="sheets/s.xml"/>`)})

	cases := []struct {
		name     string
		data     []byte
		wantType string
		wantErr  error
	}{
		{"zip bomb by ratio", zipOf(t, entry{"zeros", zeros}), inspect.TypeZip, inspect.ErrBudget},
		{"too many entries", zipOf(t, many...), "", inspect.ErrBudget},
		{"nested within depth", zipOf(t, entry{"a.zip", inner}), inspect.TypeZip, nil},
		{"nested too deep", zipOf(t, entry{"a.zip", zipOf(t, entry{"b.zip", inner})}), inspect.TypeZip, inspect.ErrBudget},
		{"nested archives share one budget", zipOf(t, entry{"a.zip", half}, entry{"b.zip", half}), inspect.TypeZip, inspect.ErrBudget},
		{"zip slip name", zipOf(t, entry{"../evil.sh", []byte("x")}), inspect.TypeZip, inspect.ErrMalformed},
		{"clean docx", docx(t, entry{"word/_rels/document.xml.rels", rels(`<Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com" TargetMode="External"/>`)}), inspect.TypeDocx, nil},
		{"macro docx by part", docx(t, entry{"word/vbaProject.bin", []byte("vba")}), inspect.TypeDocx, inspect.ErrActiveContent},
		{"macro docx by content type", zipOf(t, entry{"[Content_Types].xml", []byte(macroContentTypes)}, entry{"word/document.xml", []byte(document)}), inspect.TypeDocx, inspect.ErrActiveContent},
		{"activex docx", docx(t, entry{"word/activeX/activeX1.xml", []byte("<x/>")}), inspect.TypeDocx, inspect.ErrActiveContent},
		{"ole object docx", docx(t, entry{"word/embeddings/oleObject1.bin", []byte("ole")}), inspect.TypeDocx, inspect.ErrActiveContent},
		{"external template docx", docx(t, entry{"word/_rels/settings.xml.rels", rels(`<Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://attacker.example/t.dotm" TargetMode="External"/>`)}), inspect.TypeDocx, inspect.ErrActiveContent},
		{"namespaced attribute shadowing TargetMode", docx(t, entry{"word/_rels/settings.xml.rels", rels(`<Relationship xmlns:evil="urn:evil" Id="r1" evil:TargetMode="Internal" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://attacker.example/t.dotm" TargetMode="External"/>`)}), inspect.TypeDocx, inspect.ErrActiveContent},
		{"xlm macro sheet", macroSheet, inspect.TypeXlsx, inspect.ErrActiveContent},
		{"international macro sheet relationship", intlMacroRel, inspect.TypeXlsx, inspect.ErrActiveContent},
		{"zip directory that does not match its end record", zipDirectoryMismatch(t), "", inspect.ErrMalformed},
		{"clean pdf", pdfWith("/Pages 2 0 R"), inspect.TypePDF, nil},
		{"clean pdf with streams", cleanPDF(t), inspect.TypePDF, nil},
		{"javascript pdf", pdfWith("/OpenAction << /S /JavaScript /JS (app.alert(1)) >>"), inspect.TypePDF, inspect.ErrActiveContent},
		{"hex-escaped javascript pdf", pdfWith("/OpenAction << /S /J#61vaScript >>"), inspect.TypePDF, inspect.ErrActiveContent},
		{"launch pdf", pdfWith("/OpenAction << /S /Launch /F (cmd.exe) >>"), inspect.TypePDF, inspect.ErrActiveContent},
		{"embedded file pdf", pdfWith("/Names << /EmbeddedFiles 3 0 R >>"), inspect.TypePDF, inspect.ErrActiveContent},
		{"xfa form pdf", pdfWith("/AcroForm << /XFA 5 0 R >>"), inspect.TypePDF, inspect.ErrActiveContent},
		{"javascript in a compressed object stream", pdfStream(objStm+"/Filter /FlateDecode", jsFlate), inspect.TypePDF, inspect.ErrActiveContent},
		{"indirect filter", pdfStream(objStm+"/Filter 3 0 R", jsFlate), inspect.TypePDF, inspect.ErrUnsupported},
		{"abbreviated flate filter", pdfStream(objStm+"/Filter /Fl", jsFlate), inspect.TypePDF, inspect.ErrUnsupported},
		{"abbreviated hex filter", pdfStream(objStm+"/Filter /AHx", []byte("2f4a53>")), inspect.TypePDF, inspect.ErrUnsupported},
		{"object stream disguised as an image", pdfStream("/Subtype /Image /N 1 /First 4 /Filter /FlateDecode", jsFlate), inspect.TypePDF, inspect.ErrActiveContent},
		{"image encoding outside an image", pdfStream(objStm+"/Filter /DCTDecode", jsPayload), inspect.TypePDF, inspect.ErrUnsupported},
		{"image length covering a later object", imageLengthSkip(), inspect.TypePDF, inspect.ErrMalformed},
		{"png predictor", pdfStream(objStm+"/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 16 >>", jsPredicted), inspect.TypePDF, inspect.ErrActiveContent},
		{"string that tokenises as obj", pdfStream(objStm+"/Filter /FlateDecode /X (obj)", jsFlate), inspect.TypePDF, inspect.ErrActiveContent},
		{"object hidden in a string", pdfWith("/Title (x 1 0 obj << /S /JavaScript >> endobj)"), inspect.TypePDF, inspect.ErrMalformed},
		{"stream hidden in an object stream", pdfStream(objStm+"/Filter /FlateDecode", flate(t, []byte("<< /Filter /FlateDecode /Length 9 >> stream\nxxxxxxxxx"))), inspect.TypePDF, inspect.ErrMalformed},
		{"length that does not end at endstream", pdfStream("/Length 3", []byte("abcdef")), inspect.TypePDF, inspect.ErrMalformed},
		{"pdf stream past the inflate budget", pdfStream("/Filter /FlateDecode", flate(t, zeros)), inspect.TypePDF, inspect.ErrBudget},
		{"pdf stream in an opaque encoding", pdfStream("/Type /ObjStm /Filter /ASCIIHexDecode", []byte("2f4a53>")), inspect.TypePDF, inspect.ErrUnsupported},
		{"huge-dimension png", claimPNG(pngOf(t, 1, 1), 100000, 100000), inspect.TypePNG, inspect.ErrImageTooLarge},
		{"16-bit png past the decoded budget", claimPNG(png16(t), 400, 400), inspect.TypePNG, inspect.ErrImageTooLarge},
		{"gif", gifOf(t, 2), inspect.TypeGIF, nil},
		{"gif frames past the decoded budget", gifOf(t, 110), inspect.TypeGIF, inspect.ErrImageTooLarge},
		{"webp", webpCanvas(64, 64), inspect.TypeWebP, nil},
		{"huge-canvas webp", webpCanvas(16000, 16000), inspect.TypeWebP, inspect.ErrImageTooLarge},
		{"utf-8 text", []byte("name,qty\nKöln,3\n"), inspect.TypeText, nil},
		{"text with NUL", append([]byte(strings.Repeat("a", 600)), 0), inspect.TypeText, inspect.ErrNotText},
		{"binary", []byte{0x00, 0x01, 0x02}, inspect.TypeUnknown, inspect.ErrUnsupported},
	}
	kitDocx, err := os.ReadFile("testdata/kit-docx.docx")
	require.NoError(t, err)
	cases = append(cases, struct {
		name     string
		data     []byte
		wantType string
		wantErr  error
	}{"docx written by kit/docx", kitDocx, inspect.TypeDocx, nil})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mime, _, err := inspectFile(t, c.data)
			if c.wantType != "" {
				assert.Equal(t, c.wantType, mime)
			}
			if c.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, c.wantErr)
		})
	}
}

func TestInspect_ReencodesImagesWithoutMetadata(t *testing.T) {
	src := jpegWithEXIF(t)
	require.True(t, bytes.Contains(src, []byte("GPS-SECRET")))
	mime, out, err := inspectFile(t, src)
	require.NoError(t, err)
	assert.Equal(t, inspect.TypeJPEG, mime)
	require.NotEmpty(t, out)
	assert.False(t, bytes.Contains(out, []byte("GPS-SECRET")))
	_, format, err := image.DecodeConfig(bytes.NewReader(out))
	require.NoError(t, err)
	assert.Equal(t, "jpeg", format)
}

func FuzzInspect(f *testing.F) {
	f.Add(pdfWith("/OpenAction << /S /JavaScript >>"))
	f.Add([]byte("%PDF-1.4\n<< /Filter /FlateDecode /Length 5 >>\nstream\nxxxxx\nendstream"))
	f.Add(zipOf(f, entry{"a.txt", []byte("a")}))
	f.Add(docx(f))
	f.Add(pngOf(f, 2, 2))
	f.Add(cleanPDF(f))
	f.Add(gifOf(f, 1))
	f.Fuzz(func(t *testing.T, data []byte) {
		in := inspect.New(testLimits, 1)
		mime, err := in.Detect(t.Context(), bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		_, _ = in.Inspect(t.Context(), bytes.NewReader(data), int64(len(data)), mime, &bytes.Buffer{}) // only panics and hangs matter here
	})
}

// Package docx writes small Word documents (paragraphs, headings, lists, tables, page breaks and a table
// of contents) with styles passed in, and validates their structure.
package docx

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Styles are the document's look; zero fields take the defaults. Sizes are in points.
type Styles struct {
	Font           string
	SizePt         int
	HeadingFont    string
	HeadingSizesPt [3]int
	HeadingColor   string // hex RGB, for example "1F3864"
	A4             bool   // A4 pages; Letter otherwise
}

func (s Styles) withDefaults() Styles {
	if s.Font == "" {
		s.Font = "Calibri"
	}
	if s.SizePt <= 0 {
		s.SizePt = 11
	}
	if s.HeadingFont == "" {
		s.HeadingFont = s.Font
	}
	for i, d := range [3]int{20, 16, 13} {
		if s.HeadingSizesPt[i] <= 0 {
			s.HeadingSizesPt[i] = d
		}
	}
	if !validHex(s.HeadingColor) {
		s.HeadingColor = "000000"
	}
	return s
}

func validHex(s string) bool {
	if len(s) != 6 {
		return false
	}
	_, err := strconv.ParseUint(s, 16, 32)
	return err == nil
}

// Run is text with emphasis inside a paragraph.
type Run struct {
	Text   string
	Bold   bool
	Italic bool
}

type heading struct {
	level int
	text  string
}

type Document struct {
	styles   Styles
	parts    []string
	tocAt    int
	tocTitle string
	headings []heading
	lists    []bool // ordered, per numbering instance
}

func New(styles Styles) *Document {
	return &Document{styles: styles.withDefaults(), tocAt: -1}
}

func (d *Document) add(xml string) { d.parts = append(d.parts, xml) }

// Heading adds a heading of level 1 to 3.
func (d *Document) Heading(level int, text string) {
	level = min(max(level, 1), 3)
	d.headings = append(d.headings, heading{level: level, text: text})
	d.add(`<w:p><w:pPr><w:pStyle w:val="Heading` + strconv.Itoa(level) + `"/></w:pPr>` + runXML(Run{Text: text}) + `</w:p>`)
}

func (d *Document) Paragraph(runs ...Run) {
	var b strings.Builder
	b.WriteString("<w:p>")
	for _, r := range runs {
		b.WriteString(runXML(r))
	}
	b.WriteString("</w:p>")
	d.add(b.String())
}

// Text adds a paragraph of plain text.
func (d *Document) Text(text string) { d.Paragraph(Run{Text: text}) }

// List adds a bulleted or numbered list; each numbered list starts at 1.
func (d *Document) List(ordered bool, items ...string) {
	d.lists = append(d.lists, ordered)
	numID := strconv.Itoa(len(d.lists))
	for _, item := range items {
		d.add(`<w:p><w:pPr><w:pStyle w:val="ListParagraph"/><w:numPr><w:ilvl w:val="0"/><w:numId w:val="` + numID +
			`"/></w:numPr></w:pPr>` + runXML(Run{Text: item}) + `</w:p>`)
	}
}

// Table adds a table with a bold header row repeated on each page; short rows are padded.
func (d *Document) Table(header []string, rows [][]string) {
	cols := len(header)
	for _, r := range rows {
		cols = max(cols, len(r))
	}
	if cols == 0 {
		return
	}
	width := 9000 / cols
	var b strings.Builder
	b.WriteString(`<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="0" w:type="auto"/></w:tblPr><w:tblGrid>`)
	for range cols {
		b.WriteString(`<w:gridCol w:w="` + strconv.Itoa(width) + `"/>`)
	}
	b.WriteString(`</w:tblGrid>`)
	row := func(cells []string, head bool) {
		b.WriteString("<w:tr>")
		if head {
			b.WriteString(`<w:trPr><w:tblHeader/></w:trPr>`)
		}
		for i := range cols {
			text := ""
			if i < len(cells) {
				text = cells[i]
			}
			b.WriteString(`<w:tc><w:tcPr><w:tcW w:w="` + strconv.Itoa(width) + `" w:type="dxa"/></w:tcPr><w:p>` +
				runXML(Run{Text: text, Bold: head}) + `</w:p></w:tc>`)
		}
		b.WriteString("</w:tr>")
	}
	if len(header) > 0 {
		row(header, true)
	}
	for _, r := range rows {
		row(r, false)
	}
	b.WriteString("</w:tbl>")
	d.add(b.String())
	d.add("<w:p/>")
}

func (d *Document) PageBreak() { d.add(`<w:p><w:r><w:br w:type="page"/></w:r></w:p>`) }

// TableOfContents places a contents field listing the headings; Word refreshes page numbers on open.
func (d *Document) TableOfContents(title string) {
	if d.tocAt >= 0 {
		return
	}
	d.tocAt, d.tocTitle = len(d.parts), title
	d.add("")
}

func (d *Document) toc() string {
	var b strings.Builder
	if d.tocTitle != "" {
		b.WriteString(`<w:p><w:pPr><w:pStyle w:val="TOCHeading"/></w:pPr>` + runXML(Run{Text: d.tocTitle}) + `</w:p>`)
	}
	begin := `<w:r><w:fldChar w:fldCharType="begin" w:dirty="true"/></w:r><w:r><w:instrText xml:space="preserve"> TOC \o "1-3" \h \z \u </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r>`
	end := `<w:r><w:fldChar w:fldCharType="end"/></w:r>`
	if len(d.headings) == 0 {
		b.WriteString(`<w:p>` + begin + end + `</w:p>`)
		return b.String()
	}
	for i, h := range d.headings {
		b.WriteString(`<w:p><w:pPr><w:pStyle w:val="TOC` + strconv.Itoa(h.level) + `"/></w:pPr>`)
		if i == 0 {
			b.WriteString(begin)
		}
		b.WriteString(runXML(Run{Text: h.text}))
		if i == len(d.headings)-1 {
			b.WriteString(end)
		}
		b.WriteString(`</w:p>`)
	}
	return b.String()
}

func runXML(r Run) string {
	var b strings.Builder
	b.WriteString("<w:r>")
	if r.Bold || r.Italic {
		b.WriteString("<w:rPr>")
		if r.Bold {
			b.WriteString("<w:b/>")
		}
		if r.Italic {
			b.WriteString("<w:i/>")
		}
		b.WriteString("</w:rPr>")
	}
	for i, line := range strings.Split(r.Text, "\n") {
		if i > 0 {
			b.WriteString("<w:br/>")
		}
		b.WriteString(`<w:t xml:space="preserve">` + escape(line) + `</w:t>`)
	}
	b.WriteString("</w:r>")
	return b.String()
}

// escape escapes markup and drops characters XML 1.0 cannot hold, which would make Word refuse the file.
func escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '&':
			b.WriteString("&amp;")
		case r == '<':
			b.WriteString("&lt;")
		case r == '>':
			b.WriteString("&gt;")
		case r == '"':
			b.WriteString("&quot;")
		case r == '\t' || r >= 0x20 && r <= 0xD7FF || r >= 0xE000 && r <= 0xFFFD || r >= 0x10000 && r <= utf8.MaxRune:
			b.WriteRune(r)
		}
	}
	return b.String()
}

const (
	nsW   = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
	nsRel = "http://schemas.openxmlformats.org/package/2006/relationships"
	nsDoc = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
	xmlPI = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`
)

// Write writes the document as a .docx archive.
func (d *Document) Write(w io.Writer) error {
	zw := zip.NewWriter(w)
	parts := []struct{ name, body string }{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", xmlPI + `<Relationships xmlns="` + nsRel + `"><Relationship Id="rId1" Type="` + nsDoc + `/officeDocument" Target="word/document.xml"/></Relationships>`},
		{"word/_rels/document.xml.rels", xmlPI + `<Relationships xmlns="` + nsRel + `">` +
			`<Relationship Id="rId1" Type="` + nsDoc + `/styles" Target="styles.xml"/>` +
			`<Relationship Id="rId2" Type="` + nsDoc + `/numbering" Target="numbering.xml"/>` +
			`<Relationship Id="rId3" Type="` + nsDoc + `/settings" Target="settings.xml"/></Relationships>`},
		{"word/document.xml", d.document()},
		{"word/styles.xml", d.stylesXML()},
		{"word/numbering.xml", d.numbering()},
		{"word/settings.xml", d.settings()},
	}
	for _, p := range parts {
		f, err := zw.Create(p.name)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(f, p.body); err != nil {
			return err
		}
	}
	return zw.Close()
}

const contentTypes = xmlPI + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
	`<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>` +
	`<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>` +
	`<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/></Types>`

func (d *Document) document() string {
	var b strings.Builder
	b.WriteString(xmlPI + `<w:document xmlns:w="` + nsW + `" xmlns:r="` + nsDoc + `"><w:body>`)
	for i, p := range d.parts {
		if i == d.tocAt {
			b.WriteString(d.toc())
			continue
		}
		b.WriteString(p)
	}
	w, h := "12240", "15840"
	if d.styles.A4 {
		w, h = "11906", "16838"
	}
	b.WriteString(`<w:sectPr><w:pgSz w:w="` + w + `" w:h="` + h + `"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr>`)
	b.WriteString(`</w:body></w:document>`)
	return b.String()
}

func halfPoints(pt int) string { return strconv.Itoa(pt * 2) }

func (d *Document) stylesXML() string {
	s := d.styles
	fonts := func(f string) string {
		f = escape(f)
		return `<w:rFonts w:ascii="` + f + `" w:hAnsi="` + f + `" w:cs="` + f + `" w:eastAsia="` + f + `"/>`
	}
	var b strings.Builder
	b.WriteString(xmlPI + `<w:styles xmlns:w="` + nsW + `">`)
	b.WriteString(`<w:docDefaults><w:rPrDefault><w:rPr>` + fonts(s.Font) + `<w:sz w:val="` + halfPoints(s.SizePt) + `"/></w:rPr></w:rPrDefault>` +
		`<w:pPrDefault><w:pPr><w:spacing w:after="160" w:line="259" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>`)
	b.WriteString(`<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>`)
	for i, size := range s.HeadingSizesPt {
		n := strconv.Itoa(i + 1)
		b.WriteString(`<w:style w:type="paragraph" w:styleId="Heading` + n + `"><w:name w:val="heading ` + n + `"/><w:basedOn w:val="Normal"/>` +
			`<w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="` + strconv.Itoa(i) + `"/></w:pPr>` +
			`<w:rPr>` + fonts(s.HeadingFont) + `<w:b/><w:color w:val="` + s.HeadingColor + `"/><w:sz w:val="` + halfPoints(size) + `"/></w:rPr></w:style>`)
	}
	b.WriteString(`<w:style w:type="paragraph" w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="720"/><w:contextualSpacing/></w:pPr></w:style>`)
	b.WriteString(`<w:style w:type="paragraph" w:styleId="TOCHeading"><w:name w:val="TOC Heading"/><w:basedOn w:val="Heading1"/><w:next w:val="Normal"/><w:pPr><w:outlineLvl w:val="9"/></w:pPr></w:style>`)
	for i := 1; i <= 3; i++ {
		n := strconv.Itoa(i)
		b.WriteString(`<w:style w:type="paragraph" w:styleId="TOC` + n + `"><w:name w:val="toc ` + n + `"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>` +
			`<w:pPr><w:spacing w:after="100"/><w:ind w:left="` + strconv.Itoa((i-1)*220) + `"/></w:pPr></w:style>`)
	}
	b.WriteString(`<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:tblPr><w:tblBorders>`)
	for _, side := range []string{"top", "left", "bottom", "right", "insideH", "insideV"} {
		b.WriteString(`<w:` + side + ` w:val="single" w:sz="4" w:space="0" w:color="auto"/>`)
	}
	b.WriteString(`</w:tblBorders><w:tblCellMar><w:left w:w="108" w:type="dxa"/><w:right w:w="108" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>`)
	b.WriteString(`</w:styles>`)
	return b.String()
}

func (d *Document) numbering() string {
	var b strings.Builder
	b.WriteString(xmlPI + `<w:numbering xmlns:w="` + nsW + `">`)
	b.WriteString(`<w:abstractNum w:abstractNumId="0"><w:multiLevelType w:val="singleLevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/>` +
		`<w:numFmt w:val="bullet"/><w:lvlText w:val="` + "•" + `"/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum>`)
	b.WriteString(`<w:abstractNum w:abstractNumId="1"><w:multiLevelType w:val="singleLevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/>` +
		`<w:numFmt w:val="decimal"/><w:lvlText w:val="%1."/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum>`)
	for i, ordered := range d.lists {
		abstract := "0"
		if ordered {
			abstract = "1"
		}
		b.WriteString(`<w:num w:numId="` + strconv.Itoa(i+1) + `"><w:abstractNumId w:val="` + abstract + `"/>` +
			`<w:lvlOverride w:ilvl="0"><w:startOverride w:val="1"/></w:lvlOverride></w:num>`)
	}
	b.WriteString(`</w:numbering>`)
	return b.String()
}

func (d *Document) settings() string {
	update := ""
	if d.tocAt >= 0 {
		update = `<w:updateFields w:val="true"/>`
	}
	return xmlPI + `<w:settings xmlns:w="` + nsW + `">` + update + `<w:defaultTabStop w:val="720"/><w:compat><w:compatSetting w:name="compatibilityMode" w:uri="http://schemas.microsoft.com/office/word" w:val="15"/></w:compat></w:settings>`
}

var ErrInvalid = errors.New("docx: invalid document structure")

func structural(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

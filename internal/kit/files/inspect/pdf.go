package inspect

import (
	"bufio"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
)

var pdfRefused = map[string]string{
	"JavaScript":    "JavaScript",
	"JS":            "JavaScript",
	"Launch":        "launch action",
	"EmbeddedFile":  "embedded file",
	"EmbeddedFiles": "embedded file",
	"XFA":           "XFA form",
	"RichMedia":     "rich media",
	"GoToR":         "remote go-to action",
	"GoToE":         "embedded go-to action",
	"SubmitForm":    "form submission",
	"ImportData":    "data import",
}

const (
	pdfFlate        = "FlateDecode"
	maxPDFToken     = 127
	maxPDFDepth     = 64
	maxPDFFilters   = 4
	maxPDFKept      = 32
	maxPredictorRow = 1 << 22
)

// image filters are accepted undecoded, and only on a dictionary that cannot double as an object stream
var pdfImageFilters = map[string]bool{"DCTDecode": true, "JPXDecode": true, "CCITTFaxDecode": true, "JBIG2Decode": true}

// pdfKept are the keys whose values decide how a stream is read; every other value is parsed and dropped.
var pdfKept = map[string]bool{
	"Type": true, "Subtype": true, "Filter": true, "DecodeParms": true, "Length": true, "N": true, "First": true,
	"F": true, "DP": true, "FFilter": true, "FDecodeParms": true,
	"Predictor": true, "Colors": true, "BitsPerComponent": true, "Columns": true,
}

// pdf.js reads /F and /DP as Filter and DecodeParms on any stream, and /F, /FFilter and /FDecodeParms
// point a stream at external data.
var pdfStreamRefusedKeys = []string{"F", "DP", "FFilter", "FDecodeParms"}

func pdfMalformed(what string) error   { return fmt.Errorf("%w: PDF %s", ErrMalformed, what) }
func pdfUnsupported(what string) error { return fmt.Errorf("%w: PDF %s", ErrUnsupported, what) }

var errPDFHidden = pdfMalformed("object syntax hidden in a string, comment or stream")

// checkPDF fails closed. The top level is tokenised (strings, comments, dictionaries) to find every stream
// and its dictionary. Every Flate stream is inflated within the budget and every name in decoded data is
// checked, wherever it sits, because a reader can parse an object stream at any offset. Bytes the
// tokeniser treats as opaque (strings, comments, stream data) are refused when they hold an object
// header or a cross-reference marker, since a reader following the cross-reference table could parse
// them as objects. Streams in any other encoding are refused.
func (in *Inspector) checkPDF(ctx context.Context, r io.Reader, b *budget) error {
	s := &pdfScanner{ctx: ctx, b: b, lex: &pdfLexer{r: bufio.NewReaderSize(r, 64<<10), ctx: ctx}}
	return s.top()
}

type pdfTokKind int

const (
	tokEOF pdfTokKind = iota
	tokName
	tokWord
	tokString
	tokDictOpen
	tokDictClose
	tokArrayOpen
	tokArrayClose
	tokStray
)

type pdfTok struct {
	kind pdfTokKind
	text string
}

type pdfLexer struct {
	r     *bufio.Reader
	ctx   context.Context
	steps int
	back  []pdfTok
}

func (l *pdfLexer) push(t pdfTok) { l.back = append(l.back, t) }

func (l *pdfLexer) next() (pdfTok, error) {
	if n := len(l.back); n > 0 {
		t := l.back[n-1]
		l.back = l.back[:n-1]
		return t, nil
	}
	for {
		if l.steps++; l.steps%65536 == 0 {
			if err := l.ctx.Err(); err != nil {
				return pdfTok{}, err
			}
		}
		c, err := l.r.ReadByte()
		if errors.Is(err, io.EOF) {
			return pdfTok{kind: tokEOF}, nil
		}
		if err != nil {
			return pdfTok{}, readError(err)
		}
		switch {
		case pdfSpace(c):
		case c == '%':
			if err := l.comment(); err != nil {
				return pdfTok{}, err
			}
		case c == '(':
			return pdfTok{kind: tokString}, l.literal()
		case c == '<':
			if l.follows('<') {
				return pdfTok{kind: tokDictOpen}, nil
			}
			return pdfTok{kind: tokString}, l.hex()
		case c == '>':
			if l.follows('>') {
				return pdfTok{kind: tokDictClose}, nil
			}
			return pdfTok{kind: tokStray}, nil
		case c == '[':
			return pdfTok{kind: tokArrayOpen}, nil
		case c == ']':
			return pdfTok{kind: tokArrayClose}, nil
		case c == '/':
			name, err := readPDFToken(l.r, true)
			if err != nil {
				return pdfTok{}, readError(err)
			}
			return pdfTok{kind: tokName, text: name}, checkPDFName(name)
		case pdfRegular(c):
			_ = l.r.UnreadByte() // cannot fail right after ReadByte
			word, err := readPDFToken(l.r, false)
			if err != nil {
				return pdfTok{}, readError(err)
			}
			return pdfTok{kind: tokWord, text: word}, nil
		default:
			return pdfTok{kind: tokStray}, nil
		}
	}
}

func (l *pdfLexer) follows(c byte) bool {
	if next, err := l.r.Peek(1); err == nil && next[0] == c {
		_, _ = l.r.Discard(1) // cannot fail after a successful Peek
		return true
	}
	return false
}

func (l *pdfLexer) comment() error {
	var o opaque
	for {
		c, err := l.r.ReadByte()
		if errors.Is(err, io.EOF) || err == nil && (c == '\r' || c == '\n') {
			return o.end()
		}
		if err != nil {
			return readError(err)
		}
		if err := o.feed(c); err != nil {
			return err
		}
	}
}

func (l *pdfLexer) literal() error {
	var o opaque
	depth := 1
	for {
		c, err := l.r.ReadByte()
		if err != nil {
			return eofMalformed(err, "unterminated string")
		}
		if err := o.feed(c); err != nil {
			return err
		}
		switch c {
		case '\\':
			if c, err = l.r.ReadByte(); err != nil {
				return eofMalformed(err, "unterminated string")
			}
			if err := o.feed(c); err != nil {
				return err
			}
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return o.end()
			}
		}
	}
}

func (l *pdfLexer) hex() error {
	for {
		c, err := l.r.ReadByte()
		if err != nil {
			return eofMalformed(err, "unterminated hex string")
		}
		if c == '>' {
			return nil
		}
		if _, ok := unhex(c); !ok && !pdfSpace(c) {
			return pdfMalformed("hex string")
		}
	}
}

func eofMalformed(err error, what string) error {
	if errors.Is(err, io.EOF) {
		return pdfMalformed(what)
	}
	return readError(err)
}

func checkPDFName(name string) error {
	if what, bad := pdfRefused[name]; bad {
		return fmt.Errorf("%w: %s", ErrActiveContent, what)
	}
	if name == "Encrypt" {
		return fmt.Errorf("%w: encrypted PDF", ErrUnsupported)
	}
	return nil
}

type pdfKind int

const (
	pdfOther pdfKind = iota
	pdfNull
	pdfName
	pdfInt
	pdfRef
	pdfDictValue
	pdfArrayValue
)

type pdfValue struct {
	kind pdfKind
	name string
	num  int64
	dict pdfDict
	arr  []pdfValue
	cut  bool
}

type pdfDict map[string]pdfValue

type pdfScanner struct {
	ctx context.Context
	b   *budget
	lex *pdfLexer
}

func (s *pdfScanner) top() error {
	var last pdfDict
	for {
		t, err := s.lex.next()
		if err != nil {
			return err
		}
		switch t.kind {
		case tokEOF:
			return nil
		case tokDictOpen:
			if last, err = s.dict(1); err != nil {
				return err
			}
			continue
		case tokArrayOpen:
			if _, err := s.array(1, false); err != nil {
				return err
			}
		case tokWord:
			if t.text == "stream" {
				if last == nil {
					return pdfMalformed("stream without a dictionary")
				}
				if err := s.stream(last); err != nil {
					return err
				}
			}
		case tokName, tokString, tokDictClose, tokArrayClose, tokStray:
		}
		last = nil
	}
}

func (s *pdfScanner) dict(depth int) (pdfDict, error) {
	if depth > maxPDFDepth {
		return nil, pdfMalformed("nesting")
	}
	d := pdfDict{}
	for {
		t, err := s.lex.next()
		if err != nil {
			return nil, err
		}
		if t.kind == tokDictClose {
			return d, nil
		}
		if t.kind != tokName {
			return nil, pdfMalformed("dictionary key")
		}
		keep := pdfKept[t.text]
		v, err := s.value(depth, keep)
		if err != nil {
			return nil, err
		}
		if keep {
			if _, dup := d[t.text]; dup {
				return nil, pdfMalformed("repeated key")
			}
			d[t.text] = v
		}
	}
}

func (s *pdfScanner) array(depth int, keep bool) (pdfValue, error) {
	if depth > maxPDFDepth {
		return pdfValue{}, pdfMalformed("nesting")
	}
	v := pdfValue{kind: pdfArrayValue}
	for {
		t, err := s.lex.next()
		if err != nil {
			return pdfValue{}, err
		}
		if t.kind == tokArrayClose {
			return v, nil
		}
		s.lex.push(t)
		e, err := s.value(depth, keep)
		if err != nil {
			return pdfValue{}, err
		}
		switch {
		case !keep:
		case len(v.arr) < maxPDFKept:
			v.arr = append(v.arr, e)
		default:
			v.cut = true
		}
	}
}

func (s *pdfScanner) value(depth int, keep bool) (pdfValue, error) {
	t, err := s.lex.next()
	if err != nil {
		return pdfValue{}, err
	}
	switch t.kind {
	case tokName:
		return pdfValue{kind: pdfName, name: t.text}, nil
	case tokString:
		return pdfValue{}, nil
	case tokDictOpen:
		d, err := s.dict(depth + 1)
		return pdfValue{kind: pdfDictValue, dict: d}, err
	case tokArrayOpen:
		return s.array(depth+1, keep)
	case tokWord:
		return s.word(t.text)
	case tokEOF, tokDictClose, tokArrayClose, tokStray:
	}
	return pdfValue{}, pdfMalformed("missing value")
}

// word reads a number, keyword or indirect reference (two integers and R).
func (s *pdfScanner) word(w string) (pdfValue, error) {
	switch w {
	case "null":
		return pdfValue{kind: pdfNull}, nil
	case "stream", "endstream", "obj", "endobj", "R":
		return pdfValue{}, pdfMalformed("keyword inside an object")
	}
	n, isInt := pdfInteger(w)
	if !isInt {
		return pdfValue{}, nil
	}
	t1, err := s.lex.next()
	if err != nil {
		return pdfValue{}, err
	}
	if t1.kind == tokWord {
		if _, isInt := pdfInteger(t1.text); isInt {
			t2, err := s.lex.next()
			if err != nil {
				return pdfValue{}, err
			}
			if t2.kind == tokWord && t2.text == "R" {
				return pdfValue{kind: pdfRef}, nil
			}
			s.lex.push(t2)
		}
	}
	s.lex.push(t1)
	return pdfValue{kind: pdfInt, num: n}, nil
}

func pdfInteger(w string) (int64, bool) {
	n, err := strconv.ParseInt(w, 10, 64)
	return n, err == nil
}

func (s *pdfScanner) stream(d pdfDict) error {
	if len(s.lex.back) > 0 {
		return pdfMalformed("stream keyword")
	}
	if err := skipEOL(s.lex.r); err != nil {
		return eofMalformed(err, "stream")
	}
	for _, k := range pdfStreamRefusedKeys {
		if _, ok := d[k]; ok {
			return pdfUnsupported("stream with external data or abbreviated keys")
		}
	}
	filters, params, err := streamFilters(d)
	if err != nil {
		return err
	}
	image := pdfImage(d)
	if err := checkFilters(filters, image); err != nil {
		return err
	}
	reg := &pdfRegion{r: s.lex.r, left: -1}
	switch l := d["Length"]; l.kind {
	case pdfInt:
		if l.num < 0 {
			return pdfMalformed("stream length")
		}
		reg.left = l.num
	case pdfRef:
	case pdfOther, pdfNull, pdfName, pdfDictValue, pdfArrayValue:
		if _, ok := d["Length"]; ok {
			return pdfMalformed("stream length")
		}
	}
	known := reg.left >= 0
	if err := s.decode(reg, filters, params, image); err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, reg); err != nil {
		return readError(err)
	}
	if !known {
		return nil
	}
	t, err := s.lex.next()
	if err != nil {
		return err
	}
	if t.kind != tokWord || t.text != "endstream" {
		return pdfMalformed("stream length does not end at endstream")
	}
	return nil
}

// pdfImage reports whether d is exactly an image XObject: pdf.js parses any stream with /N and /First
// as an object stream, whatever its /Type says.
func pdfImage(d pdfDict) bool {
	_, n := d["N"]
	_, first := d["First"]
	typ, hasType := d["Type"]
	sub := d["Subtype"]
	return sub.kind == pdfName && sub.name == "Image" && !n && !first &&
		(!hasType || typ.kind == pdfName && typ.name == "XObject")
}

func streamFilters(d pdfDict) ([]string, []pdfDict, error) {
	var filters []string
	switch f := d["Filter"]; f.kind {
	case pdfName:
		filters = []string{f.name}
	case pdfArrayValue:
		if f.cut || len(f.arr) > maxPDFFilters {
			return nil, nil, pdfUnsupported("filter chain")
		}
		for _, e := range f.arr {
			if e.kind != pdfName {
				return nil, nil, pdfUnsupported("indirect or malformed filter")
			}
			filters = append(filters, e.name)
		}
	case pdfRef:
		return nil, nil, pdfUnsupported("indirect filter")
	case pdfNull:
	case pdfOther, pdfInt, pdfDictValue:
		if _, ok := d["Filter"]; ok {
			return nil, nil, pdfMalformed("filter")
		}
	}
	params := make([]pdfDict, len(filters))
	if len(filters) == 0 {
		return nil, params, nil
	}
	switch p := d["DecodeParms"]; p.kind {
	case pdfDictValue:
		if len(filters) != 1 {
			return nil, nil, pdfMalformed("decode parameters")
		}
		params[0] = p.dict
	case pdfArrayValue:
		if p.cut || len(p.arr) != len(filters) {
			return nil, nil, pdfMalformed("decode parameters")
		}
		for i, e := range p.arr {
			switch e.kind {
			case pdfDictValue:
				params[i] = e.dict
			case pdfNull:
			case pdfRef:
				return nil, nil, pdfUnsupported("indirect decode parameters")
			case pdfOther, pdfName, pdfInt, pdfArrayValue:
				return nil, nil, pdfMalformed("decode parameters")
			}
		}
	case pdfRef:
		return nil, nil, pdfUnsupported("indirect decode parameters")
	case pdfNull:
	case pdfOther, pdfName, pdfInt:
		if _, ok := d["DecodeParms"]; ok {
			return nil, nil, pdfMalformed("decode parameters")
		}
	}
	return filters, params, nil
}

// checkFilters allows Flate, optionally followed by one image encoding on an image XObject.
func checkFilters(filters []string, image bool) error {
	for i, f := range filters {
		switch {
		case f == pdfFlate:
			if i > 0 && filters[i-1] != pdfFlate {
				return pdfUnsupported("filter chain")
			}
		case pdfImageFilters[f]:
			if !image || i != len(filters)-1 {
				return pdfUnsupported("image encoding outside an image")
			}
		default:
			return pdfUnsupported("stream encoding")
		}
	}
	return nil
}

// decode inflates the Flate filters and checks the result; an image encoding is left undecoded.
// Image pixels only spend the budget: they cannot be parsed as objects, and random pixels spell
// refused names often enough to reject real scans.
func (s *pdfScanner) decode(reg *pdfRegion, filters []string, params []pdfDict, image bool) error {
	var r io.Reader = reg
	n := 0
	for ; n < len(filters) && filters[n] == pdfFlate; n++ {
		zr, err := zlib.NewReader(r)
		if err != nil {
			return readError(err)
		}
		if r, err = predictor(s.b.reader(zr), params[n]); err != nil {
			return err
		}
	}
	if n == 0 && len(filters) > 0 {
		return nil
	}
	if image {
		_, err := io.Copy(io.Discard, r)
		return readError(err)
	}
	return scanDecoded(s.ctx, r)
}

func scanDecoded(ctx context.Context, r io.Reader) error {
	var names nameSniffer
	var hidden hiddenStream
	buf := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := r.Read(buf)
		for _, c := range buf[:n] {
			if err := names.feed(c); err != nil {
				return err
			}
			if err := hidden.feed(c); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return errors.Join(names.end(), hidden.end())
		}
		if err != nil {
			return readError(err)
		}
	}
}

// pdfRegion reads a stream's data: Length bytes when the length is direct, else up to the first
// endstream, which is where pdf.js ends a stream whose length does not land.
type pdfRegion struct {
	r     *bufio.Reader
	left  int64
	found bool
	end   int
	check opaque
}

func (g *pdfRegion) ReadByte() (byte, error) {
	if g.found || g.left == 0 {
		return 0, io.EOF
	}
	c, err := g.r.ReadByte()
	if err != nil {
		return 0, eofMalformed(err, "stream runs past the end of the file")
	}
	if err := g.check.feed(c); err != nil {
		return 0, err
	}
	if g.end = endstreamPattern.step(g.end, c); g.end == len(endstreamPattern.pat) {
		if g.left > 0 {
			return 0, pdfMalformed("endstream inside stream data")
		}
		g.found = true
		return 0, io.EOF
	}
	if g.left > 0 {
		if g.left--; g.left == 0 {
			if err := g.check.end(); err != nil {
				return 0, err
			}
		}
	}
	return c, nil
}

func (g *pdfRegion) Read(p []byte) (int, error) {
	for i := range p {
		c, err := g.ReadByte()
		if err != nil {
			return i, err
		}
		p[i] = c
	}
	return len(p), nil
}

// kmp finds a fixed pattern in a byte stream one byte at a time.
type kmp struct {
	pat  string
	fail []int
}

func newKMP(pat string) kmp {
	fail := make([]int, len(pat))
	for i, k := 1, 0; i < len(pat); i++ {
		for k > 0 && pat[i] != pat[k] {
			k = fail[k-1]
		}
		if pat[i] == pat[k] {
			k++
		}
		fail[i] = k
	}
	return kmp{pat: pat, fail: fail}
}

// step returns the matched length after c; len(pat) is a match.
func (m kmp) step(k int, c byte) int {
	if k == len(m.pat) {
		k = m.fail[k-1]
	}
	for k > 0 && c != m.pat[k] {
		k = m.fail[k-1]
	}
	if c == m.pat[k] {
		k++
	}
	return k
}

var (
	endstreamPattern = newKMP("endstream")
	startxrefPattern = newKMP("startxref")
)

type objState int

const (
	objNone objState = iota
	objDigit
	objSpace
	objComment
	objO
	objOB
	objOBJ
)

// opaque refuses bytes a reader could parse as an object header ("12 0 obj") or as the start of the
// cross-reference chain; the tokeniser itself never reads them as syntax.
type opaque struct {
	obj  objState
	xref int
}

func (o *opaque) feed(c byte) error {
	if o.xref = startxrefPattern.step(o.xref, c); o.xref == len(startxrefPattern.pat) {
		return errPDFHidden
	}
	switch o.obj {
	case objComment:
		if c == '\r' || c == '\n' {
			o.obj = objSpace
		}
		return nil
	case objOBJ:
		if !pdfRegular(c) {
			return errPDFHidden
		}
	case objNone, objDigit, objSpace, objO, objOB:
	}
	afterNumber := o.obj == objDigit || o.obj == objSpace
	switch {
	case c >= '0' && c <= '9':
		o.obj = objDigit
	case afterNumber && pdfSpace(c):
		o.obj = objSpace
	case afterNumber && c == '%':
		o.obj = objComment
	case c == 'o' && o.obj == objSpace:
		o.obj = objO
	case c == 'b' && o.obj == objO:
		o.obj = objOB
	case c == 'j' && o.obj == objOB:
		o.obj = objOBJ
	default:
		o.obj = objNone
	}
	return nil
}

func (o *opaque) end() error {
	if o.obj == objOBJ {
		return errPDFHidden
	}
	o.obj = objNone
	return nil
}

type hiddenState int

const (
	hiddenNone hiddenState = iota
	hiddenGT
	hiddenDict
	hiddenComment
	hiddenWord
)

// hiddenStream refuses a stream inside decoded data (">> stream"): pdf.js reads streams in object streams too.
type hiddenStream struct {
	state hiddenState
	k     int
}

const streamKeyword = "stream"

func (h *hiddenStream) feed(c byte) error {
	switch h.state {
	case hiddenWord:
		if h.k == len(streamKeyword) {
			if !pdfRegular(c) {
				return errPDFHidden
			}
			h.state = hiddenNone
			return nil
		}
		if c == streamKeyword[h.k] {
			h.k++
			return nil
		}
		h.state = hiddenNone
	case hiddenComment:
		if c == '\r' || c == '\n' {
			h.state = hiddenDict
		}
		return nil
	case hiddenNone, hiddenGT, hiddenDict:
	}
	switch {
	case c == '>' && h.state == hiddenGT:
		h.state = hiddenDict
	case c == '>':
		h.state = hiddenGT
	case h.state == hiddenDict && pdfSpace(c):
	case h.state == hiddenDict && c == '%':
		h.state = hiddenComment
	case h.state == hiddenDict && c == 's':
		h.state, h.k = hiddenWord, 1
	default:
		h.state = hiddenNone
	}
	return nil
}

func (h *hiddenStream) end() error {
	if h.state == hiddenWord && h.k == len(streamKeyword) {
		return errPDFHidden
	}
	return nil
}

// nameSniffer checks every name in decoded data, inside strings or not.
type nameSniffer struct {
	in   bool
	buf  [maxPDFToken]byte
	n    int
	long bool
	hash int
	hi   byte
}

func (s *nameSniffer) feed(c byte) error {
	if !s.in {
		if c == '/' {
			s.start()
		}
		return nil
	}
	switch s.hash {
	case 1:
		s.hash = 0
		if _, ok := unhex(c); ok {
			s.hi, s.hash = c, 2
			return nil
		}
		s.add('#')
	case 2:
		s.hash = 0
		lo, ok := unhex(c)
		if ok {
			hi, _ := unhex(s.hi)
			s.add(hi<<4 | lo)
			return nil
		}
		s.add('#')
		s.add(s.hi)
	}
	if !pdfRegular(c) {
		err := s.finish()
		if c == '/' {
			s.start()
		}
		return err
	}
	if c == '#' {
		s.hash = 1
		return nil
	}
	s.add(c)
	return nil
}

func (s *nameSniffer) start() { s.in, s.n, s.long, s.hash = true, 0, false, 0 }

func (s *nameSniffer) add(c byte) {
	if s.n == len(s.buf) {
		s.long = true
		return
	}
	s.buf[s.n] = c
	s.n++
}

func (s *nameSniffer) finish() error {
	s.in = false
	if s.long {
		return nil
	}
	return checkPDFName(string(s.buf[:s.n]))
}

func (s *nameSniffer) end() error {
	if !s.in {
		return nil
	}
	switch s.hash {
	case 1:
		s.add('#')
	case 2:
		s.add('#')
		s.add(s.hi)
	}
	return s.finish()
}

// predictor undoes a Flate stream's PNG or TIFF predictor, so the scanner reads what a viewer reads.
func predictor(r io.Reader, p pdfDict) (io.Reader, error) {
	pred, err := pdfParam(p, "Predictor", 1)
	if err != nil {
		return nil, err
	}
	if pred == 1 {
		return r, nil
	}
	if pred != 2 && (pred < 10 || pred > 15) {
		return nil, pdfUnsupported("predictor")
	}
	colors, err := pdfParam(p, "Colors", 1)
	if err != nil {
		return nil, err
	}
	bpc, err := pdfParam(p, "BitsPerComponent", 8)
	if err != nil {
		return nil, err
	}
	columns, err := pdfParam(p, "Columns", 1)
	if err != nil {
		return nil, err
	}
	if colors < 1 || colors > 32 || columns < 1 || columns > maxPredictorRow || (bpc != 1 && bpc != 2 && bpc != 4 && bpc != 8 && bpc != 16) {
		return nil, pdfUnsupported("predictor parameters")
	}
	rowLen := (colors*bpc*columns + 7) / 8
	if rowLen > maxPredictorRow || pred == 2 && bpc != 8 && bpc != 16 {
		return nil, pdfUnsupported("predictor parameters")
	}
	pr := &predicted{r: r, png: pred != 2, bpp: int(max(1, (colors*bpc+7)/8)), prev: make([]byte, rowLen)}
	if pr.png {
		pr.row = make([]byte, 1+rowLen)
	} else {
		pr.row = make([]byte, rowLen)
		pr.wide = bpc == 16
	}
	return pr, nil
}

func pdfParam(p pdfDict, key string, def int64) (int64, error) {
	switch v := p[key]; v.kind {
	case pdfInt:
		return v.num, nil
	case pdfRef:
		return 0, pdfUnsupported("indirect decode parameter")
	case pdfNull:
		return def, nil
	case pdfOther, pdfName, pdfDictValue, pdfArrayValue:
		if _, ok := p[key]; ok {
			return 0, pdfMalformed("decode parameter")
		}
	}
	return def, nil
}

type predicted struct {
	r    io.Reader
	png  bool
	wide bool
	bpp  int
	row  []byte
	prev []byte
	out  []byte
	err  error
}

func (p *predicted) Read(b []byte) (int, error) {
	for len(p.out) == 0 {
		if p.err != nil {
			return 0, p.err
		}
		n, err := io.ReadFull(p.r, p.row)
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			p.err = io.EOF
		case err != nil:
			return 0, err
		}
		if n == 0 {
			continue
		}
		out, err := p.undo(p.row[:n])
		if err != nil {
			return 0, err
		}
		p.out = out
	}
	n := copy(b, p.out)
	p.out = p.out[n:]
	return n, nil
}

func (p *predicted) undo(row []byte) ([]byte, error) {
	if !p.png {
		step := p.bpp
		if p.wide {
			for i := step; i+1 < len(row); i += 2 {
				binary.BigEndian.PutUint16(row[i:], binary.BigEndian.Uint16(row[i:])+binary.BigEndian.Uint16(row[i-step:]))
			}
			return row, nil
		}
		for i := step; i < len(row); i++ {
			row[i] += row[i-step]
		}
		return row, nil
	}
	typ, cur := row[0], row[1:]
	prev, bpp := p.prev, p.bpp
	for i := range cur {
		var left, upLeft byte
		if i >= bpp {
			left, upLeft = cur[i-bpp], prev[i-bpp]
		}
		switch typ {
		case 0:
		case 1:
			cur[i] += left
		case 2:
			cur[i] += prev[i]
		case 3:
			cur[i] += left/2 + prev[i]/2 + left&prev[i]&1
		case 4:
			cur[i] += paeth(left, prev[i], upLeft)
		default:
			return nil, pdfMalformed("PNG predictor row")
		}
	}
	copy(prev, cur)
	return cur, nil
}

func paeth(a, b, c byte) byte {
	p := int(a) + int(b) - int(c)
	pa, pb, pc := abs(p-int(a)), abs(p-int(b)), abs(p-int(c))
	switch {
	case pa <= pb && pa <= pc:
		return a
	case pb <= pc:
		return b
	}
	return c
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func skipEOL(br *bufio.Reader) error {
	c, err := br.ReadByte()
	if err != nil {
		return err
	}
	if c == '\r' {
		if next, err := br.Peek(1); err == nil && next[0] == '\n' {
			_, _ = br.Discard(1) // cannot fail after a successful Peek
		}
		return nil
	}
	if c != '\n' {
		return br.UnreadByte()
	}
	return nil
}

// readPDFToken reads regular characters up to a delimiter; in names, #xx is a hex-escaped byte, so
// /J#61vaScript is /JavaScript. Overlong tokens are cut, which keeps them from matching anything.
func readPDFToken(br *bufio.Reader, name bool) (string, error) {
	buf := make([]byte, 0, 16)
	long := false
	for {
		c, err := br.ReadByte()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if !pdfRegular(c) {
			if err := br.UnreadByte(); err != nil {
				return "", err
			}
			break
		}
		if name && c == '#' {
			if hex, err := br.Peek(2); err == nil {
				hi, okHi := unhex(hex[0])
				lo, okLo := unhex(hex[1])
				if okHi && okLo {
					_, _ = br.Discard(2) // cannot fail after a successful Peek
					c = hi<<4 | lo
				}
			}
		}
		if len(buf) < maxPDFToken {
			buf = append(buf, c)
		} else {
			long = true
		}
	}
	if long {
		return "", nil
	}
	return string(buf), nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func pdfSpace(c byte) bool {
	switch c {
	case 0, '\t', '\n', '\f', '\r', ' ':
		return true
	}
	return false
}

func pdfRegular(c byte) bool {
	switch c {
	case 0, '\t', '\n', '\f', '\r', ' ', '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return false
	}
	return true
}

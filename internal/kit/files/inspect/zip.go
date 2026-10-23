package inspect

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

const (
	eocdSignature        = 0x06054b50
	eocdLen              = 22
	zip64LocatorSig      = 0x07064b50
	zip64LocatorLen      = 20
	zip64EOCDSig         = 0x06064b50
	zip64EOCDLen         = 56
	maxDirBytesPerEntry  = 4 << 10
	minDirEntry          = 46
	ratioFloor           = 1 << 20
	contentTypesPartName = "[content_types].xml"
)

// openZip reads the entry count and directory size from the end records first and binds them to the
// directory's position, so an archive that holds millions of entries is refused before archive/zip reads
// its directory into memory.
func openZip(src io.ReaderAt, size int64, l Limits) (*zip.Reader, error) {
	entries, dirSize, err := directoryOf(src, size)
	if err != nil {
		return nil, err
	}
	if entries > uint64(l.MaxEntries) { //nolint:gosec // limits are positive after withDefaults
		return nil, fmt.Errorf("%w: %d archive entries", ErrBudget, entries)
	}
	if dirSize > max(entries, 1)*maxDirBytesPerEntry {
		return nil, fmt.Errorf("%w: archive directory too large", ErrBudget)
	}
	zr, err := zip.NewReader(src, size)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(zr.File) > l.MaxEntries {
		return nil, fmt.Errorf("%w: %d archive entries", ErrBudget, len(zr.File))
	}
	return zr, nil
}

func directoryOf(src io.ReaderAt, size int64) (entries, dirSize uint64, err error) {
	tailLen := min(size, eocdLen+0xFFFF)
	if tailLen < eocdLen {
		return 0, 0, ErrMalformed
	}
	tail := make([]byte, tailLen)
	if _, err := src.ReadAt(tail, size-tailLen); err != nil && !errors.Is(err, io.EOF) {
		return 0, 0, err
	}
	at := -1
	for i := len(tail) - eocdLen; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) == eocdSignature &&
			i+eocdLen+int(binary.LittleEndian.Uint16(tail[i+20:])) <= len(tail) {
			at = i
			break
		}
	}
	if at < 0 {
		return 0, 0, ErrMalformed
	}
	rec := tail[at:]
	entries = uint64(binary.LittleEndian.Uint16(rec[10:]))
	dirSize = uint64(binary.LittleEndian.Uint32(rec[12:]))
	dirOffset := uint64(binary.LittleEndian.Uint32(rec[16:]))
	eocdAt := size - tailLen + int64(at)
	if entries != 0xFFFF && dirSize != 0xFFFFFFFF && dirOffset != 0xFFFFFFFF {
		// the 16-bit count is compared modulo 65536 by archive/zip, so the directory must not have room
		// for 65536 more entries than it claims
		if dirOffset+dirSize != uint64(eocdAt) || dirSize >= (entries+0x10000)*minDirEntry { //nolint:gosec // eocdAt is an offset in the file
			return 0, 0, fmt.Errorf("%w: archive directory does not match its end record", ErrMalformed)
		}
		return entries, dirSize, nil
	}
	if eocdAt < zip64LocatorLen {
		return 0, 0, ErrMalformed
	}
	loc := make([]byte, zip64LocatorLen)
	if _, err := src.ReadAt(loc, eocdAt-zip64LocatorLen); err != nil {
		return 0, 0, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if binary.LittleEndian.Uint32(loc) != zip64LocatorSig {
		return 0, 0, ErrMalformed
	}
	off := binary.LittleEndian.Uint64(loc[8:])
	if size < zip64EOCDLen || off > uint64(size-zip64EOCDLen) { //nolint:gosec // checked not negative first
		return 0, 0, ErrMalformed
	}
	rec64 := make([]byte, zip64EOCDLen)
	if _, err := src.ReadAt(rec64, int64(off)); err != nil { //nolint:gosec // off is below size, an int64
		return 0, 0, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if binary.LittleEndian.Uint32(rec64) != zip64EOCDSig {
		return 0, 0, ErrMalformed
	}
	entries, dirSize, dirOffset = binary.LittleEndian.Uint64(rec64[32:]), binary.LittleEndian.Uint64(rec64[40:]), binary.LittleEndian.Uint64(rec64[48:])
	if dirOffset > off || off-dirOffset != dirSize {
		return 0, 0, fmt.Errorf("%w: archive directory does not match its end record", ErrMalformed)
	}
	return entries, dirSize, nil
}

func zipType(zr *zip.Reader) string {
	names := make(map[string]bool, len(zr.File))
	for _, f := range zr.File {
		names[f.Name] = true
	}
	if !names["[Content_Types].xml"] {
		return TypeZip
	}
	switch {
	case names["word/document.xml"]:
		return TypeDocx
	case names["xl/workbook.xml"]:
		return TypeXlsx
	case names["ppt/presentation.xml"]:
		return TypePptx
	}
	return TypeZip
}

func (in *Inspector) walkZip(ctx context.Context, zr *zip.Reader, depth int, b *budget) error {
	ooxml := false
	for _, f := range zr.File {
		if strings.EqualFold(f.Name, contentTypesPartName) {
			ooxml = true
		}
	}
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := in.checkEntry(ctx, f, ooxml, depth, b); err != nil {
			return err
		}
	}
	return nil
}

func (in *Inspector) checkEntry(ctx context.Context, f *zip.File, ooxml bool, depth int, b *budget) error {
	if !safeEntryName(f.Name) {
		return fmt.Errorf("%w: unsafe entry name", ErrMalformed)
	}
	lower := strings.ToLower(f.Name)
	if ooxml {
		if what := activePart(lower); what != "" {
			return fmt.Errorf("%w: %s", ErrActiveContent, what)
		}
	}
	declared := f.UncompressedSize64
	if declared > uint64(max(0, b.left)) {
		return fmt.Errorf("%w: entry larger than the remaining budget", ErrBudget)
	}
	if declared > ratioFloor && (f.CompressedSize64 == 0 || declared/f.CompressedSize64 > uint64(in.limits.MaxRatio)) { //nolint:gosec // limits are positive after withDefaults
		return fmt.Errorf("%w: compression ratio", ErrBudget)
	}
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	defer func() { _ = rc.Close() }()
	r := bufio.NewReader(b.reader(rc))
	if err := in.checkContent(ctx, r, lower, ooxml, depth, b); err != nil {
		return readError(err)
	}
	_, err = io.Copy(io.Discard, r)
	return readError(err)
}

func (in *Inspector) checkContent(ctx context.Context, r *bufio.Reader, lower string, ooxml bool, depth int, b *budget) error {
	if head, _ := r.Peek(4); bytes.Equal(head, []byte("PK\x03\x04")) {
		return in.nested(ctx, r, depth, b)
	}
	if !ooxml {
		return nil
	}
	switch {
	case lower == contentTypesPartName:
		return checkContentTypes(r)
	case strings.HasSuffix(lower, ".rels"):
		return checkRelationships(r)
	}
	return nil
}

func (in *Inspector) nested(ctx context.Context, r io.Reader, depth int, b *budget) error {
	if depth >= in.limits.MaxDepth {
		return fmt.Errorf("%w: archives nested too deep", ErrBudget)
	}
	data, err := io.ReadAll(io.LimitReader(r, in.limits.MaxNestedBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > in.limits.MaxNestedBytes {
		return fmt.Errorf("%w: nested archive too large", ErrBudget)
	}
	zr, err := openZip(bytes.NewReader(data), int64(len(data)), in.limits)
	if err != nil {
		return err
	}
	return in.walkZip(ctx, zr, depth+1, b)
}

func readError(err error) error {
	if err == nil || errors.Is(err, ErrBudget) || errors.Is(err, ErrActiveContent) || errors.Is(err, ErrMalformed) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrMalformed, err)
}

// safeEntryName refuses names that would escape a directory when someone extracts the archive.
func safeEntryName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, `\`) || strings.Contains(name, ":") {
		return false
	}
	for seg := range strings.SplitSeq(name, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

func activePart(lower string) string {
	switch {
	case strings.HasSuffix(lower, "vbaproject.bin"), strings.HasSuffix(lower, "vbadata.xml"), strings.Contains(lower, "macrosheets/"):
		return "macros"
	case strings.Contains(lower, "/activex/"):
		return "ActiveX control"
	case strings.Contains(lower, "/embeddings/") && (strings.HasSuffix(lower, ".bin") || strings.Contains(path.Base(lower), "oleobject")):
		return "OLE object"
	}
	return ""
}

func checkContentTypes(r io.Reader) error {
	return eachElement(r, func(el xml.StartElement) error {
		if el.Name.Local != "Default" && el.Name.Local != "Override" {
			return nil
		}
		ct, err := attr(el, "ContentType")
		if err != nil {
			return err
		}
		ct = strings.ToLower(ct)
		for _, bad := range []string{"macroenabled", "vbaproject", "macrosheet", "activex", "oleobject"} {
			if strings.Contains(ct, bad) {
				return fmt.Errorf("%w: %s part", ErrActiveContent, bad)
			}
		}
		return nil
	})
}

// checkRelationships refuses macro, OLE and ActiveX relationships and any external target except a
// hyperlink: external templates, frames and images are fetched when the document opens.
func checkRelationships(r io.Reader) error {
	return eachElement(r, func(el xml.StartElement) error {
		if el.Name.Local != "Relationship" {
			return nil
		}
		typ, err := attr(el, "Type")
		if err != nil {
			return err
		}
		if _, err := attr(el, "Target"); err != nil {
			return err
		}
		mode, err := attr(el, "TargetMode")
		if err != nil {
			return err
		}
		typ = strings.ToLower(typ)
		for _, bad := range []string{"/vbaproject", "/oleobject", "/activexcontrol", "/control", "macrosheet"} {
			if strings.HasSuffix(typ, bad) || bad == "macrosheet" && strings.Contains(typ, bad) {
				return fmt.Errorf("%w: %s relationship", ErrActiveContent, strings.TrimPrefix(bad, "/"))
			}
		}
		if strings.EqualFold(mode, "External") && !strings.HasSuffix(typ, "/hyperlink") {
			return fmt.Errorf("%w: external relationship", ErrActiveContent)
		}
		return nil
	})
}

func eachElement(r io.Reader, fn func(xml.StartElement) error) error {
	dec := xml.NewDecoder(r)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return readError(err)
		}
		if el, ok := tok.(xml.StartElement); ok {
			if err := fn(el); err != nil {
				return err
			}
		}
	}
}

// attr returns the unqualified attribute name. A namespaced attribute of the same local name, or a
// repeated one, is refused: Office reads only the unqualified one, and a scanner that read another
// could be shown a harmless value.
func attr(el xml.StartElement, name string) (string, error) {
	value, seen := "", false
	for _, a := range el.Attr {
		if a.Name.Local != name {
			continue
		}
		if a.Name.Space != "" || seen {
			return "", fmt.Errorf("%w: ambiguous %s attribute", ErrActiveContent, name)
		}
		value, seen = a.Value, true
	}
	return value, nil
}

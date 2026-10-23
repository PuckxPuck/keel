// Package inspect detects a file's type from its content and refuses content that is dangerous to keep or
// serve: archive bombs, active content in office files and PDFs, oversized images and text that is not UTF-8.
package inspect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	TypePDF     = "application/pdf"
	TypePNG     = "image/png"
	TypeJPEG    = "image/jpeg"
	TypeGIF     = "image/gif"
	TypeWebP    = "image/webp"
	TypeZip     = "application/zip"
	TypeDocx    = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	TypeXlsx    = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	TypePptx    = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	TypeText    = "text/plain; charset=utf-8"
	TypeUnknown = "application/octet-stream"
)

var (
	ErrMalformed     = errors.New("inspect: the file is malformed")
	ErrBudget        = errors.New("inspect: the file expands past the allowed budget")
	ErrActiveContent = errors.New("inspect: the file holds active content")
	ErrImageTooLarge = errors.New("inspect: the image is too large")
	ErrNotText       = errors.New("inspect: the text is not UTF-8 or holds NUL bytes")
	ErrUnsupported   = errors.New("inspect: the file type cannot be inspected")
)

// Limits bound inspection; zero fields take the defaults.
type Limits struct {
	MaxEntries     int   // archive entries, read from the archive's end record before its directory
	MaxRatio       int64 // compression ratio of one entry larger than 1 MiB
	MaxDecoded     int64 // decoded bytes across every entry, nested archive and PDF stream of one file
	MaxDepth       int   // nested archives
	MaxNestedBytes int64 // a nested archive is held in memory, so it has its own cap
	MaxPixels      int64
	MaxDimension   int
	MaxImageBytes  int64 // decoded bytes of one image: pixels times bytes per pixel times frames
}

func (l Limits) withDefaults() Limits {
	if l.MaxEntries <= 0 {
		l.MaxEntries = 10000
	}
	if l.MaxRatio <= 0 {
		l.MaxRatio = 200
	}
	if l.MaxDecoded <= 0 {
		l.MaxDecoded = 256 << 20
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = 2
	}
	if l.MaxNestedBytes <= 0 {
		l.MaxNestedBytes = 16 << 20
	}
	if l.MaxPixels <= 0 {
		l.MaxPixels = 50_000_000
	}
	if l.MaxDimension <= 0 {
		l.MaxDimension = 20000
	}
	if l.MaxImageBytes <= 0 {
		l.MaxImageBytes = 128 << 20
	}
	return l
}

// Scanner is an antivirus hook (for example ClamAV over its socket). keel ships none.
type Scanner interface {
	Scan(ctx context.Context, r io.Reader, size int64) error
}

// Inspector runs at most concurrency inspections at once; decoding is CPU and memory heavy.
type Inspector struct {
	limits Limits
	sem    chan struct{}
}

func New(limits Limits, concurrency int) *Inspector {
	return &Inspector{limits: limits.withDefaults(), sem: make(chan struct{}, max(1, concurrency))}
}

func (in *Inspector) acquire(ctx context.Context) (func(), error) {
	select {
	case in.sem <- struct{}{}:
		return func() { <-in.sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Detect names the file's type from its content, never from its name.
func (in *Inspector) Detect(ctx context.Context, src io.ReaderAt, size int64) (string, error) {
	release, err := in.acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	head := make([]byte, min(size, 512))
	if _, err := src.ReadAt(head, 0); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	switch {
	case bytes.HasPrefix(head, []byte("%PDF-")):
		return TypePDF, nil
	case bytes.HasPrefix(head, []byte("\x89PNG\r\n\x1a\n")):
		return TypePNG, nil
	case bytes.HasPrefix(head, []byte{0xFF, 0xD8, 0xFF}):
		return TypeJPEG, nil
	case bytes.HasPrefix(head, []byte("GIF87a")), bytes.HasPrefix(head, []byte("GIF89a")):
		return TypeGIF, nil
	case len(head) >= 12 && bytes.Equal(head[:4], []byte("RIFF")) && bytes.Equal(head[8:12], []byte("WEBP")):
		return TypeWebP, nil
	case bytes.HasPrefix(head, []byte("PK\x03\x04")), bytes.HasPrefix(head, []byte("PK\x05\x06")):
		zr, err := openZip(src, size, in.limits)
		if err != nil {
			return "", err
		}
		return zipType(zr), nil
	case looksLikeText(head, size):
		return TypeText, nil
	}
	return TypeUnknown, nil
}

func looksLikeText(head []byte, size int64) bool {
	if len(head) == 0 || bytes.IndexByte(head, 0) >= 0 {
		return false
	}
	if int64(len(head)) < size {
		head = trimPartialRune(head)
	}
	return utf8.Valid(head)
}

// Inspect refuses dangerous content of type mime. PNG and JPEG are re-encoded into out to drop their
// metadata; GIF and WebP are only size-checked and keep theirs. rewritten reports whether out now holds
// the content to keep.
func (in *Inspector) Inspect(ctx context.Context, src io.ReaderAt, size int64, mime string, out io.Writer) (rewritten bool, err error) {
	release, err := in.acquire(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	b := &budget{left: in.limits.MaxDecoded}
	switch mime {
	case TypeZip, TypeDocx, TypeXlsx, TypePptx:
		zr, err := openZip(src, size, in.limits)
		if err != nil {
			return false, err
		}
		return false, in.walkZip(ctx, zr, 1, b)
	case TypePDF:
		return false, in.checkPDF(ctx, io.NewSectionReader(src, 0, size), b)
	case TypePNG, TypeJPEG:
		return true, in.reencode(io.NewSectionReader(src, 0, size), mime, out)
	case TypeGIF:
		return false, in.checkGIF(io.NewSectionReader(src, 0, size))
	case TypeWebP:
		return false, in.checkWebP(src, size)
	case TypeText:
		return false, checkText(io.NewSectionReader(src, 0, size))
	}
	return false, fmt.Errorf("%w: %s", ErrUnsupported, mime)
}

// budget is the decoded bytes one file may still produce, shared by every entry and nesting level.
type budget struct{ left int64 }

func (b *budget) reader(r io.Reader) io.Reader { return &budgetReader{r: r, b: b} }

type budgetReader struct {
	r io.Reader
	b *budget
}

func (br *budgetReader) Read(p []byte) (int, error) {
	if br.b.left <= 0 {
		// one more byte tells a stream that ends exactly at the budget from one that goes past it
		var one [1]byte
		for {
			n, err := br.r.Read(one[:])
			if n > 0 {
				return 0, ErrBudget
			}
			if err != nil {
				return 0, err
			}
		}
	}
	if int64(len(p)) > br.b.left {
		p = p[:br.b.left]
	}
	n, err := br.r.Read(p)
	br.b.left -= int64(n)
	return n, err
}

func checkText(r io.Reader) error {
	buf := make([]byte, 32<<10)
	var carry []byte
	for {
		n, err := r.Read(buf[len(carry):])
		chunk := buf[:len(carry)+n]
		if bytes.IndexByte(chunk, 0) >= 0 {
			return ErrNotText
		}
		done := errors.Is(err, io.EOF)
		if err != nil && !done {
			return err
		}
		valid := chunk
		if !done {
			valid = trimPartialRune(chunk)
		}
		if !utf8.Valid(valid) {
			return ErrNotText
		}
		if done {
			return nil
		}
		carry = append(carry[:0], chunk[len(valid):]...)
		copy(buf, carry)
	}
}

// trimPartialRune drops an incomplete rune at the end of b so the next chunk can complete it.
func trimPartialRune(b []byte) []byte {
	for i := 1; i <= utf8.UTFMax && i <= len(b); i++ {
		if utf8.RuneStart(b[len(b)-i]) {
			if !utf8.FullRune(b[len(b)-i:]) {
				return b[:len(b)-i]
			}
			return b
		}
	}
	return b
}

// Package barcode renders QR codes, Code 128 and EAN-13 as PNG or SVG, over boombuler/barcode.
package barcode

import (
	"bytes"
	"errors"
	"fmt"
	"image/png"
	"strconv"
	"strings"
	"unicode/utf8"

	bc "github.com/boombuler/barcode"
	"github.com/boombuler/barcode/code128"
	"github.com/boombuler/barcode/ean"
	"github.com/boombuler/barcode/qr"
)

type Level int

const (
	LevelL Level = iota // about 7 percent recovery
	LevelM
	LevelQ
	LevelH
)

const (
	maxQRBytes      = 2048
	maxCode128Runes = 80
	maxPixels       = 4096
	quietModules    = 4
)

var (
	ErrContent    = errors.New("barcode: content cannot be encoded")
	ErrCheckDigit = errors.New("barcode: EAN-13 check digit does not match")
	ErrSize       = errors.New("barcode: size is out of range")
)

func (l Level) qr() (qr.ErrorCorrectionLevel, error) {
	switch l {
	case LevelL:
		return qr.L, nil
	case LevelM:
		return qr.M, nil
	case LevelQ:
		return qr.Q, nil
	case LevelH:
		return qr.H, nil
	}
	return 0, fmt.Errorf("barcode: unknown QR level %d", int(l))
}

func encodeQR(content string, level Level) (bc.Barcode, error) {
	if content == "" || len(content) > maxQRBytes || !utf8.ValidString(content) {
		return nil, ErrContent
	}
	ql, err := level.qr()
	if err != nil {
		return nil, err
	}
	code, err := qr.Encode(content, ql, qr.Auto)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrContent, err)
	}
	return code, nil
}

// QR renders content as a size by size PNG.
func QR(content string, size int, level Level) ([]byte, error) {
	code, err := encodeQR(content, level)
	if err != nil {
		return nil, err
	}
	return pngOf(code, size, size)
}

// QRSVG renders content as a size by size SVG with a quiet zone.
func QRSVG(content string, size int, level Level) ([]byte, error) {
	if size < 1 || size > maxPixels {
		return nil, ErrSize
	}
	code, err := encodeQR(content, level)
	if err != nil {
		return nil, err
	}
	b := code.Bounds()
	modules := b.Dx() + 2*quietModules
	var path strings.Builder
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if r, _, _, _ := code.At(x, y).RGBA(); r < 0x8000 {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x-b.Min.X+quietModules, y-b.Min.Y+quietModules)
			}
		}
	}
	var out bytes.Buffer
	n := strconv.Itoa(modules)
	out.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="` + strconv.Itoa(size) + `" height="` + strconv.Itoa(size) +
		`" viewBox="0 0 ` + n + " " + n + `" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><path fill="#000" d="`)
	out.WriteString(path.String())
	out.WriteString(`"/></svg>`)
	return out.Bytes(), nil
}

// Code128 renders printable ASCII content as a width by height PNG.
func Code128(content string, width, height int) ([]byte, error) {
	if content == "" || len(content) > maxCode128Runes {
		return nil, ErrContent
	}
	for i := range len(content) {
		if content[i] < 0x20 || content[i] > 0x7e {
			return nil, ErrContent
		}
	}
	code, err := code128.Encode(content)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrContent, err)
	}
	return pngOf(code, width, height)
}

// EAN13 renders a 13-digit code whose last digit must be its check digit.
func EAN13(code string, width, height int) ([]byte, error) {
	if err := ValidEAN13(code); err != nil {
		return nil, err
	}
	enc, err := ean.Encode(code)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrContent, err)
	}
	return pngOf(enc, width, height)
}

// ValidEAN13 checks the length, the digits and the check digit.
func ValidEAN13(code string) error {
	if len(code) != 13 {
		return ErrContent
	}
	sum := 0
	for i := range 12 {
		c := code[i]
		if c < '0' || c > '9' {
			return ErrContent
		}
		d := int(c - '0')
		if i%2 == 1 {
			d *= 3
		}
		sum += d
	}
	if code[12] < '0' || code[12] > '9' {
		return ErrContent
	}
	if int(code[12]-'0') != (10-sum%10)%10 {
		return ErrCheckDigit
	}
	return nil
}

func pngOf(code bc.Barcode, width, height int) ([]byte, error) {
	if width < 1 || height < 1 || width > maxPixels || height > maxPixels {
		return nil, ErrSize
	}
	scaled, err := bc.Scale(code, width, height)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSize, err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, scaled); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

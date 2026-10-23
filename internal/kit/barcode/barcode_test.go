package barcode_test

import (
	"bytes"
	"image/png"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/barcode"
)

func TestValidEAN13(t *testing.T) {
	cases := []struct {
		code string
		want error
	}{
		{"4006381333931", nil},
		{"4006381333932", barcode.ErrCheckDigit},
		{"400638133393", barcode.ErrContent},
		{"400638133393a", barcode.ErrContent},
		{"40063813339310", barcode.ErrContent},
	}
	for _, c := range cases {
		t.Run(c.code, func(t *testing.T) {
			err := barcode.ValidEAN13(c.code)
			if c.want == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, c.want)
		})
	}
}

func TestRender(t *testing.T) {
	qr, err := barcode.QR("https://example.com/i/42", 256, barcode.LevelM)
	require.NoError(t, err)
	img, err := png.Decode(bytes.NewReader(qr))
	require.NoError(t, err)
	assert.Equal(t, 256, img.Bounds().Dx())

	svg, err := barcode.QRSVG("https://example.com/i/42", 256, barcode.LevelM)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(svg), "<svg ") && strings.Contains(string(svg), "h1v1h-1z"))

	_, err = barcode.Code128("INV-2026-0042", 400, 80)
	require.NoError(t, err)
	_, err = barcode.EAN13("4006381333931", 300, 100)
	require.NoError(t, err)

	_, err = barcode.Code128("tab\there", 400, 80)
	require.ErrorIs(t, err, barcode.ErrContent)
	_, err = barcode.QR("x", 100000, barcode.LevelL)
	require.ErrorIs(t, err, barcode.ErrSize)
}

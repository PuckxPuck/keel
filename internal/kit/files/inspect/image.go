package inspect

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"

	"golang.org/x/image/webp"
)

const jpegQuality = 90

// reencode checks the dimensions and decoded size in the header before decoding anything, then decodes
// and encodes the pixels again, which drops EXIF, XMP, ICC and anything appended after the image data.
func (in *Inspector) reencode(src io.ReadSeeker, mime string, out io.Writer) error {
	cfg, format, err := image.DecodeConfig(src)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if (mime == TypePNG && format != "png") || (mime == TypeJPEG && format != "jpeg") {
		return fmt.Errorf("%w: image format does not match its content", ErrMalformed)
	}
	if err := in.checkImageSize(cfg.Width, cfg.Height, 1, bytesPerPixel(cfg.ColorModel)); err != nil {
		return err
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	img, _, err := image.Decode(src)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if mime == TypePNG {
		return png.Encode(out, img)
	}
	return jpeg.Encode(out, img, &jpeg.Options{Quality: jpegQuality})
}

func (in *Inspector) checkImageSize(w, h int, frames, bpp int64) error {
	l := in.limits
	if w <= 0 || h <= 0 || w > l.MaxDimension || h > l.MaxDimension {
		return fmt.Errorf("%w: %dx%d", ErrImageTooLarge, w, h)
	}
	px := int64(w) * int64(h)
	if px > l.MaxPixels || frames > l.MaxImageBytes/(px*bpp) {
		return fmt.Errorf("%w: %dx%d, %d frames", ErrImageTooLarge, w, h, frames)
	}
	return nil
}

// bytesPerPixel is what image.Decode allocates per pixel for the colour model; unknown models count as the widest.
func bytesPerPixel(m color.Model) int64 {
	if _, ok := m.(color.Palette); ok {
		return 1
	}
	switch m {
	case color.GrayModel, color.AlphaModel:
		return 1
	case color.Gray16Model, color.Alpha16Model:
		return 2
	case color.YCbCrModel:
		return 3
	case color.RGBAModel, color.NRGBAModel, color.CMYKModel, color.NYCbCrAModel:
		return 4
	}
	return 8
}

// checkGIF walks the blocks for the screen size and frame count; GIF is kept as uploaded, not re-encoded.
func (in *Inspector) checkGIF(r io.Reader) error {
	br := bufio.NewReader(r)
	var head [13]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	w, h := int(binary.LittleEndian.Uint16(head[6:])), int(binary.LittleEndian.Uint16(head[8:]))
	if err := in.checkImageSize(w, h, 1, 1); err != nil {
		return err
	}
	if err := skipColorTable(br, head[10]); err != nil {
		return err
	}
	screen := int64(w) * int64(h)
	var frames, cost int64
	for {
		b, err := br.ReadByte()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrMalformed, err)
		}
		switch b {
		case 0x3B:
			if frames == 0 {
				return fmt.Errorf("%w: GIF without frames", ErrMalformed)
			}
			return nil
		case 0x21:
			if _, err := br.ReadByte(); err != nil {
				return fmt.Errorf("%w: %w", ErrMalformed, err)
			}
		case 0x2C:
			var desc [9]byte
			if _, err := io.ReadFull(br, desc[:]); err != nil {
				return fmt.Errorf("%w: %w", ErrMalformed, err)
			}
			fw, fh := int(binary.LittleEndian.Uint16(desc[4:])), int(binary.LittleEndian.Uint16(desc[6:]))
			if err := in.checkImageSize(fw, fh, 1, 1); err != nil {
				return err
			}
			frames++
			if cost += max(screen, int64(fw)*int64(fh)); cost > in.limits.MaxImageBytes {
				return fmt.Errorf("%w: %d frames", ErrImageTooLarge, frames)
			}
			if err := skipColorTable(br, desc[8]); err != nil {
				return err
			}
			if _, err := br.ReadByte(); err != nil { // LZW minimum code size
				return fmt.Errorf("%w: %w", ErrMalformed, err)
			}
		default:
			return fmt.Errorf("%w: GIF block", ErrMalformed)
		}
		if err := skipSubBlocks(br); err != nil {
			return err
		}
	}
}

func skipColorTable(br *bufio.Reader, flags byte) error {
	if flags&0x80 == 0 {
		return nil
	}
	if _, err := br.Discard(3 << ((flags & 7) + 1)); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return nil
}

func skipSubBlocks(br *bufio.Reader) error {
	for {
		n, err := br.ReadByte()
		if err == nil && n > 0 {
			_, err = br.Discard(int(n))
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrMalformed, err)
		}
		if n == 0 {
			return nil
		}
	}
}

// checkWebP reads the canvas from the header and counts animation frames; WebP is kept as uploaded.
func (in *Inspector) checkWebP(src io.ReaderAt, size int64) error {
	cfg, err := webp.DecodeConfig(io.NewSectionReader(src, 0, size))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	frames, err := webpFrames(src, size)
	if err != nil {
		return err
	}
	return in.checkImageSize(cfg.Width, cfg.Height, frames, bytesPerPixel(cfg.ColorModel))
}

// webpFrames counts ANMF chunks in the RIFF container; a still image is one frame.
func webpFrames(src io.ReaderAt, size int64) (int64, error) {
	var frames int64
	var hdr [8]byte
	for at := int64(12); at < size; {
		if _, err := src.ReadAt(hdr[:], at); err != nil {
			return 0, fmt.Errorf("%w: webp chunk: %w", ErrMalformed, err)
		}
		if string(hdr[:4]) == "ANMF" {
			frames++
		}
		n := int64(binary.LittleEndian.Uint32(hdr[4:]))
		at += 8 + n + n&1
	}
	return max(frames, 1), nil
}

package files

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ContentDisposition is an RFC 6266 attachment header: an ASCII fallback filename (without '%', which
// some clients decode) plus the exact name in RFC 8187 encoding, so no name can break out of the header
// or change its meaning.
func ContentDisposition(name string) string {
	var fallback, encoded strings.Builder
	for _, r := range name {
		if r < utf8.RuneSelf && r > 0x1f && r != 0x7f && r != '"' && r != '\\' && r != '%' {
			fallback.WriteRune(r)
		} else {
			fallback.WriteByte('_')
		}
	}
	for _, b := range []byte(name) {
		if attrChar(b) {
			encoded.WriteByte(b)
		} else {
			fmt.Fprintf(&encoded, "%%%02X", b)
		}
	}
	return `attachment; filename="` + fallback.String() + `"; filename*=UTF-8''` + encoded.String()
}

func attrChar(b byte) bool {
	if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
		return true
	}
	return strings.IndexByte("!#$&+-.^_`|~", b) >= 0
}

// cleanName keeps the last path element of a client's file name, without control characters, cut to
// 255 bytes on a rune boundary.
func cleanName(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError || unicode.Is(unicode.Bidi_Control, r) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	for len(name) > maxName {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	if name == "" || name == "." || name == ".." {
		return "file"
	}
	return name
}

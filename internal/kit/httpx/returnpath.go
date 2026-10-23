package httpx

import (
	"net/url"
	"strings"
)

const maxReturnPath = 2048

// SafeReturnPath accepts only a same-site absolute path, so a redirect to it cannot leave the site.
// Anything outside printable ASCII must arrive percent-encoded, because the result goes into a Location header.
func SafeReturnPath(raw string) (string, bool) {
	if raw == "" || len(raw) > maxReturnPath || raw[0] != '/' || !printableASCII(raw) || !plainPath(raw) {
		return "", false
	}
	if decoded, err := url.PathUnescape(raw); err != nil || !plainPath(decoded) {
		return "", false
	}
	return raw, true
}

func printableASCII(s string) bool {
	for i := range len(s) {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// plainPath rejects protocol-relative starts, backslashes and control characters, which browsers normalise into other hosts.
func plainPath(s string) bool {
	if strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/\\") || strings.Contains(s, "\\") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

package jobs

import (
	"regexp"
	"unicode/utf8"
)

const maxErrorText = 1000

var (
	emailPattern  = regexp.MustCompile(`[^\s@<>"'(),;:]+@[^\s@<>"'(),;:]+\.[A-Za-z]{2,}`)
	queryPattern  = regexp.MustCompile(`([?&][^=\s&#]+=)[^\s&#"']*`)
	secretPattern = regexp.MustCompile(`[A-Za-z0-9_\-+/=.]{32,}`)
)

// Redact prepares error text for storage: email addresses, URL query values and long token-like
// strings are replaced, and the result is capped at 1000 characters.
func Redact(s string) string {
	s = emailPattern.ReplaceAllString(s, "[email]")
	s = queryPattern.ReplaceAllString(s, "${1}[redacted]")
	s = secretPattern.ReplaceAllString(s, "[redacted]")
	if utf8.RuneCountInString(s) <= maxErrorText {
		return s
	}
	r := []rune(s)
	return string(r[:maxErrorText-3]) + "..."
}

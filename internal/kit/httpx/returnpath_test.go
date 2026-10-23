package httpx_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/PuckxPuck/keel/internal/kit/httpx"
)

var returnPathCases = []struct {
	raw string
	ok  bool
}{
	{"/", true},
	{"/dashboard?tab=1#top", true},
	{"/a/b%20c", true},
	{"", false},
	{"dashboard", false},
	{"//evil.example", false},
	{"/\\evil.example", false},
	{"/a\\b", false},
	{"https://evil.example", false},
	{"javascript:alert(1)", false},
	{"/%2F/evil.example", false},
	{"/%5Cevil.example", false},
	{"/\t/evil.example", false},
	{"/a\nb", false},
	{"/%0d%0aSet-Cookie:x=1", false},
	{"/caf%C3%A9", true},
	{"/caf\u00e9", false},
	{"/\xff", false},
	{"/a b", false},
	{"/" + strings.Repeat("a", 3000), false},
}

func TestSafeReturnPath(t *testing.T) {
	for _, tt := range returnPathCases {
		got, ok := httpx.SafeReturnPath(tt.raw)
		assert.Equal(t, tt.ok, ok, tt.raw)
		if ok {
			assert.Equal(t, tt.raw, got)
		}
	}
}

func FuzzSafeReturnPath(f *testing.F) {
	for _, tt := range returnPathCases {
		f.Add(tt.raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, ok := httpx.SafeReturnPath(raw)
		if !ok {
			return
		}
		if !strings.HasPrefix(got, "/") || strings.HasPrefix(got, "//") || strings.ContainsAny(got, "\\\r\n\t") {
			t.Fatalf("unsafe path accepted: %q", got)
		}
		for i := range len(got) {
			if got[i] <= ' ' || got[i] >= 0x7f {
				t.Fatalf("raw byte %#x accepted in %q", got[i], got)
			}
		}
	})
}

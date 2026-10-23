package config

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

type ByteSize int64

var byteUnits = []struct {
	label string
	shift uint
}{
	{"GiB", 30},
	{"MiB", 20},
	{"KiB", 10},
	{"B", 0},
}

func (b *ByteSize) UnmarshalText(text []byte) error {
	s := strings.ToLower(strings.TrimSpace(string(text)))
	var shift uint
	for _, u := range byteUnits {
		if suffix := strings.ToLower(u.label); strings.HasSuffix(s, suffix) {
			s, shift = strings.TrimSpace(strings.TrimSuffix(s, suffix)), u.shift
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return fmt.Errorf("invalid byte size %q: use a number with an optional B, KiB, MiB or GiB suffix", string(text))
	}
	if n > math.MaxInt64>>shift {
		return fmt.Errorf("byte size %q is too large", string(text))
	}
	*b = ByteSize(n << shift)
	return nil
}

func (b ByteSize) MarshalText() ([]byte, error) { return []byte(b.String()), nil }

func (b ByteSize) String() string {
	n := int64(b)
	for _, u := range byteUnits[:3] {
		if n != 0 && n&(1<<u.shift-1) == 0 {
			return strconv.FormatInt(n>>u.shift, 10) + u.label
		}
	}
	return strconv.FormatInt(n, 10)
}

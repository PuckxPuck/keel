package apikeys

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/ids"
)

var testFormat = Format{Prefix: "myapp", Env: EnvTest}

func TestParse_RejectsBeforeAnyLookup(t *testing.T) {
	id := ids.New()
	key, hash := testFormat.newKey(id)
	gotID, gotHash, err := testFormat.Parse(key)
	require.NoError(t, err)
	assert.Equal(t, id, gotID)
	assert.Equal(t, hash, gotHash)
	assert.Regexp(t, `^myapp_test_[0-7][0-9A-HJKMNP-TV-Z]{25}_[0-9A-Za-z]{49}$`, key, "the documented scanner pattern")

	flip := func(s string, i int) string {
		b := []byte(s)
		if b[i] == 'a' {
			b[i] = 'b'
		} else {
			b[i] = 'a'
		}
		return string(b)
	}
	tests := map[string]string{
		"a typo in the secret":   flip(key, len(key)-10),
		"a typo in the checksum": flip(key, len(key)-1),
		"a typo in the id":       flip(key, len("myapp_test_")+3),
		"another prefix":         "other" + strings.TrimPrefix(key, "myapp"),
		"another environment":    strings.Replace(key, "_test_", "_live_", 1),
		"truncated":              key[:len(key)-1],
		"empty":                  "",
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := testFormat.Parse(raw)
			require.ErrorIs(t, err, ErrMalformed)
		})
	}
}

func FuzzParse(f *testing.F) {
	key, _ := testFormat.newKey(ids.New())
	for _, seed := range []string{key, "", "myapp_test_", key[:len(key)-6] + "000000", strings.ToLower(key), "myapp_test_" + strings.Repeat("Z", 76)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		id, hash, err := testFormat.Parse(raw)
		if err != nil {
			return
		}
		if id == uuid.Nil || len(hash) != 32 || encodeID(id) != raw[len("myapp_test_"):len("myapp_test_")+idLen] {
			t.Fatalf("Parse accepted %q with id %s", raw, id)
		}
	})
}

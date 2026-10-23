package password

import (
	"strings"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHash_WaitsBrieflyForASlotThenRefuses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, err := NewHasher(Params{Memory: 64, Time: 1, Threads: 1}, 1)
		require.NoError(t, err)
		release, err := h.acquire(t.Context())
		require.NoError(t, err)

		_, err = h.Hash(t.Context(), "violet-otter-42")
		require.ErrorIs(t, err, ErrBusy)

		release()
		_, err = h.Hash(t.Context(), "violet-otter-42")
		assert.NoError(t, err)
	})
}

// Failures that skip the stored hash still hash once at configured cost: with every slot taken they
// wait for one like a real verification does.
func TestVerify_FailuresWithoutAUsableHashStillHash(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, err := NewHasher(Params{Memory: 64, Time: 1, Threads: 1}, 1)
		require.NoError(t, err)
		release, err := h.acquire(t.Context())
		require.NoError(t, err)
		defer release()
		tests := map[string]struct{ encoded, plain string }{
			"over the maximum":     {h.DummyHash(), strings.Repeat("a", MaxChars+1)},
			"out-of-bounds hash":   {"$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U", "whatever"},
			"malformed hash":       {"plain-text", "whatever"},
			"bcrypt cost above 15": {"$2a$31$" + strings.Repeat("a", 53), "whatever"},
		}
		for name, tt := range tests {
			_, _, err := h.Verify(t.Context(), tt.encoded, tt.plain)
			require.ErrorIs(t, err, ErrBusy, name)
		}
	})
}

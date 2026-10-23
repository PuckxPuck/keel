package seal_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/seal"
)

func TestKeyring_BindsToRowAndRotates(t *testing.T) {
	old, err := seal.NewKeyring([]config.Secret{"old-key-0123456789abcdef0123456789"}, "tokens")
	require.NoError(t, err)
	rotated, err := seal.NewKeyring([]config.Secret{"new-key-0123456789abcdef0123456789", "old-key-0123456789abcdef0123456789"}, "tokens")
	require.NoError(t, err)
	otherPurpose, err := seal.NewKeyring([]config.Secret{"old-key-0123456789abcdef0123456789"}, "webhooks")
	require.NoError(t, err)

	sealed := old.Seal([]byte("refresh-token"), []byte("row-1"))

	plain, stale, err := rotated.Open(sealed, []byte("row-1"))
	require.NoError(t, err)
	assert.Equal(t, "refresh-token", string(plain))
	assert.True(t, stale, "opened with an older key")

	_, _, err = old.Open(sealed, []byte("row-2"))
	require.ErrorIs(t, err, seal.ErrUndecryptable, "copied to another row")
	_, _, err = otherPurpose.Open(sealed, []byte("row-1"))
	require.ErrorIs(t, err, seal.ErrUndecryptable, "another purpose")
}

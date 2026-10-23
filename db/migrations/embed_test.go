package migrations_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/db"
)

// An app keeps one engine's migrations; asking for another engine's is an error, not an empty schema.
func TestFor_RefusesAnEngineNotShipped(t *testing.T) {
	_, err := migrations.For(db.Dialect("sqlite"))
	require.ErrorIs(t, err, migrations.ErrNotShipped)
}

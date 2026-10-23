// Package migrations embeds the goose SQL migrations, one directory per dialect while keel holds both.
package migrations

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/PuckxPuck/keel/internal/kit/db"
)

//go:embed postgres/*.sql mysql/*.sql
var files embed.FS

// FS holds one directory per dialect, named after it.
var FS fs.FS = files

// ErrNotShipped is For's error for a dialect whose migrations this app does not ship.
var ErrNotShipped = errors.New("no migrations for this database engine")

// For returns the migrations of one dialect. An app keeps one engine's directory, so pointing it at the
// other engine fails here instead of passing the schema check on an empty database.
func For(d db.Dialect) (fs.FS, error) {
	if _, err := fs.Stat(files, d.String()); err != nil {
		return nil, fmt.Errorf("%w: this build ships no %s migrations", ErrNotShipped, d)
	}
	return fs.Sub(files, d.String())
}

// RolePrefix names the Postgres roles deploy/db/postgres-roles.sql creates: <prefix>_owner, _app, _operator.
const RolePrefix = "keel"

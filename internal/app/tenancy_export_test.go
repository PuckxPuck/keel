//go:build !notenancy

package app

import (
	"io/fs"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/tenancy"
)

// WithAppGlobalTables adds app global tables until restore runs.
func WithAppGlobalTables(e ...tenancy.Exception) (restore func()) {
	saved := appGlobalTables
	appGlobalTables = append(append([]tenancy.Exception(nil), saved...), e...)
	return func() { appGlobalTables = saved }
}

// CheckGlobalTables is migrate:validate's check that every table fsys marks global is on the allowlist.
func CheckGlobalTables(fsys fs.FS) error { return checkGlobalTables(fsys, db.Postgres) }

package db

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"
)

const maxLockName = 191

// Kit code serves both dialects, so these two statements are plain SQL rather than per-dialect Jet tables.
var lockSQL = map[Dialect][2]string{
	Postgres: {
		"INSERT INTO locks (name) VALUES ($1) ON CONFLICT (name) DO NOTHING",
		"SELECT name FROM locks WHERE name = $1 FOR UPDATE",
	},
	MySQL: {
		"INSERT INTO locks (name) VALUES (?) ON DUPLICATE KEY UPDATE name = name",
		"SELECT name FROM locks WHERE name = ? FOR UPDATE",
	},
}

// Lock takes the named lock until tx ends. Names are readable, such as "invoices:number:2026";
// take several in a fixed order. With a tenant in ctx the name is the tenant's own, so tenants never
// wait on each other.
func Lock[S Scope](ctx context.Context, tx Tx[S], name string) error {
	if id, ok := TenantOf(ctx); ok && name != "" {
		name = id.String() + ":" + name
	}
	if name == "" || utf8.RuneCountInString(name) > maxLockName {
		return fmt.Errorf("db: lock name must be 1 to %d characters", maxLockName)
	}
	stmts := lockSQL[tx.dialect]
	if _, err := tx.tx.ExecContext(ctx, stmts[0], name); err != nil {
		return fmt.Errorf("lock %s: %w", name, err)
	}
	var got string
	if err := tx.tx.QueryRowContext(ctx, stmts[1], name).Scan(&got); err != nil {
		return fmt.Errorf("lock %s: %w", name, err)
	}
	if got != name {
		return errors.New("db: lock row mismatch")
	}
	return nil
}

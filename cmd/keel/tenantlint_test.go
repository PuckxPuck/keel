package main

import (
	"fmt"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantSettingMentions(t *testing.T) {
	read := "default (nullif(current_setting('app.tenant_id', true), '')::uuid)"
	fsys := fstest.MapFS{
		"internal/kit/db/tx.go":                      {Data: []byte(`q := "select set_config('app.tenant_id', $1, true)"`)},
		"internal/kit/tenancy/hooks.go":              {Data: []byte(`"select current_setting('app.tenant_id', true)"`)},
		"db/migrations/postgres/1_tenancy_notes.sql": {Data: []byte("tenant_id uuid " + read)},
		"docs/tenancy.md":                            {Data: []byte("set_config")},
	}
	// The forms reviewers used to move a connection into another tenant.
	writes := []string{
		"\nq := `SET LOCAL app.tenant_id = 'x'`",
		`q := "select set_config('app.tenant_id', $1, false)"`,
		`_, err := tx.Q().ExecContext(ctx, "SET \"app\".\"tenant_id\" = $1", id)`,
		`_, err := tx.Q().ExecContext(ctx, "SET app . tenant_id = '" + id + "'")`,
		`_, err := tx.Q().ExecContext(ctx, "SET SESSION \"app\".tenant_id TO '" + id + "'")`,
		`_, err := tx.Q().ExecContext(ctx, "SELECT set_" + "config('app.' || 'tenant_id', $1, false)", id)`,
		`_, err := tx.Q().ExecContext(ctx, "UPDATE pg_settings SET setting = $1 WHERE name = 'app.' || 'tenant_id'", id)`,
		`_, err := tx.Q().ExecContext(ctx, "RESET \"app\".tenant_id")`,
		`_, err := tx.Q().ExecContext(ctx, "ALTER ROLE keel_app SET \"app\".\"tenant_id\" = 'x'")`,
		`_, err := tx.Q().ExecContext(ctx, "ALTER DATABASE keel SET app.tenant_id TO 'x'")`,
		"_, err := tx.Q().ExecContext(ctx, \"SET app.\" +\n\t\"tenant_id = '\" + id + \"'\")",
		"_, err := tx.Q().ExecContext(ctx, \"select set_\" +\n\t\"config('x', $1, false)\", id)",
		"q := `SET app\n\t.tenant_id = 'x'`",
		"q := \"SET app\\x2etenant_id = 'x'\"",
	}
	want := []string{"db/migrations/postgres/2_notes_hack.sql:1", "db/migrations/postgres/3_notes_role.sql:1", "db/migrations/postgres/4_notes_split.sql:2", "db/migrations/postgres/5_notes_concat.sql:3", "db/migrations/postgres/5_notes_concat.sql:4"}
	fsys["db/migrations/postgres/4_notes_split.sql"] = &fstest.MapFile{Data: []byte("-- set_config in a comment is not a call\nSET app\n  .tenant_id = '1';")}
	fsys["db/migrations/postgres/5_notes_concat.sql"] = &fstest.MapFile{Data: []byte(read + "\n\nselect set_config(\n  'app.' ||\n  'tenant_id', '1', false);")}
	fsys["internal/modules/notes/doc.go"] = &fstest.MapFile{Data: []byte("// Package notes never calls set_config or SET LOCAL app.tenant_id.\npackage notes\n")}
	fsys["db/migrations/postgres/2_notes_hack.sql"] = &fstest.MapFile{Data: []byte("select current_setting('app.tenant_id')")}
	fsys["db/migrations/postgres/3_notes_role.sql"] = &fstest.MapFile{Data: []byte(`alter role keel_app set "app"."tenant_id" = '1';`)}
	for i, line := range writes {
		path := fmt.Sprintf("internal/modules/notes/store%d.go", i)
		fsys[path] = &fstest.MapFile{Data: []byte(line)}
		row := 1
		if line[0] == '\n' {
			row = 2
		}
		want = append(want, fmt.Sprintf("%s:%d", path, row))
	}
	found, err := tenantSettingMentions(fsys)
	require.NoError(t, err)
	assert.ElementsMatch(t, want, found)
}

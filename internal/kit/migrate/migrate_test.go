package migrate_test

import (
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/migrate"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

const okName = "20261022120000_billing_invoices.sql"

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		dialect db.Dialect
		file    string
		body    string
		wantErr string
	}{
		{name: "expand migration", dialect: db.Postgres, body: "-- +goose Up\ncreate table invoices (id uuid primary key);\ncreate index invoices_id on invoices (id);\n-- +goose Down\ndrop table invoices;\n"},
		{name: "name without module", dialect: db.Postgres, file: "20261022120000_invoices.sql", body: "-- +goose Up\nselect 1;\n-- +goose Down\nselect 1;\n", wantErr: "name must be"},
		{name: "impossible timestamp", dialect: db.Postgres, file: "20261399120000_billing_x.sql", body: "-- +goose Up\nselect 1;\n-- +goose Down\nselect 1;\n", wantErr: "not a valid UTC timestamp"},
		{name: "no down", dialect: db.Postgres, body: "-- +goose Up\ncreate table x (id int);\n", wantErr: "needs both"},
		{name: "mysql with two statements", dialect: db.MySQL, body: "-- +goose Up\ncreate table a (id int);\ncreate table b (id int);\n-- +goose Down\ndrop table a;\n", wantErr: "exactly one statement in Up, found 2"},
		{name: "mysql with one statement", dialect: db.MySQL, body: "-- +goose Up\ncreate table a (\n  id int\n);\n-- +goose Down\ndrop table a;\n"},
		{name: "drop column", dialect: db.Postgres, body: "-- +goose Up\nalter table invoices drop column note;\n-- +goose Down\nalter table invoices add column note text;\n", wantErr: "drops a column"},
		{name: "drop column marked contract", dialect: db.Postgres, body: "-- keel:contract\n-- +goose Up\nalter table invoices drop column note;\n-- +goose Down\nalter table invoices add column note text;\n"},
		{name: "drop table", dialect: db.MySQL, body: "-- +goose Up\ndrop table invoices;\n-- +goose Down\ncreate table invoices (id int);\n", wantErr: "drops a table"},
		{name: "rename column", dialect: db.Postgres, body: "-- +goose Up\nalter table invoices rename column note to memo;\n-- +goose Down\nalter table invoices rename column memo to note;\n", wantErr: "renames"},
		{name: "not null without default", dialect: db.Postgres, body: "-- +goose Up\nalter table invoices add column memo text not null;\n-- +goose Down\nalter table invoices drop column memo;\n", wantErr: "not null column without a default"},
		{name: "not null with default", dialect: db.Postgres, body: "-- +goose Up\nalter table invoices add column memo text not null default '';\n-- +goose Down\nalter table invoices drop column memo;\n"},
		{name: "set not null", dialect: db.Postgres, body: "-- +goose Up\nalter table invoices alter column memo set not null;\n-- +goose Down\nalter table invoices alter column memo drop not null;\n", wantErr: "sets not null"},
		{name: "type change", dialect: db.Postgres, body: "-- +goose Up\nalter table invoices alter column total type bigint;\n-- +goose Down\nalter table invoices alter column total type integer;\n", wantErr: "changes a column type"},
		{name: "mysql modify", dialect: db.MySQL, body: "-- +goose Up\nalter table invoices modify total bigint not null;\n-- +goose Down\nalter table invoices modify total int not null;\n", wantErr: "changes a column definition"},
		{name: "index on existing table", dialect: db.Postgres, body: "-- +goose Up\ncreate index invoices_total on invoices (total);\n-- +goose Down\ndrop index invoices_total;\n", wantErr: "without concurrently"},
		{name: "concurrent index outside a transaction", dialect: db.Postgres, body: "-- +goose NO TRANSACTION\n-- +goose Up\ncreate index concurrently invoices_total on invoices (total);\n-- +goose Down\ndrop index concurrently invoices_total;\n"},
		{name: "two statements outside a transaction", dialect: db.Postgres, body: "-- +goose NO TRANSACTION\n-- +goose Up\ncreate index concurrently a on invoices (total);\ncreate index concurrently b on invoices (id);\n-- +goose Down\ndrop index concurrently a;\n", wantErr: "exactly one statement in Up"},
		{name: "concurrent index inside a transaction", dialect: db.Postgres, body: "-- +goose Up\ncreate index concurrently invoices_total on invoices (total);\n-- +goose Down\ndrop index invoices_total;\n", wantErr: "needs -- +goose NO TRANSACTION"},
		{name: "drop hidden after a comment on the line before", dialect: db.Postgres, body: "-- +goose Up\ncreate table a (id int); -- note\ndrop table invoices;\n-- +goose Down\nselect 1;\n", wantErr: "drops a table"},
		{name: "mysql second statement hidden after a comment", dialect: db.MySQL, body: "-- +goose Up\ncreate table a (id int); -- note\ncreate table b (id int);\n-- +goose Down\ndrop table a;\n", wantErr: "exactly one statement in Up, found 2"},
		{name: "two statements on one line", dialect: db.Postgres, body: "-- +goose Up\ncreate table safe (id int); drop table users;\n-- +goose Down\ndrop table safe;\n", wantErr: "drops a table"},
		{name: "mysql two statements on one line", dialect: db.MySQL, body: "-- +goose Up\ncreate table a (id int); create table b (id int);\n-- +goose Down\ndrop table a;\n", wantErr: "exactly one statement in Up, found 2"},
		{name: "semicolons inside literals and comments are not statements", dialect: db.MySQL, body: "-- +goose Up\ncreate table a (id int, note varchar(9) default 'x;y' /* ; */);\n-- +goose Down\ndrop table a;\n"},
		{name: "truncate", dialect: db.Postgres, body: "-- +goose Up\ntruncate invoices;\n-- +goose Down\nselect 1;\n", wantErr: "truncates a table"},
		{name: "drop view", dialect: db.Postgres, body: "-- +goose Up\ndrop view open_invoices;\n-- +goose Down\nselect 1;\n", wantErr: "drops a view"},
		{name: "drop function", dialect: db.Postgres, body: "-- +goose Up\ndrop function invoice_total(uuid);\n-- +goose Down\nselect 1;\n", wantErr: "drops a function"},
		{name: "drop default", dialect: db.Postgres, body: "-- +goose Up\nalter table invoices alter column note drop default;\n-- +goose Down\nselect 1;\n", wantErr: "drops a column default"},
		{name: "foreign key without not valid", dialect: db.Postgres, body: "-- +goose Up\nalter table invoices add constraint invoices_customer_fk foreign key (customer_id) references customers (id);\n-- +goose Down\nselect 1;\n", wantErr: "without not valid"},
		{name: "check without not valid", dialect: db.Postgres, body: "-- +goose Up\nalter table invoices add check (total >= 0);\n-- +goose Down\nselect 1;\n", wantErr: "without not valid"},
		{name: "foreign key with not valid", dialect: db.Postgres, body: "-- +goose Up\nalter table invoices add constraint invoices_customer_fk foreign key (customer_id) references customers (id) not valid;\n-- +goose Down\nalter table invoices drop constraint invoices_customer_fk;\n"},
		{name: "not null whose check mentions default", dialect: db.Postgres, body: "-- +goose Up\nalter table invoices add column kind text not null check (kind <> 'default');\n-- +goose Down\nalter table invoices drop column kind;\n", wantErr: "not null column without a default"},
		{name: "alter type", dialect: db.Postgres, body: "-- +goose Up\nalter type invoice_status rename value 'open' to 'due';\n-- +goose Down\nselect 1;\n", wantErr: "alters a type"},
		{name: "rename a table through alter", dialect: db.Postgres, body: "-- +goose Up\nalter table invoices rename to bills;\n-- +goose Down\nalter table bills rename to invoices;\n", wantErr: "renames"},
		{name: "vacuum full", dialect: db.Postgres, body: "-- +goose NO TRANSACTION\n-- +goose Up\nvacuum full invoices;\n-- +goose Down\nselect 1;\n", wantErr: "rewrites a table"},
		{name: "function body with semicolons", dialect: db.Postgres, body: "-- +goose Up\n-- +goose StatementBegin\ncreate function one() returns int language sql as $$ select 1; $$;\n-- +goose StatementEnd\n-- +goose Down\ndrop function one();\n"},
		{name: "contract marker after the transaction annotation", dialect: db.Postgres, body: "-- +goose NO TRANSACTION\n-- keel:contract\n-- +goose Up\ndrop table invoices;\n-- +goose Down\nselect 1;\n"},
		{name: "tenant table without row-level security", dialect: db.Postgres, body: "-- +goose Up\ncreate table invoices (tenant_id uuid not null, id uuid not null, primary key (tenant_id, id));\nalter table invoices enable row level security;\n-- +goose Down\ndrop table invoices;\n", wantErr: "table invoices has tenant_id"},
		{name: "tenant table with its guard", dialect: db.Postgres, body: "-- +goose Up\ncreate table invoices (tenant_id uuid not null, id uuid not null, primary key (tenant_id, id));\nalter table invoices enable row level security;\nalter table invoices force row level security;\ncreate policy tenant_isolation on invoices using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid)) with check (tenant_id is not distinct from (select nullif(current_setting('app.tenant_id', true), '')::uuid));\n-- +goose Down\ndrop table invoices;\n"},
		{name: "tenant column added without a policy", dialect: db.Postgres, body: "-- keel:contract\n-- +goose Up\nalter table notes add column tenant_id uuid;\n-- +goose Down\nalter table notes drop column tenant_id;\n", wantErr: "table notes has tenant_id"},
		{name: "global table marked", dialect: db.Postgres, body: "-- keel:global read before a tenant is chosen\n-- +goose Up\ncreate table memberships (tenant_id uuid not null, user_id uuid not null);\n-- +goose Down\ndrop table memberships;\n"},
		{name: "global marker without a reason", dialect: db.Postgres, body: "-- keel:global\n-- +goose Up\ncreate table memberships (tenant_id uuid not null, user_id uuid not null);\n-- +goose Down\ndrop table memberships;\n", wantErr: "needs a reason"},
		{name: "tenant table whose only policy is for select", dialect: db.Postgres, body: "-- +goose Up\ncreate table notes (tenant_id uuid not null, id uuid not null, primary key (tenant_id, id));\nalter table notes enable row level security;\nalter table notes force row level security;\ncreate policy anyone on notes for select using (true);\n-- +goose Down\ndrop table notes;\n", wantErr: "table notes has tenant_id"},
		{name: "unfinished statement goose would refuse", dialect: db.Postgres, body: "-- +goose Up\ncreate table a (id int)\n-- +goose Down\ndrop table a;\n", wantErr: "missing semicolon"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := tt.file
			if name == "" {
				name = okName
			}
			err := migrate.Validate(fstest.MapFS{name: {Data: []byte(tt.body)}}, tt.dialect, migrate.Allowed{})
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}

	for _, d := range []db.Dialect{db.Postgres, db.MySQL} {
		fsys, err := migrations.For(d)
		if errors.Is(err, migrations.ErrNotShipped) {
			continue
		}
		require.NoError(t, err)
		// The tenancy part's policies need its allowlist; kit/tenancy validates the whole set.
		require.NoError(t, migrate.Validate(migrate.Without(fsys, testdb.TenancyModule), d, migrate.Allowed{}), "keel's own %s migrations", d)
	}
}

// With the tenancy part, every table is a tenant table or marked global; nothing is shared by omission.
func TestValidate_TablesUnderTenancy(t *testing.T) {
	tenancyFile := "-- +goose Up\ncreate table tenants (id uuid primary key);\n-- +goose Down\ndrop table tenants;\n"
	tests := []struct {
		name, app string
		tenancy   bool
		wantErr   string
	}{
		{name: "a table without tenant_id", tenancy: true, app: "-- +goose Up\ncreate table invoices (id uuid primary key, number text not null);\n-- +goose Down\ndrop table invoices;\n", wantErr: "table invoices has no tenant_id"},
		{name: "a global table with its reason", tenancy: true, app: "-- keel:global currencies are the same for everyone\n-- +goose Up\ncreate table currencies (code text primary key);\n-- +goose Down\ndrop table currencies;\n"},
		{name: "the same table without tenancy", app: "-- +goose Up\ncreate table invoices (id uuid primary key, number text not null);\n-- +goose Down\ndrop table invoices;\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{"20990101000001_billing_invoices.sql": {Data: []byte(tt.app)}}
			if tt.tenancy {
				fsys["20990101000000_tenancy_tenants.sql"] = &fstest.MapFile{Data: []byte("-- keel:global the tenant list\n" + tenancyFile)}
			}
			err := migrate.Validate(fsys, db.Postgres, migrate.Allowed{})
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// Every policy is the tenant policy or allowed by name with a reason, on any table and in any file, and
// nothing turns a tenant table's row-level security off: the running release would serve the new schema
// before any startup check could refuse it.
func TestValidate_PolicyDDL(t *testing.T) {
	const tenantPolicy = "using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))\n" +
		"  with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))"
	invoices := "-- +goose Up\ncreate table invoices (tenant_id uuid not null, id uuid not null, parent_id uuid, primary key (tenant_id, id));\n" +
		"alter table invoices enable row level security;\nalter table invoices force row level security;\n" +
		"create policy tenant_isolation on invoices\n  " + tenantPolicy + ";\n-- +goose Down\ndrop table invoices;\n"
	allowed := migrate.Allowed{Policies: []migrate.Policy{{Table: "invoices", Name: "archive_read", Reason: "archived rows are read by every tenant"}}}
	tests := []struct {
		name, up string
		wantErr  string
	}{
		{name: "a policy open to everyone on an existing table", up: "create policy open_read on invoices for select using (true);", wantErr: "policy open_read on invoices is not the tenant policy"},
		{name: "the tenant expression without with check", up: "create policy second on invoices using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));", wantErr: "policy second on invoices"},
		{name: "another setting in the tenant shape", up: "create policy second on invoices using (tenant_id = (select nullif(current_setting('app.other_id', true), '')::uuid)) with check (true);", wantErr: "policy second on invoices"},
		{name: "a policy on a table without tenant_id", up: "create policy everyone on currencies using (true);", wantErr: "policy everyone on currencies"},
		{name: "an altered tenant policy", up: "alter policy tenant_isolation on invoices using (true);", wantErr: "policy tenant_isolation on invoices"},
		{name: "a renamed tenant policy keeps its expression", up: "alter policy tenant_isolation on invoices rename to isolation;"},
		{name: "an allowed policy", up: "create policy archive_read on invoices for select using (true);"},
		{name: "the tenant policy again under another name", up: "create policy isolation_two on invoices\n  " + tenantPolicy + ";"},
		{name: "a dropped tenant policy", up: "drop policy tenant_isolation on invoices;", wantErr: "drops policy tenant_isolation on tenant table invoices"},
		{name: "row-level security disabled", up: "alter table invoices disable row level security;", wantErr: "turns row-level security off on tenant table invoices"},
		{name: "row-level security no longer forced", up: "alter table only invoices add column memo text, no force row level security;", wantErr: "turns row-level security off on tenant table invoices"},
		{name: "a self reference without the tenant", up: "alter table invoices add constraint invoices_parent foreign key (parent_id) references invoices (id) not valid;", wantErr: "invoices references itself without tenant_id"},
		{name: "a self reference with the tenant", up: "alter table invoices add constraint invoices_parent foreign key (tenant_id, parent_id) references invoices (tenant_id, id) not valid;"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"20990101000000_billing_invoices.sql": {Data: []byte(invoices)},
				"20990101000001_billing_change.sql":   {Data: []byte("-- keel:contract\n-- +goose Up\n" + tt.up + "\n-- +goose Down\nselect 1;\n")},
			}
			err := migrate.Validate(fsys, db.Postgres, allowed)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// Under tenancy no migration runs procedural SQL the validator cannot read (a DO block, or a function
// that runs dynamic SQL or changes tables, policies or row-level security) unless its file says why and
// the allowlist names the file, or the function in that file, with the same reason.
func TestValidate_ProceduralUnderTenancy(t *testing.T) {
	const (
		file   = "20990101000001_billing_change.sql"
		reason = "backfills each tenant's totals"
		marker = "-- keel:procedural " + reason + "\n"
		sneak  = "create function sneak() returns void language plpgsql as $f$ begin alter table invoices no force row level security; end $f$;"
	)
	allowed := migrate.Allowed{Procedural: []migrate.Procedural{
		{File: file, Reason: reason},
		{File: file, Function: "billing.rotate", Reason: reason},
	}}
	tests := []struct {
		name, head, up string
		noTenancy      bool
		wantErr        string
	}{
		{name: "a do block", up: "do $$ begin execute 'alter table invoices disable row level security'; end $$;", wantErr: "a DO block"},
		{name: "a do block that looks harmless", up: "do language plpgsql $$ begin perform 1; end $$;", wantErr: "a DO block"},
		{name: "a function running dynamic sql", up: "create function public.purge() returns void language plpgsql as $$ begin execute 'drop policy x on y'; end $$;", wantErr: "function public.purge"},
		{name: "a function changing row-level security", up: sneak, wantErr: "function public.sneak"},
		{name: "a function body in quotes", up: "create procedure sneak() language sql as 'create policy open on invoices using (true)';", wantErr: "function public.sneak"},
		{name: "a function with a standard body", up: "create function sneak() returns void language sql begin atomic alter table invoices disable row level security; end;", wantErr: "function public.sneak"},
		{name: "a plain function", up: "create function total(a int, b int) returns int language sql as $$ select a + b $$;"},
		{name: "an allowed block in its marked file", head: marker, up: "do $$ begin perform 1; end $$;"},
		{name: "an allowed function in its marked file", head: marker, up: "create or replace function billing.rotate() returns void language plpgsql as $$ begin execute 'select 1'; end $$;"},
		{name: "a function the allowlist does not name", head: marker, up: sneak, wantErr: "function public.sneak"},
		{name: "a marker with another reason", head: "-- keel:procedural another reason\n", up: "do $$ begin perform 1; end $$;", wantErr: "a DO block"},
		{name: "an allowlisted file without the marker", up: "do $$ begin perform 1; end $$;", wantErr: "a DO block"},
		{name: "a marker without a reason", head: "-- keel:procedural\n", up: "select 1;", wantErr: "needs a reason"},
		{name: "a do block without tenancy", noTenancy: true, up: "do $$ begin perform 1; end $$;"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{file: {Data: []byte(tt.head + "-- +goose Up\n-- +goose StatementBegin\n" + tt.up + "\n-- +goose StatementEnd\n-- +goose Down\nselect 1;\n")}}
			if !tt.noTenancy {
				fsys["20990101000000_tenancy_tenants.sql"] = &fstest.MapFile{Data: []byte("-- keel:global the tenant list\n-- +goose Up\ncreate table tenants (id uuid primary key);\n-- +goose Down\ndrop table tenants;\n")}
			}
			err := migrate.Validate(fsys, db.Postgres, allowed)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// A module whose tables are tenant tables needs the tenancy part, so a test database without it leaves the
// module out. A table stays with the module that created it, so a conversion in a tenancy file takes the
// creator out too, except the kit's; a mention of tenant_id in a comment does not count.
func TestTenantModules(t *testing.T) {
	plain := "-- every tenant_id lives elsewhere\n-- +goose Up\ncreate table things (id uuid primary key);\n-- +goose Down\ndrop table things;\n"
	fsys := fstest.MapFS{
		"20990101000000_kit_things.sql":        {Data: []byte(plain)},
		"20990101000001_tenancy_things.sql":    {Data: []byte("-- keel:contract\n-- +goose Up\nalter table things add column tenant_id uuid;\n-- +goose Down\nalter table things drop column tenant_id;\n")},
		"20990101000002_billing_invoices.sql":  {Data: []byte("-- +goose Up\ncreate table invoices (tenant_id uuid not null, id uuid not null, primary key (tenant_id, id));\n-- +goose Down\ndrop table invoices;\n")},
		"20990101000003_billing_add_memo.sql":  {Data: []byte("-- +goose Up\nalter table invoices add column memo text;\n-- +goose Down\nalter table invoices drop column memo;\n")},
		"20990101000004_reports_snapshots.sql": {Data: []byte(plain)},
		"20990101000005_notes_create.sql":      {Data: []byte("-- +goose Up\ncreate table notes (id uuid primary key);\n-- +goose Down\ndrop table notes;\n")},
		"20990101000006_tenancy_notes.sql":     {Data: []byte("-- keel:contract\n-- +goose Up\nalter table notes add column tenant_id uuid;\n-- +goose Down\nalter table notes drop column tenant_id;\n")},
	}

	got, err := migrate.TenantModules(fsys, db.Postgres)

	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"tenancy", "billing", "notes"}, got)
	left, err := fs.Glob(migrate.Without(fsys, got...), "*.sql")
	require.NoError(t, err)
	assert.Equal(t, []string{"20990101000000_kit_things.sql", "20990101000004_reports_snapshots.sql"}, left)
}

func TestDown_RefusedInProduction(t *testing.T) {
	_, err := migrate.New(nil, db.Postgres, fstest.MapFS{}, migrate.Options{Production: true}).Down(t.Context())
	require.ErrorIs(t, err, migrate.ErrDownRefused)
}

func TestCurrent(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		all, err := migrations.For(e.Dialect())
		require.NoError(t, err)
		tenantModules, err := migrate.TenantModules(all, e.Dialect())
		require.NoError(t, err)
		shipped := migrate.Without(all, append(tenantModules, testdb.TenancyModule)...) // what the package database holds
		newer := fstest.MapFS{"29991231235959_kit_later.sql": {Data: []byte("-- +goose Up\nselect 1;\n-- +goose Down\nselect 1;\n")}}
		require.NoError(t, fs.WalkDir(shipped, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			raw, err := fs.ReadFile(shipped, path)
			newer[path] = &fstest.MapFile{Data: raw}
			return err
		}))

		tests := []struct {
			name     string
			fsys     fs.FS
			wantErr  error
			wantWarn bool
		}{
			{name: "database matches the binary", fsys: shipped},
			{name: "database behind the binary refuses to serve", fsys: newer, wantErr: migrate.ErrBehind},
			{name: "database ahead of the binary only warns", fsys: fstest.MapFS{}, wantWarn: true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var logs bytes.Buffer
				ctx := logx.WithLogger(t.Context(), slog.New(slog.NewTextHandler(&logs, nil)))

				err := migrate.New(e.DB().SQL(), e.Dialect(), tt.fsys, migrate.Options{}).Current(ctx)

				require.ErrorIs(t, err, tt.wantErr)
				assert.Equal(t, tt.wantWarn, bytes.Contains(logs.Bytes(), []byte("ahead of this binary")))
			})
		}
	})
}

func TestKitMigrations_UpDownUp(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		ctx := t.Context()
		fsys, err := migrations.For(e.Dialect())
		require.NoError(t, err)
		versions, err := migrate.Versions(fsys)
		require.NoError(t, err)
		m := migrate.New(e.Empty(t).SQL(), e.Dialect(), fsys, migrate.Options{})

		_, err = m.Up(ctx)
		require.NoError(t, err)
		for range versions {
			_, err := m.Down(ctx)
			require.NoError(t, err)
		}
		v, err := m.Version(ctx)
		require.NoError(t, err)
		require.Zero(t, v, "every Down ran")
		results, err := m.Up(ctx)
		require.NoError(t, err)
		assert.Len(t, results, len(versions))
	})
}

func TestAppliedFunction_OwnedByTheOwnerAndClosedToPublic(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		if e.Dialect() != db.Postgres {
			t.Skip("the function exists on Postgres only")
		}
		var owner string
		var public, app bool
		require.NoError(t, e.DB().SQL().QueryRowContext(t.Context(), `SELECT pg_get_userbyid(proowner),
			has_function_privilege('public', oid, 'execute'), has_function_privilege(current_user, oid, 'execute')
			FROM pg_proc WHERE oid = 'public.keel_migrations_applied()'::regprocedure`).Scan(&owner, &public, &app))
		assert.Equal(t, migrations.RolePrefix+"_owner", owner)
		assert.False(t, public, "only the app and operator roles may read the applied versions")
		assert.True(t, app)
	})
}

func TestVersionTable_ClosedToTheAppRole(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		if e.Dialect() != db.Postgres {
			t.Skip("roles are separated on Postgres only")
		}
		_, err := e.DB().SQL().ExecContext(t.Context(), "DELETE FROM "+migrate.Schema+".goose_db_version")
		require.ErrorContains(t, err, "permission denied for schema "+migrate.Schema)
	})
}

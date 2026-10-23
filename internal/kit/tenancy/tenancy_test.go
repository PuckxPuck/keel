package tenancy_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/migrate"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/tenancy"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

var catalogue = rbac.NewCatalogue(rbac.Perm{Code: "notes.read", Area: "Notes", Label: "Read notes", Description: "Read notes"})

type world struct {
	d        *testdb.TenancyDB
	svc      *tenancy.Service
	a, b     tenancy.Tenant
	ann, bob users.User
}

type allow struct{}

func (allow) CheckStatus(context.Context, db.Transaction, users.Actor, users.ID, users.Status) error {
	return nil
}

// newWorld makes two tenants, acme owned by ann and globex owned by bob, from the same template.
func newWorld(t *testing.T) *world {
	t.Helper()
	ctx := t.Context()
	d := testdb.Tenancy(t)
	rec := audit.New(audit.Options{Chain: true})
	svc, err := tenancy.New(tenancy.Options{
		DB: d.DB, Audit: rec, Realm: "tenant", Catalogue: catalogue, Owner: "owner",
		Templates: []rbac.Builtin{{Code: "owner", Name: "Owner", Permissions: []rbac.Code{"notes.read"}}},
	})
	require.NoError(t, err)
	w := &world{d: d, svc: svc}
	require.NoError(t, db.InTx(ctx, d.DB, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		people := users.NewService(rec, allow{})
		if w.ann, err = people.Create(ctx, tx, users.NewUser{Email: "ann@example.test"}); err != nil {
			return err
		}
		w.bob, err = people.Create(ctx, tx, users.NewUser{Email: "bob@example.test"})
		return err
	}))
	require.NoError(t, db.InOperatorTx(ctx, d.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		var err error
		if w.a, err = svc.Create(ctx, tx, tenancy.NewTenant{Slug: "acme", Name: "Acme", Owner: w.ann.ID}); err != nil {
			return err
		}
		w.b, err = svc.Create(ctx, tx, tenancy.NewTenant{Slug: "globex", Name: "Globex", Owner: w.bob.ID})
		return err
	}))
	return w
}

func (w *world) in(t tenancy.Tenant) context.Context {
	return tenancy.WithTenant(context.Background(), t)
}

func count(ctx context.Context, tx db.Transaction, query string, args ...any) (int, error) {
	var n int
	rows, err := tx.Q().QueryContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := rows.Scan(&n); err != nil {
			return 0, err
		}
	}
	return n, rows.Err()
}

func TestTransactions_SeeOnlyTheirTenant(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()

	var aRoles, aOthers int
	require.NoError(t, db.InTx(w.in(w.a), w.d.DB, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		var err error
		if aRoles, err = count(ctx, tx, "SELECT count(*) FROM roles"); err != nil {
			return err
		}
		aOthers, err = count(ctx, tx, "SELECT count(*) FROM user_roles WHERE user_id = $1", w.bob.ID)
		return err
	}))
	assert.Equal(t, 1, aRoles, "acme sees its own copy of the template")
	assert.Zero(t, aOthers, "acme cannot see globex's grants")

	var both int
	require.NoError(t, db.InOperatorTx(ctx, w.d.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		var err error
		both, err = count(ctx, tx, "SELECT count(*) FROM roles WHERE tenant_id IS NOT NULL")
		return err
	}))
	assert.Equal(t, 2, both, "the operator pool sees every tenant")

	err := db.InTx(ctx, w.d.DB, func(context.Context, db.Tx[db.Tenant]) error { return nil })
	require.ErrorIs(t, err, tenancy.ErrNoTenant, "a tenant transaction without a tenant refuses to open")
	err = tenancy.Runner(w.d.DB)(ctx, func(context.Context, db.Transaction) error { return nil })
	require.ErrorIs(t, err, tenancy.ErrNoTenant, "the runner never falls back to the operator pool")
}

// A session-level SET of the setting, in any spelling, never reaches the next borrower of the
// connection: the pool clears it on every checkout.
func TestSessionSetting_NeverReachesTheNextBorrower(t *testing.T) {
	w := newWorld(t)
	for _, stmt := range []string{
		`SET "app"."tenant_id" = '%s'`,
		`SET app . tenant_id = '%s'`,
		`SET SESSION "app".tenant_id TO '%s'`,
	} {
		t.Run(stmt, func(t *testing.T) {
			p := w.d.As(t, "app")
			p.SQL().SetMaxOpenConns(1)
			require.NoError(t, tenancy.Install(p))
			require.NoError(t, db.InTx(t.Context(), p, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				_, err := tx.Q().ExecContext(ctx, fmt.Sprintf(stmt, w.b.ID))
				return err
			}))
			var foreign int
			require.NoError(t, db.InTx(t.Context(), p, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				var err error
				foreign, err = count(ctx, tx, "SELECT count(*) FROM roles WHERE tenant_id IS NOT NULL")
				return err
			}))
			assert.Zero(t, foreign)
		})
	}
}

// Only the operator pool writes the tables that decide entry; a tenant transaction cannot touch another
// tenant's audit chain head or locate a key into another tenant.
func TestTenantTransactions_CannotWriteControlTables(t *testing.T) {
	w := newWorld(t)
	tests := []struct {
		name, query string
		args        func() []any
	}{
		{"rename another tenant", "UPDATE tenants SET name = 'pwned' WHERE id = $1", func() []any { return []any{w.b.ID} }},
		{"its own state", "UPDATE tenants SET status = 'active' WHERE id = $1", func() []any { return []any{w.a.ID} }},
		{"join another tenant", "INSERT INTO memberships (tenant_id, user_id, status, is_default, created_at) VALUES ($1, $2, 'active', false, now())", func() []any { return []any{w.b.ID, w.ann.ID} }},
		{"disable a member", "UPDATE memberships SET status = 'disabled' WHERE tenant_id = $1", func() []any { return []any{w.b.ID} }},
		{"add a domain", "INSERT INTO tenant_domains (host, tenant_id, created_at) VALUES ('evil.example.test', $1, now())", func() []any { return []any{w.b.ID} }},
		{"rewrite another chain head", "UPDATE audit_chain SET hash = '\\x00' WHERE chain_key = $1", func() []any { return []any{w.b.ID.String()} }},
		{"locate a key in another tenant", "INSERT INTO api_key_tenants (key_id, tenant_id) VALUES ($1, $2)", func() []any { return []any{ids.New(), w.b.ID} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var changed int64
			err := db.InTx(w.in(w.a), w.d.DB, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
				res, err := tx.Q().ExecContext(ctx, tt.query, tt.args()...)
				if err != nil {
					return err
				}
				changed, err = res.RowsAffected()
				return err
			})
			if err == nil {
				assert.Zero(t, changed)
			}
		})
	}
}

// The whole migration set validates with the kit's allowed policies, the tenancy part's own included.
func TestMigrations_AreValid(t *testing.T) {
	fsys, err := migrations.For(db.Postgres)
	require.NoError(t, err)
	require.NoError(t, migrate.Validate(fsys, db.Postgres, migrate.Allowed{Policies: tenancy.AllowedPolicies(), Procedural: tenancy.KitProcedural}))
}

// Every table keel's own migrations mark global is on the kit's allowlist, so the two cannot drift apart.
// An app's tables are checked against the kit's and the app's exceptions in internal/app.
func TestGlobalTables_AreAllowlisted(t *testing.T) {
	marked, _ := globalTables(t)
	for table := range marked {
		assert.True(t, slices.ContainsFunc(tenancy.KitExceptions, func(e tenancy.Exception) bool {
			return e.Table == table && e.Index == "" && e.Policy == ""
		}), table)
	}
}

// globalTables splits the tables the Postgres migrations mark global into keel's own (the kit's and the
// tenancy part's) and the app's, which the app's exceptions cover.
func globalTables(t *testing.T) (own map[string]string, app []tenancy.Exception) {
	t.Helper()
	fsys, err := migrations.For(db.Postgres)
	require.NoError(t, err)
	all, err := migrate.GlobalTables(fsys)
	require.NoError(t, err)
	own, err = migrate.GlobalTables(keelOwn(t, fsys))
	require.NoError(t, err)
	for _, table := range slices.Sorted(maps.Keys(all)) {
		if _, ok := own[table]; !ok {
			app = append(app, tenancy.Exception{Table: table, Reason: all[table]})
		}
	}
	return own, app
}

// keelOwn are the migrations of keel's own modules, kit and tenancy (<timestamp>_<module>_<what>.sql).
func keelOwn(t *testing.T, fsys fs.FS) fs.FS {
	t.Helper()
	names, err := fs.Glob(fsys, "*.sql")
	require.NoError(t, err)
	own := fstest.MapFS{}
	for _, name := range names {
		if parts := strings.SplitN(name, "_", 3); len(parts) == 3 && (parts[1] == "kit" || parts[1] == "tenancy") {
			raw, err := fs.ReadFile(fsys, name)
			require.NoError(t, err)
			own[name] = &fstest.MapFile{Data: raw}
		}
	}
	return own
}

// Every table with a tenant_id column, read on the app pool with no tenant set, shows no tenant's rows.
func TestUnsetTenant_SeesNoTenantRows(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	require.NoError(t, db.InTx(ctx, w.d.DB, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		rows, err := tx.Q().QueryContext(ctx, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id'
			WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity ORDER BY 1`)
		if err != nil {
			return err
		}
		var tables []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return err
			}
			tables = append(tables, name)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		require.Contains(t, tables, "roles")
		for _, table := range tables {
			n, err := count(ctx, tx, "SELECT count(*) FROM "+table+" WHERE tenant_id IS NOT NULL")
			if err != nil {
				return fmt.Errorf("%s: %w", table, err)
			}
			assert.Zero(t, n, table)
		}
		return nil
	}))
}

func TestCommit_RefusesARewrittenSetting(t *testing.T) {
	w := newWorld(t)
	name := "planted-" + ids.New().String()[:8]
	err := db.InTx(w.in(w.a), w.d.DB, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		if _, err := tx.Q().ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", w.b.ID.String()); err != nil {
			return err
		}
		_, err := tx.Q().ExecContext(ctx, `INSERT INTO roles (id, realm, code, name, created_at, updated_at) VALUES ($1, 'tenant', 'planted', $2, now(), now())`,
			ids.New(), name)
		return err
	})
	require.ErrorIs(t, err, tenancy.ErrSettingMove)

	var planted int
	require.NoError(t, db.InOperatorTx(t.Context(), w.d.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		var err error
		planted, err = count(ctx, tx, "SELECT count(*) FROM roles WHERE name = $1", name)
		return err
	}))
	assert.Zero(t, planted, "the transaction rolled back")
}

func TestCheckCatalogue(t *testing.T) {
	w := newWorld(t)
	owner := w.d.As(t, "owner")
	check := func(t *testing.T, extra ...tenancy.Exception) error {
		t.Helper()
		return db.InTx(t.Context(), owner, func(ctx context.Context, tx db.Tx[db.Plain]) error { return tenancy.CheckCatalogue(ctx, tx, extra...) })
	}
	_, appGlobal := globalTables(t)
	require.NoError(t, check(t, appGlobal...), "the kit's own schema follows the rules; the app's global tables are the app's to list")

	policy := `create policy tenant_isolation on %[1]s
		using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
		with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))`
	tests := []struct {
		name    string
		table   string
		ddl     []string
		extra   []tenancy.Exception
		wantErr string
	}{
		{
			name: "row-level security not forced", table: "cat_unforced",
			ddl:     []string{"create table cat_unforced (tenant_id uuid not null, id uuid not null, primary key (tenant_id, id))", "alter table cat_unforced enable row level security", policy},
			wantErr: "cat_unforced: row-level security must be enabled and forced",
		},
		{
			name: "no policy", table: "cat_open",
			ddl:     []string{"create table cat_open (tenant_id uuid not null, id uuid not null, primary key (tenant_id, id))", "alter table cat_open enable row level security", "alter table cat_open force row level security"},
			wantErr: "cat_open: needs the tenant policy",
		},
		{
			name: "index without the tenant first", table: "cat_index",
			ddl: []string{
				"create table cat_index (tenant_id uuid not null, id uuid not null, code text, primary key (tenant_id, id))", "alter table cat_index enable row level security",
				"alter table cat_index force row level security", policy, "create unique index cat_index_code on cat_index (code)",
			},
			wantErr: "cat_index: index cat_index_code must lead with tenant_id",
		},
		{
			name: "foreign key without the tenant", table: "cat_child",
			ddl: []string{
				"create table cat_child (tenant_id uuid not null, id uuid not null, role_id uuid references roles (id), primary key (tenant_id, id))",
				"alter table cat_child enable row level security", "alter table cat_child force row level security", policy,
			},
			wantErr: "cat_child: foreign key cat_child_role_id_fkey to roles must include tenant_id",
		},
		{
			name: "a nullable tenant_id without an exception", table: "cat_nullable",
			ddl: []string{
				"create table cat_nullable (tenant_id uuid, id uuid primary key)", "alter table cat_nullable enable row level security",
				"alter table cat_nullable force row level security", policy,
			},
			wantErr: "cat_nullable: tenant_id must be not null",
		},
		{
			name: "a self reference without the tenant", table: "cat_tree",
			ddl: []string{
				"create table cat_tree (tenant_id uuid not null, id uuid not null, parent_id uuid, primary key (tenant_id, id), unique (id), foreign key (parent_id) references cat_tree (id))",
				"alter table cat_tree enable row level security", "alter table cat_tree force row level security", policy,
			},
			wantErr: "cat_tree: foreign key cat_tree_parent_id_fkey to cat_tree must include tenant_id",
		},
		{
			name: "a table without tenant_id", table: "cat_plain",
			ddl:     []string{"create table cat_plain (id uuid primary key, number text not null)"},
			wantErr: "cat_plain: has no tenant_id",
		},
		{
			name: "an extra permissive policy", table: "cat_loose",
			ddl: []string{
				"create table cat_loose (tenant_id uuid not null, id uuid not null, primary key (tenant_id, id))", "alter table cat_loose enable row level security",
				"alter table cat_loose force row level security", policy, "create policy everyone_reads on cat_loose for select using (true)",
			},
			wantErr: "cat_loose: policy everyone_reads is not the tenant policy",
		},
		{
			name: "a policy that only mentions the setting", table: "cat_fake",
			ddl: []string{
				"create table cat_fake (tenant_id uuid not null, id uuid not null, primary key (tenant_id, id))", "alter table cat_fake enable row level security",
				"alter table cat_fake force row level security",
				"create policy tenant_isolation on cat_fake using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid) or true) with check (true)",
			},
			wantErr: "cat_fake: needs the tenant policy",
		},
		{
			name: "a view that runs as its owner", table: "cat_view",
			ddl:     []string{"create view cat_view as select tenant_id, code from roles"},
			wantErr: "cat_view: a view must be created with (security_invoker = true)",
		},
		{
			name: "a security definer function", table: "cat_count",
			ddl:     []string{"create function cat_count() returns bigint language sql security definer as 'select count(*) from roles'"},
			wantErr: "function public.cat_count(): security definer",
		},
		{
			name: "an overload of an excepted function", table: "keel_migrations_applied",
			ddl: []string{
				"create function keel_migrations_applied(n integer) returns setof bigint language sql security definer set search_path = pg_catalog, pg_temp as 'select 1::bigint'",
				"revoke all on function keel_migrations_applied(integer) from public",
			},
			wantErr: "function public.keel_migrations_applied(integer): security definer",
		},
		{
			name: "an excepted function whose body changed", table: "cat_changed",
			ddl: []string{
				"create function cat_changed() returns int language sql security definer set search_path = pg_catalog as 'select 2'",
				"revoke all on function cat_changed() from public",
			},
			extra:   []tenancy.Exception{definer("public.cat_changed()")},
			wantErr: "function public.cat_changed(): its body's SHA-256",
		},
		{
			name: "an excepted function without a pinned search path", table: "cat_unpinned",
			ddl: []string{
				"create function cat_unpinned() returns int language sql security definer as 'select 1'",
				"revoke all on function cat_unpinned() from public",
			},
			extra:   []tenancy.Exception{definer("public.cat_unpinned()")},
			wantErr: "function public.cat_unpinned(): a security definer function must pin its search_path",
		},
		{
			name: "an excepted function anyone may execute", table: "cat_public",
			ddl:     []string{"create function cat_public() returns int language sql security definer set search_path = pg_catalog as 'select 1'"},
			extra:   []tenancy.Exception{definer("public.cat_public()")},
			wantErr: "function public.cat_public(): PUBLIC may execute it",
		},
		{
			name: "a global table pointing into a tenant table", table: "cat_global",
			ddl:     []string{"create table cat_global (id uuid primary key, device_tenant uuid, device_id uuid, foreign key (device_tenant, device_id) references devices (tenant_id, id))"},
			extra:   []tenancy.Exception{{Table: "cat_global", Reason: "reference data"}},
			wantErr: "cat_global: a global table's foreign key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, db.InTx(t.Context(), owner, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				// db.Open pins pg_catalog first, where nothing may be created; migrations run with public.
				if _, err := tx.Q().ExecContext(ctx, "set local search_path = public"); err != nil {
					return err
				}
				for _, stmt := range tt.ddl {
					if stmt == policy {
						stmt = fmt.Sprintf(policy, tt.table)
					}
					if _, err := tx.Q().ExecContext(ctx, stmt); err != nil {
						return fmt.Errorf("%s: %w", stmt, err)
					}
				}
				return nil
			}))
			require.ErrorContains(t, check(t, tt.extra...), tt.wantErr)
		})
	}

	w.d.Admin(t, "create function public.cat_super() returns int language sql security definer set search_path = pg_catalog as 'select 1'",
		"revoke all on function public.cat_super() from public")
	require.ErrorContains(t, check(t, definer("public.cat_super()")), "function public.cat_super(): owned by",
		"a superuser's definer function skips every policy")
}

// definer excepts a security definer function whose body is select 1.
func definer(signature string) tenancy.Exception {
	sum := sha256.Sum256([]byte("select 1"))
	return tenancy.Exception{Function: signature, BodySHA256: hex.EncodeToString(sum[:]), Reason: "a test function"}
}

// Under tenancy the pool must clear the setting on every checkout, or a session-level SET reaches the
// next borrower.
func TestInstall_NeedsTheSessionReset(t *testing.T) {
	require.ErrorIs(t, tenancy.Install(db.New(db.Postgres, nil)), tenancy.ErrNoReset)
	require.NoError(t, tenancy.Install(testdb.Tenancy(t).DB))
}

func TestCheckRoles(t *testing.T) {
	w := newWorld(t)
	// app is a role like the app role that one case then misconfigures; roles are shared across databases.
	app := func(t *testing.T, stmts ...string) *db.DB {
		t.Helper()
		role := w.d.TempRole(t, "nobypassrls")
		for i := range stmts {
			stmts[i] = strings.ReplaceAll(stmts[i], "{role}", `"`+role+`"`)
		}
		w.d.Admin(t, stmts...)
		return w.d.AsRole(t, role)
	}
	tests := []struct {
		name    string
		app     func(t *testing.T) *db.DB
		wantErr string
	}{
		{name: "the app role under row-level security and the operator role", app: func(*testing.T) *db.DB { return w.d.DB }},
		{name: "an app pool that bypasses row-level security", app: func(t *testing.T) *db.DB { return w.d.As(t, "operator") }, wantErr: "bypasses row-level security"},
		{name: "an app pool that owns the tables", app: func(t *testing.T) *db.DB { return w.d.As(t, "owner") }, wantErr: "owns"},
		{name: "a member of the operator role", app: func(t *testing.T) *db.DB { return app(t, `GRANT "`+w.d.Operator.LoginRole()+`" TO {role}`) }, wantErr: "is the operator role"},
		{name: "a member of a role that bypasses row-level security", app: func(t *testing.T) *db.DB {
			escape := w.d.TempRole(t, "bypassrls")
			return app(t, `GRANT "`+escape+`" TO {role}`)
		}, wantErr: "bypasses row-level security"},
		{name: "a role that may write tenants", app: func(t *testing.T) *db.DB { return app(t, "GRANT UPDATE ON tenants TO {role}") }, wantErr: "may write tenants"},
		{name: "a default for the tenant setting", app: func(t *testing.T) *db.DB {
			return app(t, "ALTER ROLE {role} IN DATABASE {db} SET app.tenant_id = '"+w.b.ID.String()+"'")
		}, wantErr: "sets a default for app.tenant_id"},
		{name: "a default for the search path", app: func(t *testing.T) *db.DB {
			return app(t, "ALTER ROLE {role} IN DATABASE {db} SET search_path = shadow, public")
		}, wantErr: "sets a default for search_path"},
		{name: "a pool that acts as another role than it logs in as", app: func(t *testing.T) *db.DB {
			p := app(t, "GRANT "+migrations.RolePrefix+"_app TO {role}")
			p.SQL().SetMaxOpenConns(1)
			_, err := p.SQL().ExecContext(t.Context(), "SET ROLE "+migrations.RolePrefix+"_app")
			require.NoError(t, err)
			return p
		}, wantErr: "acts as " + migrations.RolePrefix + "_app"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tenancy.CheckRoles(t.Context(), tt.app(t), w.d.Operator)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}

	w.d.Admin(t, "CREATE VIEW superuser_roles AS SELECT tenant_id, code FROM roles")
	require.ErrorContains(t, tenancy.CheckRoles(t.Context(), w.d.DB, w.d.Operator), "view superuser_roles is owned by",
		"a view a superuser made skips every policy")
}

// The operator login bypasses row-level security itself and holds nothing more: no superuser, role or
// database creation or replication, of its own or through a role it belongs to.
func TestCheckRoles_OperatorRole(t *testing.T) {
	d := testdb.Tenancy(t)
	tests := []struct {
		name, attrs, member, wantErr string
	}{
		{name: "bypassrls and nothing more", attrs: "bypassrls"},
		{name: "bypassrls only through a membership", attrs: "nobypassrls", member: "bypassrls", wantErr: "does not bypass row-level security"},
		{name: "a superuser", attrs: "superuser bypassrls", wantErr: "is a superuser"},
		{name: "may create roles", attrs: "bypassrls createrole", wantErr: "may create roles"},
		{name: "may create databases", attrs: "bypassrls createdb", wantErr: "may create databases"},
		{name: "may replicate", attrs: "bypassrls replication", wantErr: "may replicate"},
		{name: "a member of a superuser", attrs: "bypassrls", member: "superuser", wantErr: "is a member of"},
		{name: "a member of a role that may create roles", attrs: "bypassrls", member: "createrole", wantErr: "is a member of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := d.TempRole(t, tt.attrs)
			if tt.member != "" {
				d.Admin(t, `GRANT "`+d.TempRole(t, tt.member)+`" TO "`+role+`"`)
			}
			err := tenancy.CheckRoles(t.Context(), d.DB, d.AsOperator(t, role))
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

type seen struct {
	tenant  string
	roles   int
	touched int64
}

// A job enqueued in a tenant runs with that tenant set and cannot reach another's rows; a job without a
// tenant runs only when its kind is registered as global; a suspended tenant's job waits.
func TestJobs_RunInTheTenantTheyWereEnqueuedIn(t *testing.T) {
	w := newWorld(t)
	cfg := jobs.Defaults()
	cfg.Lanes = jobs.NewLanes(jobs.LaneWorkers{Name: "fast", Workers: 1})
	cfg.Lease, cfg.Poll, cfg.ShutdownGrace = time.Minute, 20*time.Millisecond, 0
	q, err := jobs.New(jobs.Options{Config: cfg, Tx: jobs.OperatorTx(w.d.Operator)})
	require.NoError(t, err)
	run := tenancy.Runner(w.d.DB)

	results := make(chan seen, 2)
	q.Handle("probe", func(ctx context.Context, _ jobs.Job) error {
		var s seen
		if id, ok := db.TenantOf(ctx); ok {
			s.tenant = id.String()
		}
		err := run(ctx, func(ctx context.Context, tx db.Transaction) error {
			var err error
			if s.roles, err = count(ctx, tx, "SELECT count(*) FROM roles WHERE tenant_id IS NOT NULL"); err != nil {
				return err
			}
			res, err := tx.Q().ExecContext(ctx, "UPDATE roles SET name = 'taken' WHERE tenant_id = $1", w.b.ID)
			if err != nil {
				return err
			}
			s.touched, err = res.RowsAffected()
			return err
		})
		results <- s
		return err
	})

	var tenantJob, globalJob jobs.ID
	require.NoError(t, db.InTx(w.in(w.a), w.d.DB, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		var err error
		tenantJob, err = q.Enqueue(ctx, tx, "probe", nil)
		return err
	}))
	require.NoError(t, db.InTx(t.Context(), w.d.DB, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		globalJob, err = q.Enqueue(ctx, tx, "probe", nil)
		return err
	}))
	var heldJob jobs.ID
	require.NoError(t, db.InTx(w.in(w.b), w.d.DB, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		var err error
		heldJob, err = q.Enqueue(ctx, tx, "probe", nil)
		return err
	}))
	require.NoError(t, db.InOperatorTx(t.Context(), w.d.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		_, err := w.svc.SetState(ctx, tx, w.b.ID, tenancy.Suspended, "")
		return err
	}))

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- q.Run(ctx) }()
	defer func() {
		cancel()
		require.NoError(t, <-done)
	}()

	select {
	case s := <-results:
		assert.Equal(t, seen{tenant: w.a.ID.String(), roles: 1, touched: 0}, s)
	case <-time.After(10 * time.Second):
		t.Fatal("the tenant's job did not run")
	}
	require.Eventually(t, func() bool { return status(t, w, globalJob) == "failed" }, 10*time.Second, 20*time.Millisecond,
		"a job without a tenant of a kind not registered as global fails without running")
	assert.Equal(t, "done", status(t, w, tenantJob))
	require.Eventually(t, func() bool { return postponed(t, w, heldJob) }, 10*time.Second, 20*time.Millisecond,
		"the suspended tenant's job waits, its attempt given back")
	assert.Empty(t, results, "the refused and the held jobs never ran")
}

func postponed(t *testing.T, w *world, id jobs.ID) bool {
	t.Helper()
	var n int
	require.NoError(t, db.InOperatorTx(t.Context(), w.d.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		var err error
		n, err = count(ctx, tx, "SELECT count(*) FROM jobs WHERE id = $1 AND status = 'queued' AND attempts = 0 AND run_at > now() + interval '10 minutes'", id)
		return err
	}))
	return n == 1
}

func status(t *testing.T, w *world, id jobs.ID) string {
	t.Helper()
	var s string
	require.NoError(t, db.InOperatorTx(t.Context(), w.d.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		rows, err := tx.Q().QueryContext(ctx, "SELECT status FROM jobs WHERE id = $1", id)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			if err := rows.Scan(&s); err != nil {
				return err
			}
		}
		return rows.Err()
	}))
	return s
}

// Each tenant's audit rows chain on their own head and verify alone; the creation was recorded with the
// tenant it made.
func TestAudit_ChainsPerTenant(t *testing.T) {
	w := newWorld(t)
	for _, tn := range []tenancy.Tenant{w.a, w.b} {
		var rep audit.Report
		var trail []audit.Entry
		require.NoError(t, db.InOperatorTx(w.in(tn), w.d.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
			var err error
			if rep, err = audit.Verify(ctx, tx); err != nil {
				return err
			}
			trail, err = audit.List(ctx, tx, 0, 10)
			return err
		}))
		assert.Equal(t, 1, rep.Chained, tn.Slug)
		require.Len(t, trail, 1)
		assert.Equal(t, "tenant.created", trail[0].Action)
		var image map[string]any
		require.NoError(t, json.Unmarshal(trail[0].After, &image))
		assert.Equal(t, tn.Slug, image["slug"])
	}
}

// Each pool logs in as its own role, so RESET ROLE leaves it there and SET ROLE reaches no role above it:
// the app pool no superuser, owner or role that bypasses row-level security, the operator pool no
// superuser or owner (who could change the policies).
func TestPools_CannotSwitchToAPrivilegedRole(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	var aboveApp, aboveOperator []string
	require.NoError(t, db.InTx(ctx, w.d.DB, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		if aboveOperator, err = names(ctx, tx, "SELECT rolname FROM pg_roles WHERE rolsuper OR rolname = $1", migrations.RolePrefix+"_owner"); err != nil {
			return err
		}
		aboveApp, err = names(ctx, tx, "SELECT rolname FROM pg_roles WHERE rolsuper OR rolbypassrls OR rolname = $1", migrations.RolePrefix+"_owner")
		return err
	}))
	require.NotEmpty(t, aboveOperator)

	pools := []struct {
		name  string
		run   func(fn func(ctx context.Context, tx db.Transaction) error) error
		above []string
		rows  int
	}{
		{"app", func(fn func(ctx context.Context, tx db.Transaction) error) error {
			return db.InTx(ctx, w.d.DB, func(ctx context.Context, tx db.Tx[db.Plain]) error { return fn(ctx, tx) })
		}, aboveApp, 0},
		{"operator", func(fn func(ctx context.Context, tx db.Transaction) error) error {
			return db.InOperatorTx(ctx, w.d.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error { return fn(ctx, tx) })
		}, aboveOperator, 2},
	}
	for _, p := range pools {
		t.Run(p.name, func(t *testing.T) {
			var who []string
			var rows int
			require.NoError(t, p.run(func(ctx context.Context, tx db.Transaction) error {
				if _, err := tx.Q().ExecContext(ctx, "RESET ROLE"); err != nil {
					return err
				}
				var err error
				if who, err = names(ctx, tx, "SELECT unnest(ARRAY[session_user::text, current_user::text])"); err != nil {
					return err
				}
				rows, err = count(ctx, tx, "SELECT count(*) FROM roles WHERE tenant_id IS NOT NULL")
				return err
			}))
			require.Len(t, who, 2)
			assert.Equal(t, who[0], who[1], "RESET ROLE stays the role the pool logged in as")
			assert.NotContains(t, p.above, who[0])
			assert.Equal(t, p.rows, rows)
			for _, role := range p.above {
				err := p.run(func(ctx context.Context, tx db.Transaction) error {
					_, err := tx.Q().ExecContext(ctx, `SET ROLE "`+role+`"`)
					return err
				})
				require.Error(t, err, "SET ROLE %s", role)
			}
		})
	}
}

func names(ctx context.Context, tx db.Transaction, query string, args ...any) ([]string, error) {
	rows, err := tx.Q().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

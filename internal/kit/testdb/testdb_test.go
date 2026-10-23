package testdb_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

func TestIsolated_IsMigratedAndSeparate(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		ctx := t.Context()
		shared, own := e.DB(), e.Isolated(t)
		insert := map[db.Dialect]string{
			db.Postgres: "INSERT INTO locks (name) VALUES ($1)",
			db.MySQL:    "INSERT INTO locks (name) VALUES (?)",
		}[e.Dialect()]
		_, err := own.SQL().ExecContext(ctx, insert, "testdb:isolated")
		require.NoError(t, err, "the clone carries the migrated schema")

		var n int
		require.NoError(t, shared.SQL().QueryRowContext(ctx, "SELECT COUNT(*) FROM locks WHERE name = 'testdb:isolated'").Scan(&n))
		assert.Zero(t, n, "writes to one database never show in another")
	})
}

func TestPostgres_ConnectsAsTheAppRole(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		if e.Dialect() != db.Postgres {
			t.Skip("roles are separated on Postgres only")
		}
		var switched, member, bypass bool
		require.NoError(t, e.DB().SQL().QueryRowContext(t.Context(),
			"SELECT session_user <> current_user, pg_has_role(current_user, $1, 'MEMBER'), rolbypassrls FROM pg_roles WHERE rolname = current_user",
			migrations.RolePrefix+"_app").Scan(&switched, &member, &bypass))
		assert.False(t, switched, "tests log in as the role they act as, as apps do")
		assert.True(t, member, "with the app role's grants")
		assert.False(t, bypass, "row-level security applies in tests as in production")
	})
}

// MySQL tests run as a login with the production app user's grants: table DML, audit_log append-only,
// no DDL.
func TestMySQL_ConnectsWithTheAppUsersGrants(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		if e.Dialect() != db.MySQL {
			t.Skip("Postgres tests run as the app role")
		}
		d := e.Isolated(t)
		_, err := d.SQL().ExecContext(t.Context(), "INSERT INTO locks (name) VALUES ('testdb:grants')")
		require.NoError(t, err, "table DML")
		_, err = d.SQL().ExecContext(t.Context(), "DELETE FROM audit_log")
		require.ErrorContains(t, err, "denied", "the audit log is append-only")
		_, err = d.SQL().ExecContext(t.Context(), "CREATE TABLE testdb_extra (id int)")
		require.ErrorContains(t, err, "denied", "no DDL")
	})
}

//go:build !notenancy

package app_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

// doctor passes a healthy local setup with every database check; each part's test breaks its own check.
func TestDoctor_PassesAHealthySetup(t *testing.T) {
	d := testdb.Tenancy(t)
	cfg, err := app.LoadConfig([]string{"APP_ENV=local", signingKeys})
	require.NoError(t, err)
	for _, c := range app.Diagnose(t.Context(), cfg, app.Deps{DB: d.DB, Operator: d.Operator, Tenancy: true}) {
		assert.NotEqual(t, app.Fail, c.Status, "%s: %s", c.Name, c.Detail)
	}
}

// With the database unreachable or its schema behind, every database check still has its own line: the
// ones that need what is missing are skipped, the rest run and report.
func TestDoctor_ReportsEveryDatabaseCheckOnItsOwn(t *testing.T) {
	t.Run("unreachable", func(t *testing.T) {
		code, out, _ := runCommand(t, []string{
			"APP_ENV=local", signingKeys,
			"APP_DATABASE_URL=postgres://keel:x@127.0.0.1:1/keel?sslmode=disable",
		}, "doctor", "--json")
		var rows []map[string]string
		require.NoError(t, json.Unmarshal([]byte(out), &rows), out)
		got := map[string]string{}
		for _, r := range rows {
			got[r["check"]] = r["status"]
		}

		assert.Equal(t, 1, code)
		assert.Equal(t, "fail", got["database"])
		for _, name := range []string{"migrations", "roles", "row-level security", "jobs", "clock"} {
			assert.Equal(t, "skip", got[name], name)
		}
		assert.Equal(t, "pass", got["operations"])
	})
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		tenancy := e.Dialect() == db.Postgres
		cfg, err := app.LoadConfig([]string{"APP_ENV=local", signingKeys})
		require.NoError(t, err)

		got := map[string]app.CheckStatus{}
		for _, c := range app.Diagnose(t.Context(), cfg, app.Deps{DB: e.Empty(t), Tenancy: tenancy}) {
			got[c.Name] = c.Status
		}

		assert.Equal(t, app.Warn, got["database"], "reachable, TLS not verified")
		assert.Equal(t, app.Fail, got["migrations"])
		assert.Equal(t, app.Skip, got["jobs"])
		assert.Equal(t, app.Pass, got["clock"])
		if tenancy {
			assert.Equal(t, app.Fail, got["roles"], "no operator pool")
			assert.Equal(t, app.Skip, got["row-level security"])
		}
	})
}

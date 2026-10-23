package audit_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

type secret struct {
	Name  string `json:"name"`
	Value string `json:"value" audit:"redact"`
}

func verify(t *testing.T, d *db.DB) (audit.Report, error) {
	t.Helper()
	var rep audit.Report
	err := db.InTx(t.Context(), d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		rep, err = audit.Verify(ctx, tx)
		return err
	})
	return rep, err
}

// Concurrent chained writes form one chain even when each transaction read from an older snapshot
// first (repeatable read on both engines); the app role cannot rewrite it, and on MySQL, where only the
// grant protects it, Verify reports each row the owner rewrites and a deleted tail.
func TestRecord_HashChain(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		d := e.Isolated(t)
		rec := audit.New(audit.Options{Chain: true})
		actor := ids.New()
		ctx := audit.WithActor(t.Context(), audit.Actor{Type: audit.ActorUser, ID: &actor})

		errs := make(chan error, 8)
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Go(func() {
				errs <- db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
					if err := readFirst(ctx, tx); err != nil {
						return err
					}
					return rec.Record(ctx, tx, audit.Event{
						Action: "secret.changed", Entity: "secret", EntityID: ids.New().String(),
						Before: secret{Name: "a", Value: "old"}, After: secret{Name: "a", Value: strconv.Itoa(i)},
					})
				}, db.Isolation(sql.LevelRepeatableRead), db.Retry(10))
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
		rep, err := verify(t, d)
		require.NoError(t, err)
		assert.Equal(t, 8, rep.Chained)

		var after string
		require.NoError(t, d.SQL().QueryRowContext(ctx, "SELECT "+col(d, "after")+" FROM audit_log ORDER BY seq LIMIT 1").Scan(&after))
		assert.Contains(t, after, `[redacted]`)
		assert.NotRegexp(t, `[0-9]`, after, "the secret value never reaches the log")

		rewrite := "UPDATE audit_log SET action = 'secret.read' WHERE seq = (SELECT s FROM (SELECT seq AS s FROM audit_log ORDER BY seq LIMIT 1 OFFSET %d) x)"
		_, err = d.SQL().ExecContext(ctx, fmt.Sprintf(rewrite, 0))
		require.Error(t, err, "the app role may not update audit rows")
		_, err = d.SQL().ExecContext(ctx, "DELETE FROM audit_log")
		require.Error(t, err, "nor delete them")
		if e.Dialect() == db.Postgres {
			return
		}
		// MySQL cannot make the table append-only for its owner, so whoever holds those credentials can
		// rewrite rows; the chain shows it.
		owner := e.Owner(t, d)
		_, err = owner.SQL().ExecContext(ctx, fmt.Sprintf(rewrite, 0))
		require.NoError(t, err)
		_, err = owner.SQL().ExecContext(ctx, fmt.Sprintf(rewrite, 2))
		require.NoError(t, err)
		rep, err = verify(t, d)
		require.ErrorIs(t, err, audit.ErrChainBroken)
		assert.Len(t, rep.Breaks, 2, "every rewritten row is reported, not only the first")

		_, err = owner.SQL().ExecContext(ctx, "DELETE FROM audit_log ORDER BY seq DESC LIMIT 1")
		require.NoError(t, err)
		rep, _ = verify(t, d)
		assert.Equal(t, "the chain head does not name the last chained row", rep.Breaks[len(rep.Breaks)-1].Reason)
	})
}

// Numbers come back from jsonb and MySQL json rewritten (1e21 as 1000000000000000000000 or 1e21);
// the chain hashes an exact decimal form so either reads back the same. Unchained rows are counted.
func TestVerify_NumbersSurviveTheRoundTripAndUnchainedRowsAreCounted(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		d := e.Isolated(t)
		ctx := t.Context()
		numbers := map[string]any{"float": 1.5e-7, "big": 1e21, "huge": 1e300}
		for i, n := range []string{"1e21", "1.5e-7", "1E2", "100.0", "-0", "1e-300", "-12.50", "18446744073709551615"} {
			numbers["n"+strconv.Itoa(i)] = json.Number(n)
		}
		require.NoError(t, db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			return audit.New(audit.Options{Chain: true}).Record(ctx, tx, audit.Event{Action: "x.changed", After: numbers})
		}))
		require.NoError(t, db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			return audit.New(audit.Options{}).Record(ctx, tx, audit.Event{Action: "job.ran", Entity: "job"})
		}))

		rep, err := verify(t, d)
		require.NoError(t, err)
		assert.Equal(t, audit.Report{Chained: 1, Unchained: 1}, rep)
	})
}

func TestRecord_TakesContextAndRefusesBadEvents(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		d := e.DB()
		rec := audit.New(audit.Options{})
		ctx := t.Context()

		err := db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			return rec.Record(ctx, tx, audit.Event{Entity: "x"})
		})
		require.ErrorIs(t, err, audit.ErrInvalidEvent)

		entity := ids.New().String()
		require.NoError(t, db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			return rec.Record(ctx, tx, audit.Event{Action: "job.ran", Entity: "job", EntityID: entity})
		}))
		var actorType string
		var prev []byte
		require.NoError(t, d.SQL().QueryRowContext(ctx, "SELECT actor_type, prev_hash FROM audit_log WHERE entity_id = "+bind(d), entity).Scan(&actorType, &prev))
		assert.Equal(t, "system", actorType, "no actor in the context means the system acted")
		assert.Nil(t, prev, "unchained rows carry no hash")
	})
}

// readFirst fixes the transaction's snapshot before it records, as real services do.
func readFirst(ctx context.Context, tx db.Tx[db.Plain]) error {
	rows, err := tx.Q().QueryContext(ctx, "SELECT count(*) FROM audit_log")
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			return err
		}
	}
	return rows.Err()
}

func bind(d *db.DB) string { return db.Rebind(d.Dialect(), "?") }

func col(d *db.DB, name string) string {
	if d.Dialect() == db.MySQL {
		return "`" + name + "`"
	}
	return name
}

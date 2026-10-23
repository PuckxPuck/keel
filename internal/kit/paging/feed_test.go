package paging_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go-jet/jet/v2/mysql"
	"github.com/go-jet/jet/v2/postgres"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

type doc struct {
	ID        uuid.UUID `alias:"paging_docs.id"`
	Title     string    `alias:"paging_docs.title"`
	Version   int64     `alias:"paging_docs.version"`
	ChangeXid string    `alias:"paging_docs.change_xid"`
	ChangedAt time.Time `alias:"paging_docs.changed_at"`
}

var (
	docID, docTitle, docVersion = postgres.StringColumn("id"), postgres.StringColumn("title"), postgres.IntegerColumn("version")
	docXID, docChangedAt        = postgres.StringColumn("change_xid"), postgres.TimestampColumn("changed_at")
	pgDocs                      = postgres.NewTable("", "paging_docs", "", docID, docTitle, docVersion, docXID)
	myDocs                      = mysql.NewTable("", "paging_docs", "", docID, docTitle, docVersion, docChangedAt)
)

const docRetention = 30 * 24 * time.Hour

func newFeed(t *testing.T, dialect db.Dialect, lag time.Duration) *paging.Feed {
	t.Helper()
	f, err := paging.NewFeed(keyset(t, dialect, "f"), paging.FeedOptions{Entity: "paging_docs", Retention: docRetention, Lag: lag})
	require.NoError(t, err)
	return f
}

func readFeed(ctx context.Context, d *db.DB, f *paging.Feed, token string, limit int) (paging.FeedPage[string], error) {
	var page paging.FeedPage[string]
	err := db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		w, err := f.Open(ctx, tx, token, nil)
		if err != nil {
			return err
		}
		var rows []doc
		if d.Dialect() == db.Postgres {
			pos := docXID
			err = postgres.SELECT(docID, docTitle, docVersion, docXID).FROM(pgDocs).WHERE(w.Where(pos, docID)).
				ORDER_BY(w.OrderBy(pos, docID)...).LIMIT(int64(limit+1)).QueryContext(ctx, tx.Q(), &rows)
		} else {
			pos := docChangedAt
			err = mysql.SELECT(docID, docTitle, docVersion, docChangedAt).FROM(myDocs).WHERE(w.Where(pos, docID)).
				ORDER_BY(w.OrderBy(pos, docID)...).LIMIT(int64(limit+1)).QueryContext(ctx, tx.Q(), &rows)
		}
		if err != nil {
			return err
		}
		page, err = paging.Changes(ctx, tx, w, rows, limit,
			func(r doc) paging.Change {
				return paging.Change{ID: r.ID, Version: r.Version, XID: r.ChangeXid, ChangedAt: r.ChangedAt}
			},
			func(r doc) string { return r.Title })
		return err
	}, db.ReadOnly())
	return page, err
}

func insertDoc(ctx context.Context, d *db.DB, title string) (uuid.UUID, error) {
	id := ids.New()
	_, err := d.SQL().ExecContext(ctx, db.Rebind(d.Dialect(), "INSERT INTO paging_docs (id, title) VALUES (?, ?)"), id, title)
	return id, err
}

func titles(p paging.FeedPage[string]) []string {
	var out []string
	for _, e := range p.Entries {
		if e.Op == httpx.FeedDelete {
			out = append(out, "-"+e.ID)
			continue
		}
		out = append(out, *e.Record)
	}
	return out
}

func TestFeed_LateCommitAppearsInTheNextPage(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		if e.Dialect() != db.Postgres {
			t.Skip("the commit-safe watermark is Postgres; MySQL relies on the lag window (TestFeed_MySQLReadsStopAtTheLag)")
		}
		ctx := t.Context()
		d := e.Isolated(t)
		f := newFeed(t, e.Dialect(), time.Second)
		_, err := insertDoc(ctx, d, "before")
		require.NoError(t, err)

		late, err := d.SQL().BeginTx(ctx, nil)
		require.NoError(t, err)
		defer func() { _ = late.Rollback() }()
		_, err = late.ExecContext(ctx, "INSERT INTO paging_docs (id, title) VALUES ($1, $2)", ids.New(), "late")
		require.NoError(t, err)
		_, err = insertDoc(ctx, d, "after")
		require.NoError(t, err)

		first, err := readFeed(ctx, d, f, "", 10)
		require.NoError(t, err)
		assert.NotContains(t, titles(first), "after", "a change committed behind an open transaction must wait for it")

		require.NoError(t, late.Commit())
		got := append([]string{}, titles(first)...)
		token := first.Next
		// The watermark is cluster-wide, so transactions of tests running in other databases can hold it
		// back for a moment; read until the feed catches up.
		for deadline := time.Now().Add(10 * time.Second); len(got) < 3 && time.Now().Before(deadline); { //nolint:forbidigo // waits on other sessions
			next, err := readFeed(ctx, d, f, token, 10)
			require.NoError(t, err)
			got, token = append(got, titles(next)...), next.Next
			if len(got) < 3 {
				time.Sleep(20 * time.Millisecond)
			}
		}
		assert.Equal(t, []string{"before", "late", "after"}, got, "every change exactly once, in commit-safe order")
	})
}

func TestFeed_MySQLReadsStopAtTheLag(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		if e.Dialect() != db.MySQL {
			t.Skip("the lag window is MySQL's")
		}
		ctx := t.Context()
		d := e.Isolated(t)
		f := newFeed(t, e.Dialect(), 10*time.Second)
		old, err := insertDoc(ctx, d, "old")
		require.NoError(t, err)
		_, err = d.SQL().ExecContext(ctx, "UPDATE paging_docs SET changed_at = NOW(6) - INTERVAL 20 SECOND WHERE id = ?", old)
		require.NoError(t, err)
		recent, err := insertDoc(ctx, d, "recent")
		require.NoError(t, err)

		page, err := readFeed(ctx, d, f, "", 10)
		require.NoError(t, err)
		assert.Equal(t, []string{"old"}, titles(page), "changes inside the lag window must wait")

		// as if 15 seconds passed: the change is still after the token but now outside the window
		_, err = d.SQL().ExecContext(ctx, "UPDATE paging_docs SET changed_at = changed_at - INTERVAL 15 SECOND WHERE id = ?", recent)
		require.NoError(t, err)
		page, err = readFeed(ctx, d, f, page.Next, 10)
		require.NoError(t, err)
		assert.Equal(t, []string{"recent"}, titles(page))
	})
}

func TestFeed_DeliversTombstonesInOrder(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		ctx := t.Context()
		d := e.Isolated(t)
		// a microsecond lag: on MySQL these changes are read only after they committed
		f := newFeed(t, e.Dialect(), time.Microsecond)
		var gone uuid.UUID
		for _, title := range []string{"a", "b", "c"} {
			id, err := insertDoc(ctx, d, title)
			require.NoError(t, err)
			if title == "b" {
				gone = id
			}
		}
		first, token := readUntil(ctx, t, d, f, "", 2, 2)
		assert.Equal(t, []string{"a", "b"}, first)

		require.NoError(t, db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM paging_docs WHERE id = ?"), gone); err != nil {
				return err
			}
			return paging.Tombstone(ctx, tx, "paging_docs", gone)
		}))
		next, token := readUntil(ctx, t, d, f, token, 10, 2)
		assert.Equal(t, []string{"c", "-" + gone.String()}, next)

		other, err := paging.NewFeed(keyset(t, e.Dialect(), "f"), paging.FeedOptions{Entity: "other", Retention: docRetention})
		require.NoError(t, err)
		_, err = readFeed(ctx, d, other, token, 10)
		require.ErrorIs(t, err, paging.ErrCursorMismatch, "a token is bound to its feed")

		later := clock.WithWall(ctx, clock.Fixed(clock.Wall(ctx).Now().Add(docRetention+time.Hour)))
		_, err = readFeed(later, d, f, token, 10)
		require.ErrorIs(t, err, paging.ErrResyncRequired)
		p, ok := paging.Mapper(err)
		require.True(t, ok)
		assert.Equal(t, http.StatusGone, p.Status)

		var pruned int64
		require.NoError(t, db.InTx(later, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			pruned, err = paging.PruneTombstones(ctx, tx, clock.Wall(ctx).Now().Add(-docRetention), 100)
			return err
		}))
		assert.Equal(t, int64(1), pruned)
	})
}

// readUntil reads pages of limit until want entries arrived or the watermark never lets them through.
func readUntil(ctx context.Context, t *testing.T, d *db.DB, f *paging.Feed, token string, limit, want int) ([]string, string) {
	t.Helper()
	var got []string
	for deadline := time.Now().Add(10 * time.Second); len(got) < want && time.Now().Before(deadline); { //nolint:forbidigo // waits on other sessions
		page, err := readFeed(ctx, d, f, token, limit)
		require.NoError(t, err)
		require.LessOrEqual(t, len(page.Entries), limit)
		got, token = append(got, titles(page)...), page.Next
		if len(page.Entries) == 0 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	return got, token
}

func TestFeed_RecreatedRowFollowsItsTombstoneAcrossPages(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		ctx := t.Context()
		d := e.Isolated(t)
		f := newFeed(t, e.Dialect(), time.Microsecond)
		id, err := insertDoc(ctx, d, "v1")
		require.NoError(t, err)
		first, token := readUntil(ctx, t, d, f, "", 10, 1)
		require.Equal(t, []string{"v1"}, first)

		require.NoError(t, db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM paging_docs WHERE id = ?"), id); err != nil {
				return err
			}
			if err := paging.Tombstone(ctx, tx, "paging_docs", id); err != nil {
				return err
			}
			_, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "INSERT INTO paging_docs (id, title) VALUES (?, ?)"), id, "v2")
			return err
		}))
		if e.Dialect() == db.MySQL {
			// one transaction shares one position on Postgres; give MySQL's two statements the same one
			_, err = d.SQL().ExecContext(ctx, "UPDATE tombstones t JOIN paging_docs d ON d.id = t.id SET t.changed_at = d.changed_at WHERE t.id = ?", id)
			require.NoError(t, err)
		}
		got, _ := readUntil(ctx, t, d, f, token, 1, 2)
		assert.Equal(t, []string{"-" + id.String(), "v2"}, got, "the recreated row must follow its tombstone even when a page ends between them")
	})
}

func TestFeed_CaughtUpTokenExpiresLagEarly(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		ctx := t.Context()
		d := e.Isolated(t)
		const lag = 10 * time.Minute
		f := newFeed(t, e.Dialect(), lag)
		page, err := readFeed(ctx, d, f, "", 10)
		require.NoError(t, err)
		require.False(t, page.HasMore)

		now := clock.Wall(ctx).Now()
		at := func(d time.Duration) context.Context { return clock.WithWall(ctx, clock.Fixed(now.Add(d))) }
		_, err = readFeed(at(docRetention-2*lag), d, f, page.Next, 10)
		require.NoError(t, err)
		// a delete in flight when the token was made may be up to lag older than it, and is pruned at retention
		_, err = readFeed(at(docRetention-lag/2), d, f, page.Next, 10)
		require.ErrorIs(t, err, paging.ErrResyncRequired)
	})
}

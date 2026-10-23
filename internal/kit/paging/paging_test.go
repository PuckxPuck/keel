package paging_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/go-jet/jet/v2/mysql"
	"github.com/go-jet/jet/v2/postgres"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

var schema = map[db.Dialect][]string{
	db.Postgres: {
		`create table paging_groups (id uuid primary key, name text not null)`,
		`create table paging_items (id uuid primary key, group_id uuid not null references paging_groups (id), score integer not null,
			flagged boolean not null, due_on date, created_at timestamptz not null)`,
		`create table paging_docs (id uuid primary key, title text not null, version integer not null default 1,
			change_xid xid8 not null default pg_current_xact_id())`,
	},
	db.MySQL: {
		`create table paging_groups (id char(36) character set ascii collate ascii_bin primary key, name varchar(32) not null)`,
		`create table paging_items (id char(36) character set ascii collate ascii_bin primary key,
			group_id char(36) character set ascii collate ascii_bin not null references paging_groups (id), score int not null,
			flagged boolean not null, due_on date, created_at datetime(6) not null)`,
		`create table paging_docs (id char(36) character set ascii collate ascii_bin primary key, title varchar(64) not null,
			version int not null default 1, changed_at datetime(6) not null default current_timestamp(6))`,
	},
}

var groupIDs = []uuid.UUID{ids.Stable(uuid.NameSpaceOID, "north"), ids.Stable(uuid.NameSpaceOID, "north-2"), ids.Stable(uuid.NameSpaceOID, "south")}

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{
		Migrations: migrations.FS,
		RolePrefix: migrations.RolePrefix,
		Template: testdb.WithTemplate("paging", 3, func(ctx context.Context, owner *db.DB) error {
			for _, stmt := range schema[owner.Dialect()] {
				if _, err := owner.SQL().ExecContext(ctx, stmt); err != nil {
					return err
				}
			}
			for i, name := range []string{"north", "north", "south"} {
				q := db.Rebind(owner.Dialect(), "INSERT INTO paging_groups (id, name) VALUES (?, ?)")
				if _, err := owner.SQL().ExecContext(ctx, q, groupIDs[i], name); err != nil {
					return err
				}
			}
			for i := range 30 {
				if err := insertItem(ctx, owner, i%5, i%3 == 0, base.Add(time.Duration(i)*time.Minute)); err != nil {
					return err
				}
			}
			return nil
		}),
	})
}

var base = time.Date(2026, 10, 1, 9, 0, 0, 123456000, time.UTC)

func insertItem(ctx context.Context, d *db.DB, score int, nullDue bool, at time.Time) error {
	var due *time.Time
	if !nullDue {
		day := at.AddDate(0, 0, at.Minute()%7).Truncate(24 * time.Hour)
		due = &day
	}
	q := db.Rebind(d.Dialect(), "INSERT INTO paging_items (id, group_id, score, flagged, due_on, created_at) VALUES (?, ?, ?, ?, ?, ?)")
	_, err := d.SQL().ExecContext(ctx, q, ids.New(), groupIDs[at.Minute()%3], score, at.Minute()%4 == 0, due, at)
	return err
}

type itemTag struct{}

type item struct {
	ID        ids.ID[itemTag] `alias:"paging_items.id"`
	Score     int32           `alias:"paging_items.score"`
	Flagged   bool            `alias:"paging_items.flagged"`
	DueOn     *time.Time      `alias:"paging_items.due_on"`
	CreatedAt time.Time       `alias:"paging_items.created_at"`
}

type group struct {
	ID   uuid.UUID `alias:"paging_groups.id"`
	Name string    `alias:"paging_groups.name"`
}

// joined has two ID fields, so a sort key must say which one it reads.
type joined struct {
	Item  item
	Group group
}

var (
	itemID, groupID, groupRef = postgres.StringColumn("id"), postgres.StringColumn("id"), postgres.StringColumn("group_id")
	score, flagged            = postgres.IntegerColumn("score"), postgres.BoolColumn("flagged")
	due, created, groupName   = postgres.DateColumn("due_on"), postgres.TimestampzColumn("created_at"), postgres.StringColumn("name")
	itemCols                  = []postgres.Column{itemID, groupRef, score, flagged, due, created}
	groupCols                 = []postgres.Column{groupID, groupName}
	pgItems, pgGroups         = postgres.NewTable("", "paging_items", "", itemCols...), postgres.NewTable("", "paging_groups", "", groupCols...)
	myItems, myGroups         = mysql.NewTable("", "paging_items", "", itemCols...), mysql.NewTable("", "paging_groups", "", groupCols...)
)

func byID(r joined) any { return r.Item.ID }

var sorts = paging.Sorts[joined]{
	"score":     {{Column: score, Value: func(r joined) any { return r.Item.Score }}, {Column: itemID, Value: byID}},
	"flagged":   {{Column: flagged, Value: func(r joined) any { return r.Item.Flagged }}, {Column: itemID, Value: byID}},
	"dueOn":     {{Column: due, Value: func(r joined) any { return paging.Opt(r.Item.DueOn) }, Nullable: true}, {Column: itemID, Value: byID}},
	"createdAt": {{Column: created, Value: func(r joined) any { return r.Item.CreatedAt }}, {Column: itemID, Value: byID}},
	"group": {
		{Column: groupName, Value: func(r joined) any { return r.Group.Name }},
		{Column: groupID, Value: func(r joined) any { return r.Group.ID }},
		{Column: itemID, Value: byID},
	},
}

func list(ctx context.Context, d *db.DB, where postgres.BoolExpression, s paging.Sort[joined], limit int) ([]joined, error) {
	var out []joined
	var cols []postgres.Projection
	for _, c := range append(append([]postgres.Column{}, itemCols...), groupCols...) {
		cols = append(cols, c)
	}
	if d.Dialect() == db.Postgres {
		err := postgres.SELECT(cols[0], cols[1:]...).FROM(pgItems.INNER_JOIN(pgGroups, groupRef.EQ(groupID))).
			WHERE(where).ORDER_BY(s.OrderBy()...).LIMIT(int64(limit+1)).QueryContext(ctx, d.SQL(), &out)
		return out, err
	}
	err := mysql.SELECT(cols[0], cols[1:]...).FROM(myItems.INNER_JOIN(myGroups, groupRef.EQ(groupID))).
		WHERE(where).ORDER_BY(s.OrderBy()...).LIMIT(int64(limit+1)).QueryContext(ctx, d.SQL(), &out)
	return out, err
}

func keyset(t *testing.T, d db.Dialect, keys ...string) *paging.Keyset {
	t.Helper()
	raw := make([][]byte, len(keys))
	for i, k := range keys {
		raw[i] = bytes.Repeat([]byte(k), 32)
	}
	k, err := paging.NewKeyset(d, raw...)
	require.NoError(t, err)
	return k
}

type filter struct {
	Status string `json:"status"`
}

func TestKeysetWalk_ReturnsEveryRowOnceWhileRowsArrive(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		ctx := t.Context()
		d := e.Isolated(t)
		k := keyset(t, e.Dialect(), "a")
		f := filter{Status: "open"}

		all, err := sorts.Resolve("createdAt", "")
		require.NoError(t, err)
		original, err := list(ctx, d, postgres.RawBool("TRUE"), all, 1000)
		require.NoError(t, err)
		require.Len(t, original, 30)

		extra := 0
		for _, sortKey := range []string{"score", "-score", "flagged", "-flagged", "dueOn", "-dueOn", "createdAt", "-createdAt", "group", "-group"} {
			t.Run(sortKey, func(t *testing.T) {
				s, err := sorts.Resolve(sortKey, "")
				require.NoError(t, err)
				seen := map[ids.ID[itemTag]]int{}
				token := ""
				for pages := range 100 {
					cond, err := k.After(token, s, f)
					require.NoError(t, err)
					rows, err := list(ctx, d, cond, s, 4)
					require.NoError(t, err)
					page, err := paging.Trim(rows, 4, s, f, k, func(r joined) item { return r.Item })
					require.NoError(t, err)
					for _, r := range page.Items {
						seen[r.ID]++
					}
					// While the first pages are read, one row lands before the cursor and one after it, whatever the direction.
					if pages < 3 {
						extra++
						require.NoError(t, insertItem(ctx, d, 0, extra%2 == 0, base.Add(-time.Duration(extra)*time.Hour)))
						require.NoError(t, insertItem(ctx, d, 4, extra%2 == 1, base.Add(time.Duration(extra)*time.Hour)))
					}
					if page.Next == "" {
						break
					}
					token = page.Next
				}
				for _, r := range original {
					assert.Equal(t, 1, seen[r.Item.ID], "row %s", r.Item.ID)
				}
				for id, n := range seen {
					assert.Equal(t, 1, n, "row %s seen more than once", id)
				}
			})
		}
	})
}

func TestCursor_Refusals(t *testing.T) {
	k := keyset(t, db.Postgres, "a")
	byScore, err := sorts.Resolve("score", "")
	require.NoError(t, err)
	rows := []joined{{Item: item{ID: ids.NewOf[itemTag](), Score: 1}}, {Item: item{ID: ids.NewOf[itemTag](), Score: 2}}}
	page, err := paging.Trim(rows, 1, byScore, filter{Status: "open"}, k, func(r joined) joined { return r })
	require.NoError(t, err)
	require.NotEmpty(t, page.Next)

	byScoreDesc, err := sorts.Resolve("-score", "")
	require.NoError(t, err)
	tests := []struct {
		name    string
		keys    *paging.Keyset
		cursor  string
		sort    paging.Sort[joined]
		filter  filter
		wantErr error
	}{
		{name: "same sort and filter", keys: k, cursor: page.Next, sort: byScore, filter: filter{Status: "open"}},
		{name: "after key rotation", keys: keyset(t, db.Postgres, "b", "a"), cursor: page.Next, sort: byScore, filter: filter{Status: "open"}},
		{name: "other filter", keys: k, cursor: page.Next, sort: byScore, filter: filter{Status: "paid"}, wantErr: paging.ErrCursorMismatch},
		{name: "other direction", keys: k, cursor: page.Next, sort: byScoreDesc, filter: filter{Status: "open"}, wantErr: paging.ErrCursorMismatch},
		{name: "retired key", keys: keyset(t, db.Postgres, "b"), cursor: page.Next, sort: byScore, filter: filter{Status: "open"}, wantErr: paging.ErrCursorInvalid},
		{name: "tampered", keys: k, cursor: "x" + page.Next, sort: byScore, filter: filter{Status: "open"}, wantErr: paging.ErrCursorInvalid},
		{name: "garbage", keys: k, cursor: "not-a-cursor", sort: byScore, filter: filter{Status: "open"}, wantErr: paging.ErrCursorInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.keys.After(tt.cursor, tt.sort, tt.filter)
			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantErr != nil {
				p, ok := paging.Mapper(err)
				require.True(t, ok)
				assert.Equal(t, http.StatusBadRequest, p.Status)
			}
		})
	}

	_, err = sorts.Resolve("secret_column", "score")
	require.ErrorIs(t, err, paging.ErrUnknownSort)
}

func TestTrim_RefusesValuesItCannotBind(t *testing.T) {
	k := keyset(t, db.Postgres, "a")
	type row struct {
		Ratio float64
		ID    ids.ID[itemTag]
		Due   *time.Time
	}
	rows := []row{{ID: ids.NewOf[itemTag]()}, {ID: ids.NewOf[itemTag]()}}
	tests := []struct {
		name string
		key  paging.Key[row]
	}{
		{name: "float", key: paging.Key[row]{Column: score, Value: func(r row) any { return r.Ratio }}},
		{name: "pointer without Opt", key: paging.Key[row]{Column: due, Value: func(r row) any { return r.Due }, Nullable: true}},
		{name: "NULL in a key not marked nullable", key: paging.Key[row]{Column: due, Value: func(r row) any { return paging.Opt(r.Due) }}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := paging.Sorts[row]{"x": {tt.key, {Column: itemID, Value: func(r row) any { return r.ID }}}}.Resolve("x", "")
			require.NoError(t, err)
			_, err = paging.Trim(rows, 1, s, nil, k, func(r row) row { return r })
			require.Error(t, err)
		})
	}
}

func TestOffset_DepthCap(t *testing.T) {
	tests := []struct {
		name    string
		offset  paging.Offset
		want    int64
		wantErr error
	}{
		{name: "within the cap", offset: paging.Offset{Page: 3, Limit: 20}, want: 40},
		{name: "last page within the cap", offset: paging.Offset{Page: 50, Limit: 20}, want: 980},
		{name: "past the cap", offset: paging.Offset{Page: 51, Limit: 20}, wantErr: paging.ErrTooDeep},
		{name: "page times limit overflows", offset: paging.Offset{Page: (1 << 62) + 1, Limit: 4}, wantErr: paging.ErrTooDeep},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skip, err := tt.offset.Skip(1000)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, skip)
		})
	}
	_, err := paging.Offset{Page: 0, Limit: 20}.Skip(1000)
	require.Error(t, err)
}

func FuzzCursor(f *testing.F) {
	k, err := paging.NewKeyset(db.Postgres, bytes.Repeat([]byte("k"), 32))
	require.NoError(f, err)
	s, err := sorts.Resolve("score", "")
	require.NoError(f, err)
	for _, seed := range []string{"", "a.b", "e30.", "eyJzIjoicmFuayJ9.AAAA", fmt.Sprintf("%0300d", 0)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		cond, err := k.After(token, s, nil)
		if err == nil {
			assert.NotNil(t, cond)
		}
	})
}

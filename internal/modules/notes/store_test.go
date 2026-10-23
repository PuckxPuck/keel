package notes_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/occ"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/tenancy"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/modules/notes"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

// tenants makes two tenants and returns the database and a context in each.
func tenants(t *testing.T) (*db.DB, context.Context, context.Context) {
	t.Helper()
	d := testdb.Tenancy(t)
	require.NoError(t, tenancy.Install(d.DB))
	return d.DB, db.WithTenant(t.Context(), d.NewTenant(t, "first")), db.WithTenant(t.Context(), d.NewTenant(t, "second"))
}

func newService(t *testing.T, d *db.DB) *notes.Service {
	t.Helper()
	cursors, err := paging.NewKeyset(d.Dialect(), bytes.Repeat([]byte("k"), 32))
	require.NoError(t, err)
	q, err := jobs.New(jobs.Options{Config: jobs.Defaults(), Tx: jobs.PlainTx(d)})
	require.NoError(t, err)
	m := notes.New(notes.Deps{DB: d, Audit: audit.New(audit.Options{}), Cursors: cursors, Jobs: q, FeedRetention: time.Hour})
	m.Jobs(q)
	return m.Service()
}

// Notes are created once per clientId, refused on a stale version, listed a page at a time without
// another tenant's, and a delete reaches the change feed as a tombstone.
func TestService_CreateChangeListDelete(t *testing.T) {
	d, ctx, other := tenants(t)
	svc := newService(t, d)

	clientID := ids.New()
	first, created, err := svc.Create(ctx, nil, notes.Draft{ClientID: &clientID, Title: "  First  ", Body: "one two"})
	require.NoError(t, err)
	assert.True(t, created)
	assert.Equal(t, "First", first.Title)
	again, created, err := svc.Create(ctx, nil, notes.Draft{ClientID: &clientID, Title: "Uploaded twice"})
	require.NoError(t, err)
	assert.False(t, created, "a repeat upload returns the stored note")
	assert.Equal(t, first.ID, again.ID)
	assert.Equal(t, "First", again.Title)
	_, _, err = svc.Create(ctx, nil, notes.Draft{Title: "Second"})
	require.NoError(t, err)
	_, created, err = svc.Create(other, nil, notes.Draft{ClientID: &clientID, Title: "Elsewhere"})
	require.NoError(t, err)
	assert.True(t, created, "clientIds are unique within a tenant")

	renamed := "Renamed"
	changed, err := svc.Update(ctx, nil, first.ID, first.Version, notes.Patch{Title: &renamed})
	require.NoError(t, err)
	assert.Equal(t, first.Version+1, changed.Version)
	_, err = svc.Update(ctx, nil, first.ID, first.Version, notes.Patch{Title: &renamed})
	var stale *occ.StaleError
	require.ErrorAs(t, err, &stale)
	assert.Equal(t, int(changed.Version), stale.Current.Version)

	page, err := svc.List(ctx, notes.Filter{}, paging.Request{Limit: 1, Sort: "title"})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	assert.Equal(t, "Renamed", page.Items[0].Title)
	page, err = svc.List(ctx, notes.Filter{}, paging.Request{Limit: 1, Sort: "title", Cursor: page.Next})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	assert.Equal(t, "Second", page.Items[0].Title)
	assert.Empty(t, page.Next)
	found, err := svc.List(ctx, notes.Filter{Query: "sec"}, paging.Request{Limit: 10, Sort: "title"})
	require.NoError(t, err)
	require.Len(t, found.Items, 1)
	assert.Equal(t, "Second", found.Items[0].Title)

	_, err = svc.Get(other, first.ID)
	require.ErrorIs(t, err, notes.ErrNotFound, "another tenant's note")
	require.ErrorIs(t, svc.Delete(other, first.ID), notes.ErrNotFound)

	start, err := svc.Changes(ctx, "", 10)
	require.NoError(t, err)
	require.NoError(t, svc.Delete(ctx, first.ID))
	_, err = svc.Get(ctx, first.ID)
	require.ErrorIs(t, err, notes.ErrNotFound)

	// The feed's watermark is cluster-wide, so other packages' open transactions can hold it back a moment.
	token, deleted := start.Next, false
	require.Eventually(t, func() bool {
		next, err := svc.Changes(ctx, token, 10)
		if err != nil {
			return false
		}
		for _, e := range next.Entries {
			deleted = deleted || (e.Op == httpx.FeedDelete && e.ID == first.ID.String())
		}
		token = next.Next
		return deleted
	}, 10*time.Second, 20*time.Millisecond, "the delete arrives as a tombstone")
}

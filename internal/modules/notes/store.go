package notes

import (
	"context"
	"time"

	jet "github.com/go-jet/jet/v2/postgres"
	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/dbgen/postgres/model"
	"github.com/PuckxPuck/keel/internal/dbgen/postgres/table"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/files"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/occ"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

var notesTable = table.Notes

var byID = paging.Key[model.Notes]{Column: notesTable.ID, Value: func(r model.Notes) any { return r.ID }}

// sorts are the list's allowed sorts; the migration has an index for each.
var sorts = paging.Sorts[model.Notes]{
	"title":     {{Column: notesTable.Title, Value: func(r model.Notes) any { return r.Title }}, byID},
	"createdAt": {{Column: notesTable.CreatedAt, Value: func(r model.Notes) any { return r.CreatedAt }}, byID},
	"updatedAt": {{Column: notesTable.UpdatedAt, Value: func(r model.Notes) any { return r.UpdatedAt }}, byID},
}

const defaultSort = "-updatedAt"

// changed moves a row to the writing transaction's place in the change feed; every update sets it.
var changed = jet.Raw("pg_current_xact_id()")

func insert(ctx context.Context, tx db.Tx[db.Tenant], n Note) error {
	_, err := notesTable.INSERT(db.Insertable(notesTable.AllColumns)).MODEL(toModel(n)).ExecContext(ctx, tx.Q())
	return err
}

func get(ctx context.Context, tx db.Tx[db.Tenant], id ID, forUpdate bool) (Note, error) {
	stmt := jet.SELECT(notesTable.AllColumns).FROM(notesTable).WHERE(notesTable.ID.EQ(id.Param()))
	if forUpdate {
		stmt = stmt.FOR(jet.UPDATE())
	}
	return one(ctx, tx, stmt)
}

func byClientID(ctx context.Context, tx db.Tx[db.Tenant], clientID uuid.UUID) (Note, error) {
	return one(ctx, tx, jet.SELECT(notesTable.AllColumns).FROM(notesTable).WHERE(notesTable.ClientID.EQ(jet.UUID(clientID))))
}

func one(ctx context.Context, tx db.Tx[db.Tenant], stmt jet.SelectStatement) (Note, error) {
	var m model.Notes
	if err := stmt.QueryContext(ctx, tx.Q(), &m); err != nil {
		return Note{}, db.NotFoundOr(err, ErrNotFound)
	}
	return fromModel(m), nil
}

func (f Filter) where() jet.BoolExpression {
	where := jet.Bool(true)
	if f.Status != "" {
		where = where.AND(notesTable.Status.EQ(jet.String(string(f.Status))))
	}
	if f.Query != "" {
		pattern := "%" + db.LikeEscape(f.Query) + "%"
		where = where.AND(jet.LOWER(notesTable.Title).LIKE(jet.LOWER(jet.String(pattern))))
	}
	return where
}

func list(ctx context.Context, tx db.Tx[db.Tenant], cursors *paging.Keyset, f Filter, p paging.Request) (paging.Page[Note], error) {
	sort, err := sorts.Resolve(p.Sort, defaultSort)
	if err != nil {
		return paging.Page[Note]{}, err
	}
	after, err := cursors.After(p.Cursor, sort, f)
	if err != nil {
		return paging.Page[Note]{}, err
	}
	stmt := jet.SELECT(notesTable.AllColumns).
		FROM(notesTable).
		WHERE(f.where().AND(after)).
		ORDER_BY(sort.OrderBy()...).
		LIMIT(int64(p.Limit + 1))
	var rows []model.Notes
	if err := stmt.QueryContext(ctx, tx.Q(), &rows); err != nil {
		return paging.Page[Note]{}, err
	}
	return paging.Trim(rows, p.Limit, sort, f, cursors, fromModel)
}

// changes reads the feed after since: rows in the window, merged with the deletes' tombstones.
func changes(ctx context.Context, tx db.Tx[db.Tenant], feed *paging.Feed, since string, limit int) (paging.FeedPage[Note], error) {
	w, err := feed.Open(ctx, tx, since, nil)
	if err != nil {
		return paging.FeedPage[Note]{}, err
	}
	stmt := jet.SELECT(notesTable.AllColumns).
		FROM(notesTable).
		WHERE(w.Where(notesTable.ChangeXid, notesTable.ID)).
		ORDER_BY(w.OrderBy(notesTable.ChangeXid, notesTable.ID)...).
		LIMIT(int64(limit + 1))
	var rows []model.Notes
	if err := stmt.QueryContext(ctx, tx.Q(), &rows); err != nil {
		return paging.FeedPage[Note]{}, err
	}
	return paging.Changes(ctx, tx, w, rows, limit, func(m model.Notes) paging.Change {
		return paging.Change{ID: m.ID, Version: int64(m.Version), XID: m.ChangeXid}
	}, fromModel)
}

// update writes n over the row at version; a row at another version is an *occ.StaleError.
func update(ctx context.Context, tx db.Tx[db.Tenant], n Note, version int32) error {
	t, m := notesTable, toModel(n)
	res, err := t.UPDATE(t.Title, t.Body, t.Status, t.ArchivedAt, t.ArchivedBy, t.AttachmentID, t.AttachmentName,
		t.AttachmentMime, t.AttachmentSize, t.Version, t.UpdatedAt, t.UpdatedBy, t.ChangeXid).
		SET(m.Title, m.Body, m.Status, m.ArchivedAt, m.ArchivedBy, m.AttachmentID, m.AttachmentName,
			m.AttachmentMime, m.AttachmentSize, m.Version, m.UpdatedAt, m.UpdatedBy, changed).
		WHERE(t.ID.EQ(n.ID.Param()).AND(t.Version.EQ(jet.Int32(version)))).
		ExecContext(ctx, tx.Q())
	if err != nil {
		return err
	}
	return occ.Check(ctx, res, func(ctx context.Context) (occ.Current, error) {
		cur, err := get(ctx, tx, n.ID, true)
		return current(cur), err
	})
}

// setWordCount stores the index job's result. It does not move version, which belongs to the people
// editing the note.
func setWordCount(ctx context.Context, tx db.Tx[db.Tenant], id ID, words int) error {
	t := notesTable
	_, err := t.UPDATE(t.WordCount, t.ChangeXid).
		SET(int32(min(words, maxBody)), changed). //nolint:gosec // a body has at most maxBody characters, so fewer words
		WHERE(t.ID.EQ(id.Param())).
		ExecContext(ctx, tx.Q())
	return err
}

func remove(ctx context.Context, tx db.Tx[db.Tenant], id ID) error {
	_, err := notesTable.DELETE().WHERE(notesTable.ID.EQ(id.Param())).ExecContext(ctx, tx.Q())
	return err
}

func current(n Note) occ.Current {
	return occ.Current{Version: int(n.Version), ChangedBy: userUUID(n.UpdatedBy), ChangedAt: n.UpdatedAt}
}

func toModel(n Note) model.Notes {
	m := model.Notes{
		ID: n.ID.UUID(), ClientID: n.ClientID, Title: n.Title, Body: n.Body, Status: string(n.Status),
		ArchivedAt: n.ArchivedAt, ArchivedBy: userUUID(n.ArchivedBy), Version: n.Version,
		CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt, CreatedBy: userUUID(n.CreatedBy), UpdatedBy: userUUID(n.UpdatedBy),
	}
	if a := n.Attachment; a != nil {
		id := a.FileID.UUID()
		m.AttachmentID, m.AttachmentName, m.AttachmentMime, m.AttachmentSize = &id, &a.Name, &a.Mime, &a.Size
	}
	return m
}

func fromModel(m model.Notes) Note {
	n := Note{
		ID: ids.FromUUID[noteTag](m.ID), ClientID: m.ClientID, Title: m.Title, Body: m.Body, Status: Status(m.Status),
		ArchivedAt: utc(m.ArchivedAt), ArchivedBy: userID(m.ArchivedBy), Version: m.Version,
		CreatedAt: m.CreatedAt.UTC(), UpdatedAt: m.UpdatedAt.UTC(), CreatedBy: userID(m.CreatedBy), UpdatedBy: userID(m.UpdatedBy),
	}
	if m.WordCount != nil {
		words := int(*m.WordCount)
		n.WordCount = &words
	}
	if m.AttachmentID != nil && m.AttachmentName != nil && m.AttachmentMime != nil && m.AttachmentSize != nil {
		n.Attachment = &Attachment{
			FileID: files.ID(*m.AttachmentID), Name: *m.AttachmentName, Mime: *m.AttachmentMime, Size: *m.AttachmentSize,
		}
	}
	return n
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func userUUID(id *users.ID) *uuid.UUID {
	if id == nil {
		return nil
	}
	u := id.UUID()
	return &u
}

func userID(u *uuid.UUID) *users.ID {
	if u == nil {
		return nil
	}
	id := users.ID(*u)
	return &id
}

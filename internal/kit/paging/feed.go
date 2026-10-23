package paging

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-jet/jet/v2/postgres"
	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
)

var ErrResyncRequired = &Error{Code: "resync_required", Detail: "the sync token is older than the kept change history; start a full sync"}

// Mapper answers ErrResyncRequired with 410 and every other refused cursor, sort or token with 400.
func Mapper(err error) (*problem.Problem, bool) {
	var e *Error
	if !errors.As(err, &e) {
		return nil, false
	}
	if e == ErrResyncRequired {
		return problem.New(http.StatusGone, e.Code, e.Detail), true
	}
	return problem.New(http.StatusBadRequest, e.Code, e.Detail), true
}

const (
	defaultLag   = 2 * time.Minute
	maxTokenSize = 1024
	feedDomain   = "keel-feed-v1\x00"
)

// mysqlEpoch is the position before every row on MySQL.
var mysqlEpoch = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

type FeedOptions struct {
	// Entity names the table in tombstones.
	Entity string
	// Retention is how long tombstones are kept (PruneTombstones); an older token gets ErrResyncRequired.
	Retention time.Duration
	// Lag must exceed the longest transaction (plus clock skew between app and database). MySQL reads stop
	// this far behind the database clock, and on both engines a caught-up token's retention runs from
	// this far back, so a tombstone still in flight when the token was made is never pruned before the
	// client can receive it.
	Lag time.Duration
}

// Feed reads one table's changes in commit-safe order: on Postgres by change_xid below the snapshot's
// xmin, on MySQL by changed_at up to now minus the lag. Tokens are signed by the keyset's keys.
type Feed struct {
	keyset *Keyset
	opts   FeedOptions
}

func NewFeed(k *Keyset, opts FeedOptions) (*Feed, error) {
	if k == nil {
		return nil, errors.New("paging: a feed needs a keyset")
	}
	if opts.Entity == "" || len(opts.Entity) > 64 {
		return nil, errors.New("paging: feed entity must be 1 to 64 characters")
	}
	if opts.Retention <= 0 {
		return nil, errors.New("paging: feed retention must be positive")
	}
	if opts.Lag <= 0 {
		opts.Lag = defaultLag
	}
	return &Feed{keyset: k, opts: opts}, nil
}

// feedToken is where a client is in the feed. Since is the oldest delete the client may still be owed:
// tombstones pruned after it may never have reached the client.
type feedToken struct {
	Tenant string `json:"n,omitempty"`
	Entity string `json:"e"`
	Filter string `json:"f"`
	XID    uint64 `json:"x,omitempty"`
	At     string `json:"t,omitempty"`
	ID     string `json:"i"`
	Del    bool   `json:"d,omitempty"`
	Since  int64  `json:"s"`
}

// position orders the feed totally: change position, id, then a tombstone before an upsert, since a row
// deleted and created again in one transaction shares its tombstone's position and outlives it.
type position struct {
	xid uint64
	at  time.Time
	id  uuid.UUID
	del bool
}

func (p position) less(o position, dialect db.Dialect) bool {
	if dialect == db.Postgres {
		if p.xid != o.xid {
			return p.xid < o.xid
		}
	} else if !p.at.Equal(o.at) {
		return p.at.Before(o.at)
	}
	if c := strings.Compare(p.id.String(), o.id.String()); c != 0 {
		return c < 0
	}
	return p.del && !o.del
}

// Window is one read of a feed: changes after the token and below the watermark taken when it opened.
type Window struct {
	tenant  string
	feed    *Feed
	dialect db.Dialect
	filter  string
	after   position
	since   int64
	opened  time.Time
	xmin    uint64
	until   time.Time
}

// Open verifies token (empty starts a full sync) against this feed and filter, and takes the watermark in tx.
func (f *Feed) Open(ctx context.Context, tx db.Transaction, token string, filter any) (*Window, error) {
	hash, err := filterHash(filter)
	if err != nil {
		return nil, err
	}
	now := clock.Wall(ctx).Now()
	w := &Window{feed: f, dialect: tx.Dialect(), filter: hash, opened: now, since: now.Add(-f.opts.Lag).Unix(), after: position{at: mysqlEpoch}}
	if id, ok := db.TenantOf(ctx); ok {
		w.tenant = id.String()
	}
	if token != "" {
		t, err := f.decode(token)
		if err != nil {
			return nil, err
		}
		if t.Entity != f.opts.Entity || t.Filter != hash || t.Tenant != w.tenant {
			return nil, ErrCursorMismatch
		}
		if now.Sub(time.Unix(t.Since, 0)) > f.opts.Retention {
			return nil, ErrResyncRequired
		}
		if w.after, err = t.position(w.dialect); err != nil {
			return nil, err
		}
		w.since = t.Since
	}
	if err := w.watermark(ctx, tx); err != nil {
		return nil, err
	}
	return w, nil
}

func (t feedToken) position(dialect db.Dialect) (position, error) {
	id, err := uuid.Parse(t.ID)
	if err != nil {
		return position{}, ErrCursorInvalid
	}
	p := position{xid: t.XID, id: id, at: mysqlEpoch, del: t.Del}
	if dialect == db.MySQL {
		if p.at, err = time.Parse(time.RFC3339Nano, t.At); err != nil {
			return position{}, ErrCursorInvalid
		}
	}
	return p, nil
}

func (w *Window) watermark(ctx context.Context, tx db.Transaction) error {
	q, args := "SELECT pg_snapshot_xmin(pg_current_snapshot())::text", []any(nil)
	if w.dialect == db.MySQL {
		q, args = "SELECT DATE_SUB(NOW(6), INTERVAL ? MICROSECOND)", []any{w.feed.opts.Lag.Microseconds()}
	}
	rows, err := tx.Q().QueryContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("paging: feed watermark: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return errors.Join(rows.Err(), errors.New("paging: feed watermark: no row"))
	}
	if w.dialect == db.MySQL {
		err = rows.Scan(&w.until)
	} else {
		var xmin string
		if err = rows.Scan(&xmin); err == nil {
			w.xmin, err = strconv.ParseUint(xmin, 10, 64)
		}
	}
	if err != nil {
		return fmt.Errorf("paging: feed watermark: %w", err)
	}
	return rows.Err()
}

// Where selects the rows of this window; pos is change_xid on Postgres and changed_at on MySQL. A row at
// the token's own position is still due when the token ends on that row's tombstone.
func (w *Window) Where(pos, id postgres.Column) postgres.BoolExpression {
	idArg := postgres.Raw("#i", postgres.RawArgs{"#i": w.after.id})
	if w.dialect == db.Postgres {
		after := postgres.ROW(postgres.Raw("CAST(#x AS xid8)", postgres.RawArgs{"#x": strconv.FormatUint(w.after.xid, 10)}), idArg)
		bound := postgres.Raw("CAST(#b AS xid8)", postgres.RawArgs{"#b": strconv.FormatUint(w.xmin, 10)})
		from := postgres.ROW(pos, id).GT(after)
		if w.after.del {
			from = postgres.ROW(pos, id).GT_EQ(after)
		}
		return postgres.AND(from, postgres.BoolExp(postgres.CustomExpression(pos, postgres.Token(" < "), bound)))
	}
	at := postgres.Raw("#t", postgres.RawArgs{"#t": w.after.at})
	until := postgres.Raw("#u", postgres.RawArgs{"#u": w.until})
	idOp := " > "
	if w.after.del {
		idOp = " >= "
	}
	return postgres.AND(
		postgres.OR(
			postgres.BoolExp(postgres.CustomExpression(pos, postgres.Token(" > "), at)),
			postgres.AND(
				postgres.BoolExp(postgres.CustomExpression(pos, postgres.Token(" = "), at)),
				postgres.BoolExp(postgres.CustomExpression(id, postgres.Token(idOp), idArg)),
			),
		),
		postgres.BoolExp(postgres.CustomExpression(pos, postgres.Token(" <= "), until)),
	)
}

// OrderBy is the order rows must be read in, with LIMIT limit+1.
func (w *Window) OrderBy(pos, id postgres.Column) []postgres.OrderByClause {
	return []postgres.OrderByClause{pos.ASC(), id.ASC()}
}

// Change is where a row sits in the feed. Set XID on Postgres (the change_xid column, which Jet reads as a
// string) and ChangedAt on MySQL.
type Change struct {
	ID        uuid.UUID
	Version   int64
	XID       string
	ChangedAt time.Time
}

// FeedPage is one page of changes in order; Next is the token to store once the page is applied.
type FeedPage[R any] struct {
	Entries []httpx.FeedEntry[R]
	Next    string
	HasMore bool
}

func (p FeedPage[R]) Body(limit int) httpx.FeedBody[R] {
	return httpx.FeedBody[R]{Data: p.Entries, Meta: httpx.FeedMeta{Limit: limit, HasMore: p.HasMore}, Links: httpx.FeedLinks{Next: p.Next}}
}

type feedItem[R any] struct {
	pos   position
	entry httpx.FeedEntry[R]
}

// Changes merges the rows a store read through the window (limit+1, in OrderBy order) with the window's
// tombstones into one page.
func Changes[T, R any](ctx context.Context, tx db.Transaction, w *Window, rows []T, limit int, change func(T) Change, conv func(T) R) (FeedPage[R], error) {
	if limit < 1 {
		return FeedPage[R]{}, errors.New("paging: feed limit must be at least 1")
	}
	ups := make([]feedItem[R], 0, len(rows))
	for _, r := range rows {
		c := change(r)
		p := position{id: c.ID, at: c.ChangedAt.UTC()}
		if w.dialect == db.Postgres {
			xid, err := strconv.ParseUint(c.XID, 10, 64)
			if err != nil {
				return FeedPage[R]{}, fmt.Errorf("paging: feed row %s has no change_xid", c.ID)
			}
			p.xid = xid
		}
		rec := conv(r)
		ups = append(ups, feedItem[R]{pos: p, entry: httpx.FeedEntry[R]{Op: httpx.FeedUpsert, ID: c.ID.String(), Version: c.Version, Record: &rec}})
	}
	dels, err := tombstonesIn[R](ctx, tx, w, limit+1)
	if err != nil {
		return FeedPage[R]{}, err
	}
	merged := make([]feedItem[R], 0, min(len(ups)+len(dels), limit+1))
	for i, j := 0, 0; (i < len(ups) || j < len(dels)) && len(merged) <= limit; {
		if j >= len(dels) || (i < len(ups) && ups[i].pos.less(dels[j].pos, w.dialect)) {
			merged = append(merged, ups[i])
			i++
		} else {
			merged = append(merged, dels[j])
			j++
		}
	}
	page := FeedPage[R]{HasMore: len(merged) > limit}
	if page.HasMore {
		merged = merged[:limit]
	}
	last, since := w.after, w.opened.Add(-w.feed.opts.Lag).Unix()
	if page.HasMore {
		since = w.since
	}
	page.Entries = make([]httpx.FeedEntry[R], len(merged))
	for i, m := range merged {
		page.Entries[i] = m.entry
		last = m.pos
	}
	if page.Next, err = w.feed.encode(w.dialect, feedToken{Tenant: w.tenant, Entity: w.feed.opts.Entity, Filter: w.filter, Since: since}, last); err != nil {
		return FeedPage[R]{}, err
	}
	return page, nil
}

func tombstonesIn[R any](ctx context.Context, tx db.Transaction, w *Window, n int) ([]feedItem[R], error) {
	q := `SELECT id, change_xid::text FROM tombstones WHERE entity = ? AND (change_xid, id) > (CAST(? AS xid8), ?)
		AND change_xid < CAST(? AS xid8) ORDER BY change_xid, id LIMIT ?`
	args := []any{w.feed.opts.Entity, strconv.FormatUint(w.after.xid, 10), w.after.id, strconv.FormatUint(w.xmin, 10), n}
	if w.dialect == db.MySQL {
		q = `SELECT id, changed_at FROM tombstones WHERE entity = ? AND (changed_at > ? OR (changed_at = ? AND id > ?))
			AND changed_at <= ? ORDER BY changed_at, id LIMIT ?`
		args = []any{w.feed.opts.Entity, w.after.at, w.after.at, w.after.id, w.until, n}
	}
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(w.dialect, q), args...)
	if err != nil {
		return nil, fmt.Errorf("paging: tombstones: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []feedItem[R]
	for rows.Next() {
		var p position
		if w.dialect == db.MySQL {
			err = rows.Scan(&p.id, &p.at)
		} else {
			var xid string
			if err = rows.Scan(&p.id, &xid); err == nil {
				p.xid, err = strconv.ParseUint(xid, 10, 64)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("paging: tombstones: %w", err)
		}
		p.at, p.del = p.at.UTC(), true
		out = append(out, feedItem[R]{pos: p, entry: httpx.FeedEntry[R]{Op: httpx.FeedDelete, ID: p.id.String()}})
	}
	return out, rows.Err()
}

func (f *Feed) encode(dialect db.Dialect, t feedToken, p position) (string, error) {
	t.ID, t.Del = p.id.String(), p.del
	if dialect == db.MySQL {
		t.At = p.at.UTC().Format(time.RFC3339Nano)
	} else {
		t.XID = p.xid
	}
	payload, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("paging: encode feed token: %w", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(sign(f.keyset.keys[0], append([]byte(feedDomain), payload...))), nil
}

func (f *Feed) decode(token string) (feedToken, error) {
	if len(token) > maxTokenSize {
		return feedToken{}, ErrCursorInvalid
	}
	body, mac, ok := strings.Cut(token, ".")
	if !ok {
		return feedToken{}, ErrCursorInvalid
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(body)
	if err != nil {
		return feedToken{}, ErrCursorInvalid
	}
	sig, err := enc.DecodeString(mac)
	if err != nil {
		return feedToken{}, ErrCursorInvalid
	}
	signed := append([]byte(feedDomain), payload...)
	for _, key := range f.keyset.keys {
		if hmac.Equal(sig, sign(key, signed)) {
			var t feedToken
			if err := json.Unmarshal(payload, &t); err != nil {
				return feedToken{}, ErrCursorInvalid
			}
			return t, nil
		}
	}
	return feedToken{}, ErrCursorInvalid
}

// Tombstone records that entity row id was deleted; call it in the transaction that deletes the row.
func Tombstone(ctx context.Context, tx db.Transaction, entity string, id uuid.UUID) error {
	q := `INSERT INTO tombstones (entity, id, deleted_at) VALUES (?, ?, ?)
		ON CONFLICT ON CONSTRAINT tombstones_pkey DO UPDATE SET change_xid = pg_current_xact_id(), deleted_at = excluded.deleted_at`
	now := clock.Wall(ctx).Now().UTC()
	args := []any{entity, id, now}
	if tx.Dialect() == db.MySQL {
		q = `INSERT INTO tombstones (entity, id, changed_at, deleted_at) VALUES (?, ?, NOW(6), ?)
			ON DUPLICATE KEY UPDATE changed_at = NOW(6), deleted_at = ?`
		args = append(args, now)
	}
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), args...); err != nil {
		return fmt.Errorf("paging: tombstone: %w", err)
	}
	return nil
}

// PruneTombstones deletes up to limit tombstones recorded before before and reports how many; the
// retention job passes now minus the feed's Retention and calls it in fresh transactions until it
// returns fewer than limit, on the operator pool under tenancy.
func PruneTombstones(ctx context.Context, tx db.Transaction, before time.Time, limit int) (int64, error) {
	q := "DELETE FROM tombstones WHERE (entity, id) IN (SELECT entity, id FROM tombstones WHERE deleted_at < ? LIMIT ?)"
	if tx.Tenancy() {
		q = "DELETE FROM tombstones WHERE (tenant_id, entity, id) IN (SELECT tenant_id, entity, id FROM tombstones WHERE deleted_at < ? LIMIT ?)"
	}
	if tx.Dialect() == db.MySQL {
		q = "DELETE FROM tombstones WHERE deleted_at < ? ORDER BY deleted_at LIMIT ?"
	}
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), before.UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("paging: prune tombstones: %w", err)
	}
	return res.RowsAffected()
}

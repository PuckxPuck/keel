package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/db"
)

type row struct {
	tenancy    bool
	tenant     *uuid.UUID
	id         uuid.UUID
	occurredAt time.Time
	realm      *string
	actorType  ActorType
	actorID    *uuid.UUID
	onBehalfOf *uuid.UUID
	action     string
	entity     string
	entityID   string
	before     *string
	after      *string
	ip         *string
	requestID  *string
	prevHash   []byte
	hash       []byte
}

// columns quotes before and after: BEFORE is reserved on MySQL.
var columns = map[db.Dialect]string{
	db.Postgres: "id, occurred_at, realm, actor_type, actor_id, on_behalf_of, action, entity, entity_id, before, after, ip, request_id, prev_hash, hash",
	db.MySQL:    "id, occurred_at, realm, actor_type, actor_id, on_behalf_of, action, entity, entity_id, `before`, `after`, ip, request_id, prev_hash, hash",
}

func insert(ctx context.Context, tx db.Transaction, r row) error {
	cols, marks := columns[tx.Dialect()], "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?"
	args := []any{
		r.id, r.occurredAt, r.realm, string(r.actorType), r.actorID, r.onBehalfOf,
		r.action, r.entity, r.entityID, r.before, r.after, r.ip, r.requestID, r.prevHash, r.hash,
	}
	// Written, not left to the column default, so an operator transaction (no tenant set) records the
	// tenant it acted on; in a tenant transaction the policy refuses any other value.
	if r.tenancy {
		cols, marks, args = cols+", tenant_id", marks+", ?", append(args, r.tenant)
	}
	_, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "INSERT INTO audit_log ("+cols+") VALUES ("+marks+")"), args...)
	if err != nil {
		return fmt.Errorf("audit %s: %w", r.action, err)
	}
	return nil
}

// lockHead returns the chain's last hash, creating the head row on first use, and locks it until tx
// ends. The locking read sees the latest commit whatever snapshot tx holds, so the chain cannot fork.
func lockHead(ctx context.Context, tx db.Transaction, chain string, r row) ([]byte, error) {
	create, args := "INSERT INTO audit_chain (chain_key) VALUES (?) ON CONFLICT (chain_key) DO NOTHING", []any{chain}
	switch {
	case tx.Dialect() == db.MySQL:
		create = "INSERT INTO audit_chain (chain_key) VALUES (?) ON DUPLICATE KEY UPDATE chain_key = chain_key"
	case r.tenancy:
		// As in insert: an operator transaction names the tenant whose head it creates.
		create, args = "INSERT INTO audit_chain (chain_key, tenant_id) VALUES (?, ?) ON CONFLICT (chain_key) DO NOTHING", append(args, r.tenant)
	}
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), create), args...); err != nil {
		return nil, fmt.Errorf("audit chain: %w", err)
	}
	var h []byte
	q := db.Rebind(tx.Dialect(), "SELECT hash FROM audit_chain WHERE chain_key = ? FOR UPDATE")
	if err := scanOne(ctx, tx, q, []any{chain}, &h); err != nil {
		return nil, fmt.Errorf("audit chain: %w", err)
	}
	return h, nil
}

func moveHead(ctx context.Context, tx db.Transaction, chain string, r row) error {
	q := db.Rebind(tx.Dialect(), "UPDATE audit_chain SET last_id = ?, hash = ? WHERE chain_key = ?")
	if _, err := tx.Q().ExecContext(ctx, q, r.id, r.hash, chain); err != nil {
		return fmt.Errorf("audit chain: %w", err)
	}
	return nil
}

func scanOne(ctx context.Context, tx db.Transaction, q string, args []any, dest ...any) error {
	rows, err := tx.Q().QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return sql.ErrNoRows
	}
	if err := rows.Scan(dest...); err != nil {
		return err
	}
	return rows.Err()
}

type chainForm struct {
	TenantID   *uuid.UUID      `json:"tenantId,omitempty"`
	ID         string          `json:"id"`
	OccurredAt string          `json:"occurredAt"`
	Realm      *string         `json:"realm"`
	ActorType  ActorType       `json:"actorType"`
	ActorID    *uuid.UUID      `json:"actorId"`
	OnBehalfOf *uuid.UUID      `json:"onBehalfOf"`
	Action     string          `json:"action"`
	Entity     string          `json:"entity"`
	EntityID   string          `json:"entityId"`
	Before     json.RawMessage `json:"before"`
	After      json.RawMessage `json:"after"`
	IP         *string         `json:"ip"`
	RequestID  *string         `json:"requestId"`
}

// chainHash is SHA-256 over the previous row's hash and this row's canonical JSON.
func (r row) chainHash() ([]byte, error) {
	form := chainForm{
		TenantID: r.tenant, ID: r.id.String(), OccurredAt: r.occurredAt.UTC().Format(time.RFC3339Nano), Realm: r.realm,
		ActorType: r.actorType, ActorID: r.actorID, OnBehalfOf: r.onBehalfOf,
		Action: r.action, Entity: r.entity, EntityID: r.entityID, IP: r.ip, RequestID: r.requestID,
	}
	var err error
	if form.Before, err = canonicalRaw(r.before); err != nil {
		return nil, err
	}
	if form.After, err = canonicalRaw(r.after); err != nil {
		return nil, err
	}
	body, err := json.Marshal(form)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(r.prevHash)
	h.Write(body)
	return h.Sum(nil), nil
}

func canonicalRaw(s *string) (json.RawMessage, error) {
	if s == nil {
		return json.RawMessage("null"), nil
	}
	c, err := canonical([]byte(*s))
	return json.RawMessage(c), err
}

var ErrChainBroken = errors.New("audit: hash chain broken")

// Report is what Verify found. Unchained rows (no hashes) are counted, not judged: rows written with the
// chain off look the same as rows inserted around the recorder, so a non-zero count needs explaining.
type Report struct {
	Chained   int
	Unchained int
	Breaks    []Break
}

type Break struct {
	Seq    int64
	ID     uuid.UUID
	Reason string
}

// Verify walks one chain in order and reports every break, then checks that the last chained row is
// the one the chain head names, which catches a deleted tail unless the head was rewritten too. Under
// tenancy the chain is the context's tenant's (the rows without a tenant when there is none); run it on
// the operator pool for the rows without a tenant. The chain has no key: whoever can write audit_log
// and audit_chain directly can recompute every hash.
func Verify(ctx context.Context, tx db.Transaction) (Report, error) {
	var rep Report
	var head struct {
		id   sql.Null[uuid.UUID]
		hash []byte
	}
	var tenant *uuid.UUID
	if id, ok := db.TenantOf(ctx); ok && tx.Tenancy() {
		tenant = &id
	}
	err := scanOne(ctx, tx, db.Rebind(tx.Dialect(), "SELECT last_id, hash FROM audit_chain WHERE chain_key = ?"), []any{chainKey(tenant)}, &head.id, &head.hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return rep, fmt.Errorf("audit verify: %w", err)
	}
	cols := "seq, id, occurred_at, realm, actor_type, actor_id, on_behalf_of, action, entity, entity_id, before::text, after::text, ip, request_id, prev_hash, hash"
	if tx.Dialect() == db.MySQL {
		cols = "seq, " + columns[db.MySQL]
	}
	where, args := "", []any(nil)
	if tx.Tenancy() {
		cols += ", tenant_id"
		where, args = " WHERE tenant_id IS NULL", nil
		if tenant != nil {
			where, args = " WHERE tenant_id = ?", []any{*tenant}
		}
	}
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), "SELECT "+cols+" FROM audit_log"+where+" ORDER BY seq"), args...)
	if err != nil {
		return rep, fmt.Errorf("audit verify: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var prev []byte
	var last uuid.UUID
	for rows.Next() {
		var seq int64
		r, err := scanRow(rows, &seq, tx.Tenancy())
		if err != nil {
			return rep, err
		}
		brk := func(reason string) { rep.Breaks = append(rep.Breaks, Break{Seq: seq, ID: r.id, Reason: reason}) }
		switch {
		case r.hash == nil && r.prevHash == nil:
			rep.Unchained++
			continue
		case r.hash == nil:
			brk("the row has a previous hash but no hash")
			continue
		}
		rep.Chained++
		want, err := r.chainHash()
		if err != nil {
			return rep, err
		}
		if !bytes.Equal(r.prevHash, prev) {
			brk("the previous hash does not match the row before")
		}
		if !bytes.Equal(r.hash, want) {
			brk("the hash does not match the row")
		}
		prev, last = r.hash, r.id
	}
	if err := rows.Err(); err != nil {
		return rep, err
	}
	if rep.Chained > 0 && (!head.id.Valid || head.id.V != last || !bytes.Equal(head.hash, prev)) {
		rep.Breaks = append(rep.Breaks, Break{ID: last, Reason: "the chain head does not name the last chained row"})
	}
	if rep.Chained == 0 && head.id.Valid {
		rep.Breaks = append(rep.Breaks, Break{ID: head.id.V, Reason: "the chain head names a row that is gone"})
	}
	if len(rep.Breaks) > 0 {
		return rep, fmt.Errorf("%w: %d breaks", ErrChainBroken, len(rep.Breaks))
	}
	return rep, nil
}

func scanRow(rows *sql.Rows, seq *int64, tenancy bool) (row, error) {
	var (
		r                                   row
		actorType                           string
		realm, before, after, ip, requestID sql.NullString
		actorID, onBehalfOf, tenant         sql.NullString
	)
	dest := []any{
		seq, &r.id, &r.occurredAt, &realm, &actorType, &actorID, &onBehalfOf, &r.action, &r.entity, &r.entityID,
		&before, &after, &ip, &requestID, &r.prevHash, &r.hash,
	}
	if tenancy {
		dest = append(dest, &tenant)
	}
	if err := rows.Scan(dest...); err != nil {
		return row{}, err
	}
	r.tenancy = tenancy
	r.actorType = ActorType(actorType)
	r.realm, r.before, r.after, r.ip, r.requestID = nullable(realm), nullable(before), nullable(after), nullable(ip), nullable(requestID)
	var err error
	if r.actorID, err = nullableUUID(actorID); err != nil {
		return row{}, err
	}
	if r.onBehalfOf, err = nullableUUID(onBehalfOf); err != nil {
		return row{}, err
	}
	if r.tenant, err = nullableUUID(tenant); err != nil {
		return row{}, err
	}
	return r, nil
}

func nullable(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	return &s.String
}

func nullableUUID(s sql.NullString) (*uuid.UUID, error) {
	if !s.Valid {
		return nil, nil
	}
	u, err := uuid.Parse(s.String)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// Entry is one audit row as a reader sees it.
type Entry struct {
	Seq        int64           `json:"seq"`
	ID         uuid.UUID       `json:"id"`
	OccurredAt time.Time       `json:"occurredAt"`
	Realm      *string         `json:"realm,omitempty"`
	ActorType  ActorType       `json:"actorType"`
	ActorID    *uuid.UUID      `json:"actorId,omitempty"`
	OnBehalfOf *uuid.UUID      `json:"onBehalfOf,omitempty"`
	Action     string          `json:"action"`
	Entity     string          `json:"entity"`
	EntityID   string          `json:"entityId"`
	Before     json.RawMessage `json:"before,omitempty"`
	After      json.RawMessage `json:"after,omitempty"`
	IP         *string         `json:"ip,omitempty"`
	RequestID  *string         `json:"requestId,omitempty"`
}

// List reads the newest rows first, those with seq below before when before is positive. Under tenancy
// it reads the context's tenant's rows, so an operator transaction reads one tenant's trail.
func List(ctx context.Context, tx db.Transaction, before int64, limit int) ([]Entry, error) {
	cols := "seq, id, occurred_at, realm, actor_type, actor_id, on_behalf_of, action, entity, entity_id, before::text, after::text, ip, request_id, prev_hash, hash"
	if tx.Dialect() == db.MySQL {
		cols = "seq, " + columns[db.MySQL]
	}
	where, args := "WHERE 1 = 1", []any{}
	if tx.Tenancy() {
		id, ok := db.TenantOf(ctx)
		if !ok {
			return nil, errors.New("audit: listing under tenancy needs a tenant in the context")
		}
		where, args = "WHERE tenant_id = ?", append(args, id)
	}
	if before > 0 {
		where, args = where+" AND seq < ?", append(args, before)
	}
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), "SELECT "+cols+" FROM audit_log "+where+" ORDER BY seq DESC LIMIT ?"), append(args, limit)...)
	if err != nil {
		return nil, fmt.Errorf("audit list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Entry
	for rows.Next() {
		var seq int64
		r, err := scanRow(rows, &seq, false)
		if err != nil {
			return nil, err
		}
		e := Entry{
			Seq: seq, ID: r.id, OccurredAt: r.occurredAt.UTC(), Realm: r.realm, ActorType: r.actorType, ActorID: r.actorID,
			OnBehalfOf: r.onBehalfOf, Action: r.action, Entity: r.entity, EntityID: r.entityID, IP: r.ip, RequestID: r.requestID,
		}
		if r.before != nil {
			e.Before = json.RawMessage(*r.before)
		}
		if r.after != nil {
			e.After = json.RawMessage(*r.after)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

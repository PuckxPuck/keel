// Package idempotency makes operations marked Required at most once per Idempotency-Key and caller.
package idempotency

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
)

const (
	statusInProgress = "in_progress"
	statusDone       = "done"
	statusUnknown    = "unknown"
)

type Store struct {
	db *db.DB
}

func NewStore(d *db.DB) *Store { return &Store{db: d} }

type idemID = uuid.UUID

// scope is whose key it is; under tenancy the row's tenant (from the transaction) joins its unique key.
type scope struct {
	realm, principal, key string
}

type record struct {
	id          idemID
	requestHash []byte
	status      string
	respStatus  int
	headers     map[string]string
	body        []byte
	bodyStored  bool
	leaseUntil  time.Time
}

// claim inserts an in-progress row for the key in its own short transaction, or returns the row
// already there. Only expired rows are cleared first: a claim is never taken over.
func (s *Store) claim(ctx context.Context, sc scope, hash []byte, now time.Time, cfg Config) (record, bool, error) {
	var rec record
	var claimed bool
	err := db.InAppTx(ctx, s.db, func(ctx context.Context, tx db.Transaction) error {
		q := db.Rebind(tx.Dialect(), "DELETE FROM idempotency_keys WHERE realm = ? AND principal = ? AND idem_key = ? AND expires_at < ?")
		if _, err := tx.Q().ExecContext(ctx, q, sc.realm, sc.principal, sc.key, now); err != nil {
			return err
		}
		id := ids.New()
		insert := `INSERT INTO idempotency_keys (id, realm, principal, idem_key, request_hash, status, created_at, lease_until, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`
		if tx.Dialect() == db.MySQL {
			insert = `INSERT INTO idempotency_keys (id, realm, principal, idem_key, request_hash, status, created_at, lease_until, expires_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE id = id`
		}
		res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), insert),
			id, sc.realm, sc.principal, sc.key, hash, statusInProgress, now, now.Add(cfg.Lease), now.Add(cfg.TTL))
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 1 {
			rec, claimed = record{id: id, requestHash: hash, status: statusInProgress}, true
			return err
		}
		rec, err = load(ctx, tx, sc)
		return err
	})
	if err != nil {
		return record{}, false, fmt.Errorf("idempotency claim: %w", err)
	}
	return rec, claimed, nil
}

var errVanished = errors.New("idempotency key vanished")

func load(ctx context.Context, tx db.Transaction, sc scope) (record, error) {
	q := db.Rebind(tx.Dialect(), `SELECT id, request_hash, status, response_status, response_headers, response_body, body_stored, lease_until
		FROM idempotency_keys WHERE realm = ? AND principal = ? AND idem_key = ?`)
	rows, err := tx.Q().QueryContext(ctx, q, sc.realm, sc.principal, sc.key)
	if err != nil {
		return record{}, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return record{}, err
		}
		return record{}, errVanished
	}
	var rec record
	var status *int
	var headers []byte
	if err := rows.Scan(&rec.id, &rec.requestHash, &rec.status, &status, &headers, &rec.body, &rec.bodyStored, &rec.leaseUntil); err != nil {
		return record{}, err
	}
	if status != nil {
		rec.respStatus = *status
	}
	if len(headers) > 0 {
		if err := json.Unmarshal(headers, &rec.headers); err != nil {
			return record{}, err
		}
	}
	return rec, rows.Err()
}

func (s *Store) finish(ctx context.Context, id idemID, status int, headers map[string]string, body []byte, stored bool) error {
	raw, err := json.Marshal(headers)
	if err != nil {
		return err
	}
	return s.settle(ctx, `UPDATE idempotency_keys SET status = ?, response_status = ?, response_headers = ?, response_body = ?, body_stored = ?
		WHERE id = ? AND status = ?`, statusDone, status, string(raw), body, stored, id, statusInProgress)
}

func (s *Store) markUnknown(ctx context.Context, id idemID) error {
	return s.settle(ctx, "UPDATE idempotency_keys SET status = ? WHERE id = ? AND status = ?", statusUnknown, id, statusInProgress)
}

func (s *Store) settle(ctx context.Context, q string, args ...any) error {
	return db.InAppTx(ctx, s.db, func(ctx context.Context, tx db.Transaction) error {
		res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), args...)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return errors.Join(err, errVanished)
		}
		return nil
	})
}

// Prune deletes keys that expired before before in tx; the jobs part schedules it, on the operator pool
// under tenancy so every tenant's keys go.
func Prune(ctx context.Context, tx db.Transaction, before time.Time) (int64, error) {
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM idempotency_keys WHERE expires_at < ?"), before.UTC())
	if err != nil {
		return 0, fmt.Errorf("prune idempotency keys: %w", err)
	}
	return res.RowsAffected()
}

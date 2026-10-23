package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/db"
)

type newJobRow struct {
	id          ID
	kind        string
	lane        string
	priority    int
	payload     string
	uniqueKey   string
	maxAttempts int
	runAt       time.Time
	now         time.Time
}

const (
	insertColumns = "id, kind, lane, priority, payload, unique_key, status, attempts, max_attempts, run_at, created_at, updated_at"
	insertValues  = "?, ?, ?, ?, ?, ?, 'queued', 0, ?, ?, ?, ?"
)

func insertJob(ctx context.Context, tx db.Transaction, r newJobRow) (ID, error) {
	var unique sql.NullString
	if r.uniqueKey != "" {
		unique = sql.NullString{String: r.uniqueKey, Valid: true}
	}
	args := []any{r.id, r.kind, r.lane, r.priority, r.payload, unique, r.maxAttempts, r.runAt, r.now, r.now}
	q := "INSERT INTO jobs (" + insertColumns + ") VALUES (" + insertValues + ")"
	twin, twinArgs := twinSQL[tx.Dialect()], []any{r.uniqueKey}
	// The tenant is written, not left to the column default, so an operator transaction (a fan-out over
	// tenants) can enqueue for the tenant in the context; in a tenant transaction the policy refuses any other.
	if tx.Tenancy() {
		tenant, ok := db.TenantOf(ctx)
		var value *uuid.UUID
		if ok {
			value = &tenant
		}
		q = "INSERT INTO jobs (" + insertColumns + ", tenant_id) VALUES (" + insertValues + ", ?)"
		args = append(args, value)
		twin, twinArgs = twin+" AND tenant_id IS NOT DISTINCT FROM ?", append(twinArgs, value)
	}
	if unique.Valid {
		switch tx.Dialect() {
		case db.Postgres:
			q += " ON CONFLICT DO NOTHING"
		case db.MySQL:
			q += " ON DUPLICATE KEY UPDATE id = id"
		}
	}
	// A unique job that finished between the conflict and the lookup leaves no open twin; insert again.
	for range 2 {
		res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), args...)
		if err != nil {
			return ID{}, fmt.Errorf("enqueue %s: %w", r.kind, err)
		}
		if n, err := res.RowsAffected(); err != nil || n == 1 || !unique.Valid {
			return r.id, err
		}
		var existing ID
		err = scanOne(ctx, tx, twin, twinArgs, &existing)
		if err == nil {
			return existing, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ID{}, fmt.Errorf("enqueue %s: find unique twin: %w", r.kind, err)
		}
	}
	return ID{}, fmt.Errorf("enqueue %s: unique key kept conflicting", r.kind)
}

// twinSQL finds the open job holding a unique key. On MySQL it is a locking read on the functional index,
// so a twin committed after the transaction's snapshot is still seen.
var twinSQL = map[db.Dialect]string{
	db.Postgres: "SELECT id FROM jobs WHERE unique_key = ? AND status IN ('queued', 'running')",
	db.MySQL:    "SELECT id FROM jobs WHERE (case when status in ('queued', 'running') then unique_key end) = ? FOR SHARE",
}

func scanOne(ctx context.Context, tx db.Transaction, query string, args []any, dest ...any) error {
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), query), args...)
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
	return rows.Close()
}

func exec(ctx context.Context, tx db.Transaction, query string, args ...any) (int64, error) {
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), query), args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

type claimed struct {
	tenancy bool
	// held is true for a job of a suspended tenant, which waits instead of running.
	held    bool
	job     Job
	lane    string
	token   string
	until   time.Time
	runAt   time.Time
	created time.Time
	claimed time.Time
}

// claim takes the lane's next ready job, ordered by priority then run_at, and leases it to a new token.
func claim(ctx context.Context, tx db.Transaction, lane, token string, now time.Time, lease time.Duration) (claimed, bool, error) {
	c := claimed{tenancy: tx.Tenancy(), lane: lane, token: token, until: now.Add(lease), claimed: now}
	var payload []byte
	cols, dest := "id, kind, payload, attempts, max_attempts, run_at, created_at",
		[]any{&c.job.ID, &c.job.Kind, &payload, &c.job.Attempt, &c.job.MaxAttempts, &c.runAt, &c.created}
	if c.tenancy {
		cols += ", tenant_id, coalesce((SELECT t.status = 'suspended' FROM tenants t WHERE t.id = jobs.tenant_id), false)"
		dest = append(dest, &c.job.Tenant, &c.held)
	}
	err := scanOne(ctx, tx, "SELECT "+cols+" FROM jobs "+
		"WHERE status = 'queued' AND lane = ? AND run_at <= ? ORDER BY priority DESC, run_at LIMIT 1 FOR UPDATE SKIP LOCKED",
		[]any{lane, now}, dest...)
	if errors.Is(err, sql.ErrNoRows) {
		return claimed{}, false, nil
	}
	if err != nil {
		return claimed{}, false, fmt.Errorf("claim: %w", err)
	}
	c.job.Payload = payload
	c.job.Attempt++
	_, err = exec(ctx, tx, "UPDATE jobs SET status = 'running', attempts = attempts + 1, locked_by = ?, locked_until = ?, updated_at = ? WHERE id = ?",
		token, c.until, now, c.job.ID)
	if err != nil {
		return claimed{}, false, fmt.Errorf("claim: %w", err)
	}
	return c, true, nil
}

// renew extends the lease while token still holds it; false means another worker or an operator took it.
func renew(ctx context.Context, tx db.Transaction, id ID, token string, until, now time.Time) (bool, error) {
	n, err := exec(ctx, tx, "UPDATE jobs SET locked_until = ?, updated_at = ? WHERE id = ? AND locked_by = ? AND status = 'running'",
		until, now, id, token)
	return n == 1, err
}

const fence = " WHERE id = ? AND locked_by = ? AND status = 'running'"

func markDone(ctx context.Context, tx db.Transaction, c claimed, now time.Time) (bool, error) {
	n, err := exec(ctx, tx, "UPDATE jobs SET status = 'done', locked_by = NULL, locked_until = NULL, last_error_code = NULL, last_error = NULL, "+
		"finished_at = ?, updated_at = ?"+fence, now, now, c.job.ID, c.token)
	return n == 1, err
}

func markRetry(ctx context.Context, tx db.Transaction, c claimed, runAt, now time.Time, code, msg string) (bool, error) {
	n, err := exec(ctx, tx, "UPDATE jobs SET status = 'queued', locked_by = NULL, locked_until = NULL, run_at = ?, last_error_code = ?, last_error = ?, "+
		"updated_at = ?"+fence, runAt, code, msg, now, c.job.ID, c.token)
	return n == 1, err
}

func markFailed(ctx context.Context, tx db.Transaction, c claimed, now time.Time, code, msg string) (bool, error) {
	n, err := exec(ctx, tx, "UPDATE jobs SET status = 'failed', locked_by = NULL, locked_until = NULL, last_error_code = ?, last_error = ?, "+
		"finished_at = ?, updated_at = ?"+fence, code, msg, now, now, c.job.ID, c.token)
	return n == 1, err
}

// markReleased gives the attempt back: the run never got a fair chance (shutdown, kind unknown here).
func markReleased(ctx context.Context, tx db.Transaction, c claimed, runAt, now time.Time) (bool, error) {
	n, err := exec(ctx, tx, "UPDATE jobs SET status = 'queued', attempts = attempts - 1, locked_by = NULL, locked_until = NULL, run_at = ?, "+
		"updated_at = ?"+fence, runAt, now, c.job.ID, c.token)
	return n == 1, err
}

const leaseExpired = "lease_expired"

const reapBatch = 100

type expiredJob struct {
	id                    ID
	kind                  string
	attempts, maxAttempts int
}

// reap returns jobs whose lease ran out (a worker died, lost the database or lost its lease) to the queue
// after the kind's backoff, or fails them when their attempts are spent.
func reap(ctx context.Context, tx db.Transaction, now time.Time, delay func(kind string, attempt int) time.Duration) (int64, error) {
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), "SELECT id, kind, attempts, max_attempts FROM jobs "+
		"WHERE status = 'running' AND locked_until < ? ORDER BY locked_until LIMIT ? FOR UPDATE SKIP LOCKED"), now, reapBatch)
	if err != nil {
		return 0, fmt.Errorf("reap: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []expiredJob
	for rows.Next() {
		var j expiredJob
		if err := rows.Scan(&j.id, &j.kind, &j.attempts, &j.maxAttempts); err != nil {
			return 0, fmt.Errorf("reap: %w", err)
		}
		list = append(list, j)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return 0, fmt.Errorf("reap: %w", err)
	}
	var n int64
	for _, j := range list {
		q, args := "UPDATE jobs SET status = 'failed', locked_by = NULL, locked_until = NULL, last_error_code = ?, "+
			"last_error = 'the lease expired', finished_at = ?, updated_at = ? WHERE id = ? AND status = 'running'",
			[]any{leaseExpired, now, now, j.id}
		if j.attempts < j.maxAttempts {
			q, args = "UPDATE jobs SET status = 'queued', locked_by = NULL, locked_until = NULL, run_at = ?, last_error_code = ?, "+
				"last_error = 'the lease expired', updated_at = ? WHERE id = ? AND status = 'running'",
				[]any{now.Add(delay(j.kind, j.attempts)), leaseExpired, now, j.id}
		}
		changed, err := exec(ctx, tx, q, args...)
		if err != nil {
			return n, fmt.Errorf("reap: %w", err)
		}
		n += changed
	}
	return n, nil
}

const pruneBatch = 1000

// deleteFinished deletes one batch of jobs in statuses that finished before before.
func deleteFinished(ctx context.Context, tx db.Transaction, statuses string, before time.Time) (int64, error) {
	q := "DELETE FROM jobs WHERE id IN (SELECT id FROM jobs WHERE status IN (" + statuses + ") AND finished_at < ? LIMIT ?)"
	if tx.Dialect() == db.MySQL {
		q = "DELETE FROM jobs WHERE status IN (" + statuses + ") AND finished_at < ? ORDER BY finished_at LIMIT ?"
	}
	return exec(ctx, tx, q, before, pruneBatch)
}

// clearPayloads empties one batch of finished payloads of kind.
func clearPayloads(ctx context.Context, tx db.Transaction, kind string, before time.Time) (int64, error) {
	q := "UPDATE jobs SET payload = '{}' WHERE id IN (SELECT id FROM jobs WHERE kind = ? AND status IN ('done', 'failed', 'cancelled') " +
		"AND finished_at < ? AND payload <> '{}'::jsonb LIMIT ?)"
	if tx.Dialect() == db.MySQL {
		q = "UPDATE jobs SET payload = '{}' WHERE kind = ? AND status IN ('done', 'failed', 'cancelled') AND finished_at < ? " +
			"AND payload <> CAST('{}' AS JSON) ORDER BY finished_at LIMIT ?"
	}
	return exec(ctx, tx, q, kind, before, pruneBatch)
}

// ClearPayload empties a job's payload in tx; a handler calls it once a payload holding a secret has
// done its work.
func ClearPayload(ctx context.Context, tx db.Transaction, id ID) error {
	if _, err := exec(ctx, tx, "UPDATE jobs SET payload = '{}' WHERE id = ?", id); err != nil {
		return fmt.Errorf("clear job payload: %w", err)
	}
	return nil
}

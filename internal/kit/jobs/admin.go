package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/db"
)

type PruneResult struct {
	Deleted int64
	Cleared int64
}

// Prune deletes done and cancelled jobs past RetainDone and failed jobs past RetainFailed, and clears the
// payloads of kinds registered with RetainPayload. Each batch is its own transaction.
func (q *Queue) Prune(ctx context.Context) (PruneResult, error) {
	var res PruneResult
	now := wallNow(ctx)
	steps := []func(ctx context.Context, tx db.Transaction) (int64, error){
		func(ctx context.Context, tx db.Transaction) (int64, error) {
			return deleteFinished(ctx, tx, "'done', 'cancelled'", now.Add(-q.cfg.RetainDone))
		},
		func(ctx context.Context, tx db.Transaction) (int64, error) {
			return deleteFinished(ctx, tx, "'failed'", now.Add(-q.cfg.RetainFailed))
		},
	}
	for _, step := range steps {
		n, err := q.batches(ctx, step)
		res.Deleted += n
		if err != nil {
			return res, fmt.Errorf("jobs: prune: %w", err)
		}
	}
	for _, kind := range slices.Sorted(maps.Keys(q.handlers)) {
		h := q.handlers[kind]
		if h.retainPayload <= 0 {
			continue
		}
		n, err := q.batches(ctx, func(ctx context.Context, tx db.Transaction) (int64, error) {
			return clearPayloads(ctx, tx, kind, now.Add(-h.retainPayload))
		})
		res.Cleared += n
		if err != nil {
			return res, fmt.Errorf("jobs: clear %s payloads: %w", kind, err)
		}
	}
	return res, nil
}

func (q *Queue) batches(ctx context.Context, step func(ctx context.Context, tx db.Transaction) (int64, error)) (int64, error) {
	var total int64
	for {
		var n int64
		err := q.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
			var err error
			n, err = step(ctx, tx)
			return err
		})
		total += n
		if err != nil || n < pruneBatch {
			return total, err
		}
	}
}

// LaneStatus is the queue's depth per lane, kind and status.
type LaneStatus struct {
	Lane     string
	Kind     string
	Status   Status
	Count    int64
	OldestAt time.Time
}

// Status counts open and failed jobs; OldestAt is the earliest run_at among them.
func (q *Queue) Status(ctx context.Context) ([]LaneStatus, error) {
	var out []LaneStatus
	err := q.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		out = nil
		rows, err := tx.Q().QueryContext(ctx, "SELECT lane, kind, status, COUNT(*), MIN(run_at) FROM jobs "+
			"WHERE status IN ('queued', 'running', 'failed') GROUP BY lane, kind, status ORDER BY lane, kind, status")
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var s LaneStatus
			if err := rows.Scan(&s.Lane, &s.Kind, &s.Status, &s.Count, &s.OldestAt); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

// Overdue counts running jobs whose lease ran out more than a lease ago: the reaper returns them within
// a third of a lease, so any here mean no process is reaping.
func (q *Queue) Overdue(ctx context.Context) (int64, error) {
	var n int64
	err := q.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		return scanOne(ctx, tx, "SELECT COUNT(*) FROM jobs WHERE status = 'running' AND locked_until < ?",
			[]any{wallNow(ctx).Add(-q.cfg.Lease)}, &n)
	})
	return n, err
}

// FailedJob is a failed job with its last error.
type FailedJob struct {
	ID        ID
	Kind      string
	Attempts  int
	ErrorCode string
	Error     string
	At        time.Time
}

// Failed lists the most recent failed jobs, newest first.
func (q *Queue) Failed(ctx context.Context, limit int) ([]FailedJob, error) {
	var out []FailedJob
	err := q.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		out = nil
		rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), "SELECT id, kind, attempts, last_error_code, last_error, finished_at FROM jobs "+
			"WHERE status = 'failed' ORDER BY finished_at DESC LIMIT ?"), limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var f FailedJob
			var code, msg sql.NullString
			if err := rows.Scan(&f.ID, &f.Kind, &f.Attempts, &code, &msg, &f.At); err != nil {
				return err
			}
			f.ErrorCode, f.Error = code.String, msg.String
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

// Retry queues a failed or cancelled job again with fresh attempts. It gives up its unique key, which an
// open job may hold by now.
func (q *Queue) Retry(ctx context.Context, id ID) error {
	return q.change(ctx, "UPDATE jobs SET status = 'queued', attempts = 0, unique_key = NULL, run_at = ?, finished_at = NULL, updated_at = ? "+
		"WHERE id = ? AND status IN ('failed', 'cancelled')", id)
}

// RetryAllFailed queues every failed job again, without unique keys, and returns how many.
func (q *Queue) RetryAllFailed(ctx context.Context) (int64, error) {
	var n int64
	err := q.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		now := wallNow(ctx)
		var err error
		n, err = exec(ctx, tx, "UPDATE jobs SET status = 'queued', attempts = 0, unique_key = NULL, run_at = ?, finished_at = NULL, updated_at = ? "+
			"WHERE status = 'failed'", now, now)
		return err
	})
	return n, err
}

// Cancel stops a queued or running job. A running handler loses its lease at the next renewal and is
// cancelled; its outcome is dropped.
func (q *Queue) Cancel(ctx context.Context, id ID) error {
	return q.change(ctx, "UPDATE jobs SET status = 'cancelled', locked_by = NULL, locked_until = NULL, finished_at = ?, updated_at = ? "+
		"WHERE id = ? AND status IN ('queued', 'running')", id)
}

func (q *Queue) change(ctx context.Context, query string, id ID) error {
	return q.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		now := wallNow(ctx)
		n, err := exec(ctx, tx, query, now, now, id)
		if err != nil || n == 1 {
			return err
		}
		var status string
		if err := scanOne(ctx, tx, "SELECT status FROM jobs WHERE id = ?", []any{id}, &status); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		return fmt.Errorf("%w (status %s)", ErrNotAllowed, status)
	})
}

package ratelimit

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
)

const dbTimeout = 2 * time.Second

// DBStore counts fixed windows in rate_counters, so a count holds across replicas and deploys (D31).
// Each hit is one upsert in its own statement on the pool, never in the request's transaction, so a
// rolled-back request still counts. A deadlock is retried once; any other failure refuses the request
// unless the rule fails open.
type DBStore struct {
	pool    *sql.DB
	dialect db.Dialect
}

func NewDBStore(pool *sql.DB, dialect db.Dialect) *DBStore {
	return &DBStore{pool: pool, dialect: dialect}
}

// MySQL has no RETURNING; LAST_INSERT_ID(expr) hands the new count back through the statement's result.
const (
	pgHit = `INSERT INTO rate_counters (bucket, window_start, hits, expires_at) VALUES ($1, $2, 1, $3)
		ON CONFLICT (bucket, window_start) DO UPDATE SET hits = rate_counters.hits + 1 RETURNING hits`
	myHit = `INSERT INTO rate_counters (bucket, window_start, hits, expires_at) VALUES (?, ?, LAST_INSERT_ID(1), ?)
		ON DUPLICATE KEY UPDATE hits = LAST_INSERT_ID(hits + 1)`
)

// Take counts a hit. Errors are returned, not swallowed: a security counter's caller decides whether
// to fail closed.
func (s *DBStore) Take(ctx context.Context, key string, rate Rate) (Decision, error) {
	now := clock.Wall(ctx).Now().UTC()
	window := now.Truncate(rate.Period)
	end := window.Add(rate.Period)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dbTimeout)
	defer cancel()

	hits, err := s.hit(ctx, key, window, end)
	if db.IsRetryable(err) {
		hits, err = s.hit(ctx, key, window, end)
	}
	if err != nil {
		return Decision{}, fmt.Errorf("rate counter: %w", err)
	}
	reset := max(time.Second, end.Sub(now)+time.Second-1).Truncate(time.Second)
	d := Decision{Limit: rate.Limit, Window: rate.Period, Reset: reset, Allowed: hits <= int64(rate.Limit)}
	if d.Allowed {
		d.Remaining = rate.Limit - int(hits)
	} else {
		d.RetryAfter = reset
	}
	return d, nil
}

func (s *DBStore) hit(ctx context.Context, key string, window, end time.Time) (int64, error) {
	switch s.dialect {
	case db.Postgres:
		var hits int64
		err := s.pool.QueryRowContext(ctx, pgHit, key, window, end).Scan(&hits)
		return hits, err
	case db.MySQL:
		res, err := s.pool.ExecContext(ctx, myHit, key, window, end)
		if err != nil {
			return 0, err
		}
		return res.LastInsertId()
	}
	return 0, fmt.Errorf("unsupported dialect %q", s.dialect)
}

// Prune removes windows that ended before before.
func (s *DBStore) Prune(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.pool.ExecContext(ctx, db.Rebind(s.dialect, "DELETE FROM rate_counters WHERE expires_at < ?"), before.UTC())
	if err != nil {
		return 0, fmt.Errorf("prune rate counters: %w", err)
	}
	return res.RowsAffected()
}

// Reset deletes every window of key, so a success clears a failure count.
func (s *DBStore) Reset(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dbTimeout)
	defer cancel()
	if _, err := s.pool.ExecContext(ctx, db.Rebind(s.dialect, "DELETE FROM rate_counters WHERE bucket = ?"), key); err != nil {
		return fmt.Errorf("reset rate counter: %w", err)
	}
	return nil
}

// Refund gives back one hit in key's current window, for an attempt that turned out to succeed.
func (s *DBStore) Refund(ctx context.Context, key string, rate Rate) error {
	window := clock.Wall(ctx).Now().UTC().Truncate(rate.Period)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dbTimeout)
	defer cancel()
	q := db.Rebind(s.dialect, "UPDATE rate_counters SET hits = hits - 1 WHERE bucket = ? AND window_start = ? AND hits > 0")
	if _, err := s.pool.ExecContext(ctx, q, key, window); err != nil {
		return fmt.Errorf("refund rate counter: %w", err)
	}
	return nil
}

// DBStoreOf is a DBStore on d's app pool.
func DBStoreOf(d *db.DB) *DBStore { return NewDBStore(d.SQL(), d.Dialect()) }

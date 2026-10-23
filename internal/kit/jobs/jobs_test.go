package jobs_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

var laneSeq atomic.Int64

// newQueue gives each test its own lane, so workers of other tests never claim its jobs.
func newQueue(t *testing.T, d *db.DB, lease time.Duration) (*jobs.Queue, string) {
	t.Helper()
	lane := fmt.Sprintf("t%d", laneSeq.Add(1))
	cfg := jobs.Defaults()
	cfg.Lanes = jobs.NewLanes(jobs.LaneWorkers{Name: lane, Workers: 1})
	cfg.Lease, cfg.Poll, cfg.ShutdownGrace = lease, 20*time.Millisecond, 0
	q, err := jobs.New(jobs.Options{Config: cfg, Tx: jobs.PlainTx(d)})
	require.NoError(t, err)
	return q, lane
}

// enqueue runs with the business clock far in the future: a job that ran by it would never start.
func enqueue(t *testing.T, d *db.DB, q *jobs.Queue, kind string, payload any, opts ...jobs.EnqueueOption) jobs.ID {
	t.Helper()
	var id jobs.ID
	ctx := clock.WithFixed(t.Context(), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		id, err = q.Enqueue(ctx, tx, kind, payload, opts...)
		return err
	}))
	return id
}

type jobRow struct {
	Status      string
	Attempts    int
	LockedBy    sql.NullString
	RunAt       time.Time
	LockedUntil sql.NullTime
	ErrorCode   sql.NullString
	Error       sql.NullString
	Payload     string
}

func load(t *testing.T, d *db.DB, id jobs.ID) jobRow {
	t.Helper()
	var r jobRow
	q := db.Rebind(d.Dialect(), "SELECT status, attempts, locked_by, run_at, locked_until, last_error_code, last_error, payload FROM jobs WHERE id = ?")
	require.NoError(t, d.SQL().QueryRowContext(t.Context(), q, id).Scan(&r.Status, &r.Attempts, &r.LockedBy, &r.RunAt, &r.LockedUntil, &r.ErrorCode, &r.Error, &r.Payload))
	return r
}

func run(t *testing.T, q *jobs.Queue) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- q.Run(ctx) }()
	return func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("queue did not stop")
		}
	}
}

func wait(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func eventually(t *testing.T, cond func() bool, what string) {
	t.Helper()
	require.Eventually(t, cond, 10*time.Second, 20*time.Millisecond, what)
}

// A worker that cannot renew its lease must stop before the lease runs out, and nobody else may start
// the job until it has.
func TestLease_LossCancelsHandlerAndNextRunStartsOnlyAfterExpiry(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		const lease = time.Second
		type runInfo struct {
			attempt    int
			start, end time.Time
			cause      error
		}
		var mu sync.Mutex
		var runs []runInfo
		started, cancelled := make(chan struct{}), make(chan struct{})
		handler := func(ctx context.Context, job jobs.Job) error {
			r := runInfo{attempt: job.Attempt, start: clock.Wall(ctx).Now()}
			if job.Attempt == 1 {
				close(started)
				<-ctx.Done()
				r.cause = context.Cause(ctx)
				close(cancelled)
			}
			r.end = clock.Wall(ctx).Now()
			mu.Lock()
			runs = append(runs, r)
			mu.Unlock()
			return ctx.Err()
		}
		a, lane := newQueue(t, d, lease)
		now := jobs.Backoff(func(int) time.Duration { return 0 })
		a.Handle("lease.test", handler, jobs.Lane(lane), now)
		cfg := jobs.Defaults()
		cfg.Lanes = jobs.NewLanes(jobs.LaneWorkers{Name: lane, Workers: 1})
		cfg.Lease, cfg.Poll, cfg.ShutdownGrace = lease, 20*time.Millisecond, 0
		b, err := jobs.New(jobs.Options{Config: cfg, Tx: jobs.PlainTx(d)})
		require.NoError(t, err)
		b.Handle("lease.test", handler, jobs.Lane(lane), now)

		id := enqueue(t, d, a, "lease.test", nil)
		defer run(t, a)()
		wait(t, started, "first run")
		expiry := load(t, d, id).LockedUntil.Time
		defer run(t, b)()

		// Hold the job's row so no renewal can be confirmed.
		require.NoError(t, db.InTx(t.Context(), d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), "SELECT id FROM jobs WHERE id = ? FOR UPDATE"), id)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() { //nolint:revive // only the row lock matters
			}
			if err := rows.Err(); err != nil {
				return err
			}
			wait(t, cancelled, "lease loss")
			return nil
		}))

		eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(runs) == 2
		}, "second run")
		mu.Lock()
		defer mu.Unlock()
		first, second := runs[0], runs[1]
		require.ErrorIs(t, first.cause, jobs.ErrLeaseLost)
		assert.False(t, first.end.Before(expiry.Add(-50*time.Millisecond)), "cancelled before the confirmed lease ran out")
		assert.Equal(t, 2, second.attempt)
		assert.True(t, second.start.After(first.end), "second run overlapped the first")
		assert.False(t, second.start.Before(expiry), "second run started before the first lease expired")
		eventually(t, func() bool { return load(t, d, id).Status == "done" }, "job done")
	})
}

func TestShutdown_RequeuesWithoutSpendingAnAttempt(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		q, lane := newQueue(t, d, 2*time.Second)
		started := make(chan struct{})
		q.Handle("shutdown.test", func(ctx context.Context, _ jobs.Job) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}, jobs.Lane(lane))
		id := enqueue(t, d, q, "shutdown.test", nil)
		stop := run(t, q)
		wait(t, started, "run")
		stop()

		r := load(t, d, id)
		assert.Equal(t, "queued", r.Status)
		assert.Equal(t, 0, r.Attempts)
		assert.False(t, r.LockedBy.Valid)
	})
}

func TestEnqueue_UniqueKeyDedupesOnlyWhileOpen(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		q, lane := newQueue(t, d, 2*time.Second)
		q.Handle("unique.test", func(context.Context, jobs.Job) error { return nil }, jobs.Lane(lane))
		key := "unique:" + lane

		first := enqueue(t, d, q, "unique.test", nil, jobs.Unique(key))
		again := enqueue(t, d, q, "unique.test", nil, jobs.Unique(key))
		assert.Equal(t, first, again)

		_, err := d.SQL().ExecContext(t.Context(), db.Rebind(d.Dialect(), "UPDATE jobs SET status = 'done', finished_at = run_at WHERE id = ?"), first)
		require.NoError(t, err)
		after := enqueue(t, d, q, "unique.test", nil, jobs.Unique(key))
		assert.NotEqual(t, first, after)
	})
}

func TestSchedule_OneEnqueuePerSlotUnderConcurrentTicks(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		q, lane := newQueue(t, d, 2*time.Second)
		kind := "sched.test." + lane
		q.Handle(kind, func(context.Context, jobs.Job) error { return nil }, jobs.Lane(lane))
		q.Schedule(kind, kind, "*/5 * * * *", time.UTC)
		ctx := t.Context()
		require.NoError(t, q.SyncSchedules(ctx))
		_, err := d.SQL().ExecContext(ctx, db.Rebind(d.Dialect(), "UPDATE job_schedules SET next_run_at = ? WHERE name = ?"),
			clock.Wall(ctx).Now().Add(-time.Minute).UTC(), kind)
		require.NoError(t, err)

		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() { assert.NoError(t, q.TickSchedules(ctx)) })
		}
		wg.Wait()
		require.NoError(t, q.TickSchedules(ctx))

		var n int
		require.NoError(t, d.SQL().QueryRowContext(ctx, db.Rebind(d.Dialect(), "SELECT COUNT(*) FROM jobs WHERE kind = ?"), kind).Scan(&n))
		assert.Equal(t, 1, n)
	})
}

func TestOutcomes(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		q, lane := newQueue(t, d, 2*time.Second)
		q.Handle("outcome.test", jobs.Typed(func(_ context.Context, _ jobs.Job, p struct{ Case string }) error {
			switch p.Case {
			case "permanent":
				return jobs.Permanent(errors.New("bad input for someone@example.com"))
			case "retry-after":
				return jobs.RetryAfter(time.Hour, errors.New("busy"))
			case "exhausted":
				return errors.New("still broken")
			}
			return nil
		}), jobs.Lane(lane), jobs.MaxAttempts(3))
		cases := map[string]jobs.ID{}
		for _, c := range []string{"ok", "permanent", "retry-after"} {
			cases[c] = enqueue(t, d, q, "outcome.test", map[string]string{"Case": c})
		}
		exhausted := enqueue(t, d, q, "outcome.test", map[string]string{"Case": "exhausted"}, jobs.MaxAttempts(1))
		stop := run(t, q)
		eventually(t, func() bool {
			return load(t, d, cases["ok"]).Status == "done" && load(t, d, cases["permanent"]).Status == "failed" &&
				load(t, d, cases["retry-after"]).Attempts == 1 && load(t, d, cases["retry-after"]).Status == "queued" &&
				load(t, d, exhausted).Status == "failed"
		}, "outcomes")
		stop()

		perm := load(t, d, cases["permanent"])
		assert.Equal(t, 1, perm.Attempts)
		assert.Equal(t, "error", perm.ErrorCode.String)
		assert.NotContains(t, perm.Error.String, "someone@example.com")
		later := load(t, d, cases["retry-after"]).RunAt.Sub(clock.Wall(t.Context()).Now())
		assert.Greater(t, later, 50*time.Minute)
		assert.Less(t, later, 61*time.Minute)
		assert.Equal(t, 1, load(t, d, exhausted).Attempts)
	})
}

func TestBackoff_HasFullJitterUnderTheCap(t *testing.T) {
	seen := map[time.Duration]bool{}
	for range 50 {
		d := jobs.BackoffDelay(3)
		require.GreaterOrEqual(t, d, time.Duration(0))
		require.LessOrEqual(t, d, 20*time.Second)
		seen[d] = true
	}
	assert.Greater(t, len(seen), 40, "delays should be spread, not fixed")
	assert.LessOrEqual(t, jobs.BackoffDelay(40), time.Hour)
}

func TestPrune_DeletesFinishedJobsAndClearsRetainedPayloads(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		q, lane := newQueue(t, d, 2*time.Second)
		kind := "prune.test." + lane
		q.Handle(kind, func(context.Context, jobs.Job) error { return nil }, jobs.Lane(lane), jobs.RetainPayload(time.Hour))
		old := enqueue(t, d, q, kind, map[string]string{"email": "x@example.com"})
		recent := enqueue(t, d, q, kind, map[string]string{"email": "y@example.com"})
		ctx := t.Context()
		now := clock.Wall(ctx).Now().UTC()
		set := db.Rebind(d.Dialect(), "UPDATE jobs SET status = ?, finished_at = ? WHERE id = ?")
		_, err := d.SQL().ExecContext(ctx, set, "done", now.Add(-200*time.Hour), old)
		require.NoError(t, err)
		_, err = d.SQL().ExecContext(ctx, set, "failed", now.Add(-2*time.Hour), recent)
		require.NoError(t, err)

		_, err = q.Prune(ctx)
		require.NoError(t, err)

		var n int
		require.NoError(t, d.SQL().QueryRowContext(ctx, db.Rebind(d.Dialect(), "SELECT COUNT(*) FROM jobs WHERE id = ?"), old).Scan(&n))
		assert.Equal(t, 0, n)
		assert.NotContains(t, load(t, d, recent).Payload, "y@example.com")
	})
}

func TestReadyIndexCoversOnlyOpenJobs(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		if e.Dialect() != db.Postgres {
			t.Skip("MySQL has no partial indexes")
		}
		var def string
		require.NoError(t, e.DB().SQL().QueryRowContext(t.Context(), "SELECT indexdef FROM pg_indexes WHERE indexname = 'jobs_ready'").Scan(&def))
		assert.True(t, strings.HasSuffix(def, "WHERE (status = 'queued'::text)"), def)
	})
}

// A handler that sees the shutdown and returns nil has not finished its work: the job goes back to the
// queue without spending the attempt.
func TestShutdown_CancelledHandlerReturningNilIsReleased(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		q, lane := newQueue(t, d, 2*time.Second)
		started := make(chan struct{})
		q.Handle("shutdown.nil", func(ctx context.Context, _ jobs.Job) error {
			close(started)
			<-ctx.Done()
			return nil
		}, jobs.Lane(lane))
		id := enqueue(t, d, q, "shutdown.nil", nil)
		stop := run(t, q)
		wait(t, started, "run")
		stop()

		r := load(t, d, id)
		assert.Equal(t, "queued", r.Status)
		assert.Equal(t, 0, r.Attempts)
	})
}

// A transaction that read before enqueueing must still find a twin committed after that read.
func TestEnqueue_UniqueTwinCommittedDuringTheTransactionIsReturned(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		q, lane := newQueue(t, d, 2*time.Second)
		q.Handle("unique.race", func(context.Context, jobs.Job) error { return nil }, jobs.Lane(lane))
		key := "race:" + lane
		ctx := t.Context()

		held, release := make(chan jobs.ID, 1), make(chan struct{})
		first := make(chan error, 1)
		go func() {
			first <- db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				id, err := q.Enqueue(ctx, tx, "unique.race", nil, jobs.Unique(key))
				held <- id
				<-release
				return err
			})
		}()
		want := <-held
		var got jobs.ID
		require.NoError(t, db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			rows, err := tx.Q().QueryContext(ctx, "SELECT COUNT(*) FROM jobs")
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			if err := errors.Join(rows.Err(), rows.Close()); err != nil {
				return err
			}
			time.AfterFunc(200*time.Millisecond, func() { close(release) })
			got, err = q.Enqueue(ctx, tx, "unique.race", nil, jobs.Unique(key))
			return err
		}))
		require.NoError(t, <-first)
		assert.Equal(t, want, got)
	})
}

// Two releases run side by side during a deploy; only the newer build may rewrite a schedule.
func TestSchedule_OnlyANewerBuildChangesTheSpec(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		lane := fmt.Sprintf("t%d", laneSeq.Add(1))
		name := "sched.build." + lane
		syncAs := func(build, spec string) {
			cfg := jobs.Defaults()
			cfg.Lanes = jobs.NewLanes(jobs.LaneWorkers{Name: lane, Workers: 1})
			q, err := jobs.New(jobs.Options{Config: cfg, Tx: jobs.PlainTx(d), Build: build})
			require.NoError(t, err)
			q.Handle(name, func(context.Context, jobs.Job) error { return nil }, jobs.Lane(lane))
			q.Schedule(name, name, spec, time.UTC)
			require.NoError(t, q.SyncSchedules(t.Context()))
		}
		stored := func() string {
			var spec string
			require.NoError(t, d.SQL().QueryRowContext(t.Context(), db.Rebind(d.Dialect(), "SELECT spec FROM job_schedules WHERE name = ?"), name).Scan(&spec))
			return spec
		}

		syncAs("2026-10-02T00:00:00Z", "0 1 * * *")
		syncAs("2026-10-01T00:00:00Z", "0 2 * * *")
		assert.Equal(t, "0 1 * * *", stored(), "an older build leaves it")
		syncAs("", "0 3 * * *")
		assert.Equal(t, "0 1 * * *", stored(), "an unstamped build leaves it")
		syncAs("2026-10-03T00:00:00Z", "0 4 * * *")
		assert.Equal(t, "0 4 * * *", stored(), "a newer build changes it")

		for _, bad := range []string{"v1.2.3", "2026-10-03T02:00:00+02:00", "2026-10-03T00:00:00.5Z", strings.Repeat("9", 65)} {
			_, err := jobs.New(jobs.Options{Config: jobs.Defaults(), Tx: jobs.PlainTx(d), Build: bad})
			require.Error(t, err, "a stamp that does not sort as time: %s", bad)
		}
	})
}

// A kind no process knows is released while a deploy may still bring it, then fails.
func TestUnknownKind_FailsAfterTheLimit(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		known, lane := newQueue(t, d, 2*time.Second)
		kind := "unknown.test." + lane
		known.Handle(kind, func(context.Context, jobs.Job) error { return nil }, jobs.Lane(lane))
		fresh := enqueue(t, d, known, kind, nil)
		stale := enqueue(t, d, known, kind, nil)
		_, err := d.SQL().ExecContext(t.Context(), db.Rebind(d.Dialect(), "UPDATE jobs SET created_at = ? WHERE id = ?"),
			clock.Wall(t.Context()).Now().Add(-2*time.Hour).UTC(), stale)
		require.NoError(t, err)

		cfg := jobs.Defaults()
		cfg.Lanes = jobs.NewLanes(jobs.LaneWorkers{Name: lane, Workers: 1})
		cfg.Poll, cfg.ShutdownGrace = 20*time.Millisecond, 0
		other, err := jobs.New(jobs.Options{Config: cfg, Tx: jobs.PlainTx(d)})
		require.NoError(t, err)
		stop := run(t, other)
		eventually(t, func() bool { return load(t, d, stale).Status == "failed" }, "the stale job fails")
		eventually(t, func() bool { return load(t, d, fresh).RunAt.After(clock.Wall(t.Context()).Now()) }, "the fresh job is released")
		stop()

		assert.Equal(t, "unknown_kind", load(t, d, stale).ErrorCode.String)
		f := load(t, d, fresh)
		assert.Equal(t, "queued", f.Status)
		assert.Zero(t, f.Attempts, "a release gives the attempt back")
	})
}

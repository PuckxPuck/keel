package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime/debug"
	"sync"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/logx"
)

var (
	errLeaseLost = errors.New("jobs: the lease could not be confirmed")
	errShutdown  = errors.New("jobs: worker shutting down")
)

const (
	outcomeTimeout   = 10 * time.Second
	unknownKindDelay = 30 * time.Second
	// unknownKindLimit outlasts a deploy's overlap, when an older process may claim a newer build's kind.
	unknownKindLimit   = time.Hour
	suspendedDelay     = 15 * time.Minute
	stopAfterHardLimit = 5 * time.Second
	backoffBase        = 5 * time.Second
	backoffCap         = time.Hour
)

// Run runs workers for lanes (every configured lane when none are named), the scheduler and the reaper
// until ctx is cancelled. Running handlers then get the shutdown grace to finish; after it their context
// is cancelled and the job goes back to the queue without spending an attempt.
func (q *Queue) Run(ctx context.Context, lanes ...string) error {
	q.started.Store(true)
	pick := q.cfg.Lanes.list
	if len(lanes) > 0 {
		pick = nil
		for _, name := range lanes {
			n, ok := q.cfg.Lanes.workers(name)
			if !ok {
				return fmt.Errorf("jobs: lane %q is not configured", name)
			}
			pick = append(pick, LaneWorkers{Name: name, Workers: n})
		}
	}
	if err := q.syncSchedules(ctx); err != nil {
		return err
	}

	hard, stop := context.WithCancelCause(context.WithoutCancel(ctx))
	defer stop(nil)
	var workers, loops sync.WaitGroup
	for _, lane := range pick {
		for range lane.Workers {
			workers.Go(func() { q.work(ctx, hard, lane.Name) })
		}
	}
	loops.Go(func() { q.every(ctx, q.cfg.Lease/3, q.reapOnce) })
	loops.Go(func() { q.every(ctx, q.cfg.Poll, q.tickSchedules) })

	<-ctx.Done()
	loops.Wait()
	if waitFor(&workers, q.cfg.ShutdownGrace) {
		return nil
	}
	stop(errShutdown)
	if waitFor(&workers, stopAfterHardLimit) {
		return nil
	}
	return errors.New("jobs: handlers did not stop after their context was cancelled")
}

func waitFor(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

func (q *Queue) every(ctx context.Context, d time.Duration, fn func(context.Context) error) {
	for {
		if err := fn(ctx); err != nil && ctx.Err() == nil {
			logx.From(ctx).Warn("jobs: background step failed", "error", err)
		}
		if !sleep(ctx, jitter(d)) {
			return
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// jitter spreads polls by up to 10 percent so replicas do not query in step.
func jitter(d time.Duration) time.Duration {
	return d - time.Duration(rand.Int64N(int64(d)/10+1)) //nolint:gosec // spread, not secrecy
}

func (q *Queue) reapOnce(ctx context.Context) error {
	return q.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		_, err := reap(ctx, tx, wallNow(ctx), q.retryDelay)
		return err
	})
}

func (q *Queue) work(ctx, hard context.Context, lane string) {
	for ctx.Err() == nil {
		c, ok, err := q.claimOne(ctx, lane)
		if err != nil {
			logx.From(ctx).Warn("jobs: claim failed", "lane", lane, "error", err)
		}
		if !ok {
			if !sleep(ctx, jitter(q.cfg.Poll)) {
				return
			}
			continue
		}
		q.execute(hard, c)
	}
}

// claimOne does not stop for ctx once started, so a claim that commits is always run.
func (q *Queue) claimOne(ctx context.Context, lane string) (claimed, bool, error) {
	var c claimed
	var ok bool
	err := q.tx(context.WithoutCancel(ctx), func(ctx context.Context, tx db.Transaction) error {
		var err error
		c, ok, err = claim(ctx, tx, lane, claimToken(q.instance), wallNow(ctx), q.cfg.Lease)
		return err
	})
	if err != nil || !ok {
		return claimed{}, false, err
	}
	if q.metrics.Claimed != nil {
		q.metrics.Claimed(ctx, c.job.Kind, lane, c.claimed.Sub(c.runAt))
	}
	return c, true, nil
}

func (q *Queue) execute(hard context.Context, c claimed) {
	log := logx.From(hard).With("job_id", c.job.ID.String(), "job_kind", c.job.Kind, "attempt", c.job.Attempt)
	h, known := q.handlers[c.job.Kind]
	if !known && wallNow(hard).Sub(c.created) > unknownKindLimit {
		log.Warn("jobs: no process has run the kind since the job was enqueued; failed")
		q.finish(hard, c, OutcomeFailed, func(ctx context.Context, tx db.Transaction, now time.Time) (bool, error) {
			return markFailed(ctx, tx, c, now, "unknown_kind", "no handler is registered for the kind")
		})
		return
	}
	if !known {
		log.Warn("jobs: no handler for kind in this process; released")
		q.finish(hard, c, OutcomeReleased, func(ctx context.Context, tx db.Transaction, now time.Time) (bool, error) {
			return markReleased(ctx, tx, c, now.Add(unknownKindDelay), now)
		})
		return
	}

	if c.held {
		log.Info("jobs: the job's tenant is suspended; postponed")
		q.finish(hard, c, OutcomeReleased, func(ctx context.Context, tx db.Transaction, now time.Time) (bool, error) {
			return markReleased(ctx, tx, c, now.Add(suspendedDelay), now)
		})
		return
	}
	if c.tenancy && c.job.Tenant == nil && !h.global {
		log.Warn("jobs: a job without a tenant of a kind not registered as global; failed without running")
		q.finish(hard, c, OutcomeFailed, func(ctx context.Context, tx db.Transaction, now time.Time) (bool, error) {
			return markFailed(ctx, tx, c, now, "no_tenant", "the kind runs only for a tenant")
		})
		return
	}
	base := hard
	if c.job.Tenant != nil {
		base = db.WithTenant(logx.With(hard, slog.String(logx.KeyTenantID, c.job.Tenant.String())), *c.job.Tenant)
	}
	run, cancel := context.WithCancelCause(base)
	defer cancel(nil)
	stopLease := make(chan struct{})
	var lease sync.WaitGroup
	lease.Go(func() { q.keepLease(hard, cancel, c, stopLease) })

	handlerCtx, end := run, func(error) {}
	if q.trace != nil {
		handlerCtx, end = q.trace(run, c.job)
	}
	err := call(handlerCtx, h, c.job)
	end(err)
	close(stopLease)
	lease.Wait()

	// The cause decides before the result: a handler that saw the cancellation may still return nil.
	cause := context.Cause(run)
	switch {
	case errors.Is(cause, errShutdown):
		q.finish(hard, c, OutcomeReleased, func(ctx context.Context, tx db.Transaction, now time.Time) (bool, error) {
			return markReleased(ctx, tx, c, now, now)
		})
	case errors.Is(cause, errLeaseLost):
		log.Warn("jobs: lease lost; handler cancelled and its outcome dropped")
		q.finish(hard, c, OutcomeLeaseLost, nil)
	case err == nil:
		q.finish(hard, c, OutcomeDone, func(ctx context.Context, tx db.Transaction, now time.Time) (bool, error) {
			return markDone(ctx, tx, c, now)
		})
	default:
		q.fail(hard, log, c, err)
	}
}

// call runs the handler under its timeout and turns a panic into an error.
func call(ctx context.Context, h handlerSpec, job Job) (err error) {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			logx.From(ctx).Error("jobs: handler panicked", "job_kind", job.Kind, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			err = Permanent(panicError{})
		}
	}()
	return h.fn(ctx, job)
}

type panicError struct{}

func (panicError) Error() string     { return "the handler panicked" }
func (panicError) ErrorCode() string { return "panic" }

func (q *Queue) fail(hard context.Context, log *slog.Logger, c claimed, err error) {
	code, msg := errorCode(err), Redact(err.Error())
	var permanent *permanentError
	var after *retryAfterError
	exhausted := c.job.Attempt >= c.job.MaxAttempts
	if errors.As(err, &permanent) || exhausted {
		log.Info("jobs: failed", "error_code", code)
		q.finish(hard, c, OutcomeFailed, func(ctx context.Context, tx db.Transaction, now time.Time) (bool, error) {
			return markFailed(ctx, tx, c, now, code, msg)
		})
		return
	}
	delay := q.retryDelay(c.job.Kind, c.job.Attempt)
	if errors.As(err, &after) {
		delay = after.after
	}
	q.finish(hard, c, OutcomeRetry, func(ctx context.Context, tx db.Transaction, now time.Time) (bool, error) {
		return markRetry(ctx, tx, c, now.Add(delay), now, code, msg)
	})
}

// retryDelay is the kind's backoff, or the default one for kinds this process does not know.
func (q *Queue) retryDelay(kind string, attempt int) time.Duration {
	if h, ok := q.handlers[kind]; ok && h.backoff != nil {
		return h.backoff(attempt)
	}
	return backoff(attempt)
}

func errorCode(err error) string {
	var coded Coded
	switch {
	case errors.As(err, &coded) && coded.ErrorCode() != "":
		code := coded.ErrorCode()
		if len(code) > 64 {
			code = code[:64]
		}
		return code
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	return "error"
}

// backoff is exponential with full jitter: a random delay up to base times 2^(attempt-1), capped.
func backoff(attempt int) time.Duration {
	ceiling := backoffCap
	if attempt < 20 {
		ceiling = min(backoffCap, backoffBase<<(max(attempt, 1)-1))
	}
	return time.Duration(rand.Int64N(int64(ceiling) + 1)) //nolint:gosec // jitter, not secrecy
}

// finish records the outcome fenced by the claim token; a token that no longer holds the job changes
// nothing. A nil write records nothing (a lost lease: the reaper owns the job now).
func (q *Queue) finish(hard context.Context, c claimed, outcome Outcome,
	write func(ctx context.Context, tx db.Transaction, now time.Time) (bool, error),
) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(hard), outcomeTimeout)
	defer cancel()
	held := true
	var err error
	if write != nil {
		err = q.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
			var err error
			held, err = write(ctx, tx, wallNow(ctx))
			return err
		})
	}
	log := logx.From(ctx)
	switch {
	case err != nil:
		log.Warn("jobs: outcome not recorded; the lease will expire and the job will run again",
			"job_id", c.job.ID.String(), "job_kind", c.job.Kind, "error", err)
	case !held:
		log.Warn("jobs: outcome dropped; another worker or an operator holds the job", "job_id", c.job.ID.String(), "job_kind", c.job.Kind)
	}
	if q.metrics.Finished != nil {
		q.metrics.Finished(ctx, c.job.Kind, c.lane, outcome, wallNow(ctx).Sub(c.claimed))
	}
}

// keepLease renews every third of the lease and cancels the handler once the last confirmed lease has
// passed, so a worker that cannot reach the database stops before another may take the job.
func (q *Queue) keepLease(hard context.Context, cancel context.CancelCauseFunc, c claimed, stop <-chan struct{}) {
	base := context.WithoutCancel(hard)
	until := c.until
	deadline := time.NewTimer(until.Sub(wallNow(base)))
	defer deadline.Stop()
	tick := time.NewTicker(q.cfg.Lease / 3)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-deadline.C:
			cancel(errLeaseLost)
			return
		case <-tick.C:
		}
		now := wallNow(base)
		next := now.Add(q.cfg.Lease)
		ctx, done := context.WithTimeout(base, until.Sub(now))
		var held bool
		err := q.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
			var err error
			held, err = renew(ctx, tx, c.job.ID, c.token, next, now)
			return err
		})
		done()
		switch {
		case err != nil:
			logx.From(base).Warn("jobs: lease renewal failed", "job_id", c.job.ID.String(), "error", err)
		case !held:
			cancel(errLeaseLost)
			return
		default:
			until = next
			deadline.Reset(until.Sub(wallNow(base)))
		}
	}
}

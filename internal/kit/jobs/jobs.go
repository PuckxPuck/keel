// Package jobs is the background job queue on a table in the app's database (D11): enqueued in the
// caller's transaction, claimed with SKIP LOCKED, leased on the wall clock, delivered at least once.
package jobs

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/adhocore/gronx"
	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
)

type jobTag struct{}

type ID = ids.ID[jobTag]

type Status string

const (
	Queued    Status = "queued"
	Running   Status = "running"
	Done      Status = "done"
	Failed    Status = "failed"
	Cancelled Status = "cancelled"
)

const (
	maxAttemptsLimit = 1000
	maxPayloadBytes  = 256 << 10
	maxKind          = 128
	maxUniqueKey     = 255
	defaultTimeout   = 10 * time.Minute
	pruneKind        = "jobs.prune"
	pruneSpec        = "17 * * * *"
)

// Job is one run of a job. Attempt is 1 on the first run. Tenant is the tenant it was enqueued in under
// tenancy; the worker puts it in the handler's context (db.WithTenant), so the handler's transactions
// are that tenant's.
type Job struct {
	ID          ID
	Kind        string
	Payload     json.RawMessage
	Attempt     int
	MaxAttempts int
	Tenant      *uuid.UUID
}

// Handler runs a job. It must be idempotent: a job can run again after a crash or a lost lease.
type Handler func(ctx context.Context, job Job) error

// Typed decodes the payload into T before calling fn; a payload that does not decode fails the job.
func Typed[T any](fn func(ctx context.Context, job Job, payload T) error) Handler {
	return func(ctx context.Context, job Job) error {
		var p T
		if err := json.Unmarshal(job.Payload, &p); err != nil {
			return Permanent(fmt.Errorf("decode %s payload: %w", job.Kind, err))
		}
		return fn(ctx, job, p)
	}
}

// TxRunner opens the transactions the queue's own bookkeeping runs in: plain transactions without
// tenancy, operator transactions with it (jobs of every tenant are claimed in one place).
type TxRunner func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error

// PlainTx runs the queue's bookkeeping in plain transactions on d, read committed: MySQL's default
// repeatable read would make a claim lock every row it scans and the gaps between them.
func PlainTx(d *db.DB) TxRunner {
	return func(ctx context.Context, fn func(context.Context, db.Transaction) error) error {
		return db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error { return fn(ctx, tx) }, db.Isolation(sql.LevelReadCommitted))
	}
}

// OperatorTx runs the queue's bookkeeping on the operator pool, read committed: under tenancy one place
// claims, reaps and prunes the jobs of every tenant.
func OperatorTx(access *db.OperatorAccess) TxRunner {
	return func(ctx context.Context, fn func(context.Context, db.Transaction) error) error {
		return db.InOperatorTx(ctx, access, func(ctx context.Context, tx db.Tx[db.Operator]) error { return fn(ctx, tx) }, db.Isolation(sql.LevelReadCommitted))
	}
}

// Outcome is how a run ended, for metrics.
type Outcome string

const (
	OutcomeDone      Outcome = "done"
	OutcomeRetry     Outcome = "retry"
	OutcomeFailed    Outcome = "failed"
	OutcomeReleased  Outcome = "released"
	OutcomeLeaseLost Outcome = "lease_lost"
)

// Metrics are optional callbacks; nil fields are skipped. They run on worker goroutines and must not block.
type Metrics struct {
	Claimed  func(ctx context.Context, kind, lane string, waited time.Duration)
	Finished func(ctx context.Context, kind, lane string, outcome Outcome, took time.Duration)
}

type Options struct {
	Config Config
	Tx     TxRunner
	// Metrics receive claim and finish events.
	Metrics Metrics
	// Trace wraps each run of a handler: it returns the context the handler runs with and a function the
	// handler's result is reported to.
	Trace func(ctx context.Context, job Job) (context.Context, func(error))
	// Build orders builds: the build time in RFC 3339 UTC (2026-10-23T12:00:00Z). A stored schedule
	// changes only for a build that sorts at or after the one that wrote it, so two releases running side
	// by side do not rewrite each other's specs. Empty (an unstamped build) never changes a stamped one.
	Build string
}

type handlerSpec struct {
	global        bool
	fn            Handler
	lane          string
	timeout       time.Duration
	maxAttempts   int
	backoff       func(attempt int) time.Duration
	retainPayload time.Duration
}

type schedule struct {
	name string
	kind string
	spec string
	loc  *time.Location
}

// Queue registers handlers and schedules, enqueues jobs and runs workers.
type Queue struct {
	cfg       Config
	tx        TxRunner
	metrics   Metrics
	trace     func(ctx context.Context, job Job) (context.Context, func(error))
	build     string
	instance  string
	handlers  map[string]handlerSpec
	schedules map[string]schedule
	started   atomic.Bool
}

// New makes a queue and registers its retention job (kind jobs.prune, hourly).
func New(o Options) (*Queue, error) {
	if err := o.Config.Validate(false); err != nil {
		return nil, fmt.Errorf("jobs: %w", err)
	}
	if o.Tx == nil {
		return nil, errors.New("jobs: a transaction runner is required")
	}
	if err := checkBuild(o.Build); err != nil {
		return nil, err
	}
	q := &Queue{
		cfg: o.Config, tx: o.Tx, metrics: o.Metrics, trace: o.Trace, build: o.Build, instance: instanceID(),
		handlers: map[string]handlerSpec{}, schedules: map[string]schedule{},
	}
	q.Handle(pruneKind, func(ctx context.Context, _ Job) error {
		_, err := q.Prune(ctx)
		return err
	}, Lane(q.cfg.Lanes.list[0].Name), Global())
	q.Schedule(pruneKind, pruneKind, pruneSpec, time.UTC)
	return q, nil
}

// maxBuild is the width of job_schedules.build.
const maxBuild = 64

// checkBuild accepts only the form that sorts as time does, so comparing stamps compares build times.
func checkBuild(b string) error {
	if b == "" {
		return nil
	}
	if len(b) > maxBuild {
		return fmt.Errorf("jobs: the build stamp has %d characters, at most %d", len(b), maxBuild)
	}
	if t, err := time.Parse(time.RFC3339, b); err != nil || t.UTC().Format(time.RFC3339) != b {
		return fmt.Errorf("jobs: the build stamp %q must be the build time in RFC 3339 UTC, such as 2026-10-23T12:00:00Z", b)
	}
	return nil
}

func instanceID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "host"
	}
	if len(host) > 64 {
		host = host[:64]
	}
	return fmt.Sprintf("%s:%d", host, os.Getpid())
}

func claimToken(instance string) string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	return instance + "/" + hex.EncodeToString(b[:])
}

// HandlerOption configures a kind at registration.
type HandlerOption interface{ handler(*handlerSpec) }

// EnqueueOption configures one enqueued job.
type EnqueueOption interface{ enqueue(*enqueueSpec) }

type handlerOptionFunc func(*handlerSpec)

func (f handlerOptionFunc) handler(h *handlerSpec) { f(h) }

type enqueueOptionFunc func(*enqueueSpec)

func (f enqueueOptionFunc) enqueue(e *enqueueSpec) { f(e) }

// LaneOption sets a lane for a kind (at registration) or for one job (at enqueue).
type LaneOption string

func Lane(name string) LaneOption { return LaneOption(name) }

func (l LaneOption) handler(h *handlerSpec) { h.lane = string(l) }
func (l LaneOption) enqueue(e *enqueueSpec) { e.lane = string(l) }

// AttemptsOption sets the maximum attempts for a kind or for one job.
type AttemptsOption int

func MaxAttempts(n int) AttemptsOption { return AttemptsOption(n) }

func (a AttemptsOption) handler(h *handlerSpec) { h.maxAttempts = int(a) }
func (a AttemptsOption) enqueue(e *enqueueSpec) { e.maxAttempts = int(a) }

// Timeout bounds one run of the kind (default 10m).
func Timeout(d time.Duration) HandlerOption {
	return handlerOptionFunc(func(h *handlerSpec) { h.timeout = d })
}

// Backoff replaces the default delay before attempt+1 (exponential with full jitter).
func Backoff(fn func(attempt int) time.Duration) HandlerOption {
	return handlerOptionFunc(func(h *handlerSpec) { h.backoff = fn })
}

// Global lets the kind run without a tenant under tenancy: maintenance, schedules, and work for no
// tenant such as a sign-in link to a user who has none yet. Its handler's transactions then go to the
// operator pool. Under tenancy a job without a tenant of any other kind fails without running.
func Global() HandlerOption {
	return handlerOptionFunc(func(h *handlerSpec) { h.global = true })
}

// RetainPayload clears the payload of the kind's finished jobs after d, for payloads with personal data.
func RetainPayload(d time.Duration) HandlerOption {
	return handlerOptionFunc(func(h *handlerSpec) { h.retainPayload = d })
}

type enqueueSpec struct {
	runAt       time.Time
	uniqueKey   string
	priority    int
	lane        string
	maxAttempts int
}

// At runs the job no earlier than t.
func At(t time.Time) EnqueueOption {
	return enqueueOptionFunc(func(e *enqueueSpec) { e.runAt = t })
}

// Unique dedupes the job while another job with the key is queued or running; Enqueue then returns that job's id.
func Unique(key string) EnqueueOption {
	return enqueueOptionFunc(func(e *enqueueSpec) { e.uniqueKey = key })
}

// Priority orders ready jobs in a lane; higher runs first (-1000 to 1000, default 0).
func Priority(p int) EnqueueOption {
	return enqueueOptionFunc(func(e *enqueueSpec) { e.priority = p })
}

var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)

// Handle registers fn for kind. Call it during wiring, before Run; mistakes panic (startup programmer errors).
func (q *Queue) Handle(kind string, fn Handler, opts ...HandlerOption) {
	if q.started.Load() {
		panic("jobs: Handle after Run")
	}
	if !kindPattern.MatchString(kind) || fn == nil {
		panic("jobs: invalid kind or nil handler: " + kind)
	}
	if _, dup := q.handlers[kind]; dup {
		panic("jobs: duplicate handler for " + kind)
	}
	h := handlerSpec{fn: fn, lane: q.cfg.Lanes.list[0].Name, timeout: defaultTimeout, maxAttempts: q.cfg.MaxAttempts}
	for _, o := range opts {
		o.handler(&h)
	}
	if _, ok := q.cfg.Lanes.workers(h.lane); !ok {
		panic(fmt.Sprintf("jobs: %s uses lane %q, which is not configured", kind, h.lane))
	}
	if h.timeout <= 0 || h.maxAttempts < 1 || h.maxAttempts > maxAttemptsLimit {
		panic("jobs: invalid timeout or max attempts for " + kind)
	}
	q.handlers[kind] = h
}

// Schedule enqueues kind on every slot of the cron spec, read in loc. Slots missed while nothing ran are
// enqueued once, not once each.
func (q *Queue) Schedule(name, kind, spec string, loc *time.Location) {
	if q.started.Load() {
		panic("jobs: Schedule after Run")
	}
	if _, ok := q.handlers[kind]; !ok {
		panic("jobs: schedule " + name + " names unregistered kind " + kind)
	}
	if !kindPattern.MatchString(name) || !gronx.IsValid(spec) || loc == nil || len(spec) > 128 || len(loc.String()) > 64 {
		panic("jobs: invalid schedule " + name)
	}
	if _, dup := q.schedules[name]; dup {
		panic("jobs: duplicate schedule " + name)
	}
	q.schedules[name] = schedule{name: name, kind: kind, spec: spec, loc: loc}
}

var (
	ErrUnknownKind    = errors.New("jobs: no handler is registered for the kind")
	ErrPayloadTooBig  = errors.New("jobs: payload is larger than 256 KiB")
	ErrInvalidOptions = errors.New("jobs: invalid enqueue options")
	ErrNotFound       = errors.New("jobs: job not found")
	ErrNotAllowed     = errors.New("jobs: the job is not in a state that allows this")
)

// Enqueue adds a job in tx, so it is visible to workers only when tx commits. With Unique, a queued or
// running job with the same key wins and its id is returned.
func (q *Queue) Enqueue(ctx context.Context, tx db.Transaction, kind string, payload any, opts ...EnqueueOption) (ID, error) {
	h, ok := q.handlers[kind]
	if !ok {
		return ID{}, fmt.Errorf("%w: %s", ErrUnknownKind, kind)
	}
	raw := []byte("{}")
	if payload != nil {
		var err error
		if raw, err = json.Marshal(payload); err != nil {
			return ID{}, fmt.Errorf("jobs: encode %s payload: %w", kind, err)
		}
	}
	if len(raw) > maxPayloadBytes {
		return ID{}, ErrPayloadTooBig
	}
	now := wallNow(ctx)
	e := enqueueSpec{runAt: now, lane: h.lane, maxAttempts: h.maxAttempts}
	for _, o := range opts {
		o.enqueue(&e)
	}
	if _, ok := q.cfg.Lanes.workers(e.lane); !ok || e.priority < -1000 || e.priority > 1000 ||
		e.maxAttempts < 1 || e.maxAttempts > maxAttemptsLimit || utf8.RuneCountInString(e.uniqueKey) > maxUniqueKey {
		return ID{}, ErrInvalidOptions
	}
	return insertJob(ctx, tx, newJobRow{
		id: ids.NewOf[jobTag](), kind: kind, lane: e.lane, priority: e.priority, payload: string(raw),
		uniqueKey: e.uniqueKey, maxAttempts: e.maxAttempts, runAt: e.runAt.UTC().Truncate(time.Microsecond), now: now,
	})
}

func wallNow(ctx context.Context) time.Time {
	return clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond)
}

type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// Permanent fails the job now, without further attempts.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err: err}
}

type retryAfterError struct {
	after time.Duration
	err   error
}

func (e *retryAfterError) Error() string { return e.err.Error() }
func (e *retryAfterError) Unwrap() error { return e.err }

// RetryAfter retries the job after d instead of the backoff delay; it still spends an attempt.
func RetryAfter(d time.Duration, err error) error {
	if err == nil {
		err = errors.New("retry requested")
	}
	return &retryAfterError{after: max(0, d), err: err}
}

// Coded errors give last_error_code a stable value; other errors are recorded as "error".
type Coded interface{ ErrorCode() string }

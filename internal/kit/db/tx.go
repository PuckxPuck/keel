package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/go-jet/jet/v2/qrm"
	"github.com/google/uuid"
)

// Scope says which pool and which rules a transaction runs under (D29). The set is closed.
type Scope interface{ scope() scopeKind }

type scopeKind int

const (
	plainScope scopeKind = iota
	tenantScope
	operatorScope
	scopeCount
)

// Plain is the scope of apps without tenancy: the app pool, no tenant.
type Plain struct{}

// Tenant runs on the app pool with the tenant set by the tenancy part's begin hook.
type Tenant struct{}

// Operator runs on the operator pool, whose role bypasses row-level security.
type Operator struct{}

func (Plain) scope() scopeKind    { return plainScope }
func (Tenant) scope() scopeKind   { return tenantScope }
func (Operator) scope() scopeKind { return operatorScope }

// AppScope are the scopes InTx opens on the app pool.
type AppScope interface {
	Scope
	Plain | Tenant
}

// Tx is a transaction of scope S; stores accept the scope they are written for.
// The [0]S field makes each scope a distinct type, so no conversion turns one scope into another.
type Tx[S Scope] struct {
	_       [0]S
	tx      *sql.Tx
	dialect Dialect
	tenancy bool
}

// Q is what Jet statements run against (QueryContext and ExecContext).
func (t Tx[S]) Q() qrm.DB { return querier{t.tx} }

// querier hides the *sql.Tx so nothing but InTx can commit or roll back.
type querier struct{ tx *sql.Tx }

func (q querier) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return q.tx.QueryContext(ctx, query, args...)
}

func (q querier) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return q.tx.ExecContext(ctx, query, args...)
}

// Query and Exec complete qrm.DB; Jet calls only the context forms.
func (q querier) Query(query string, args ...any) (*sql.Rows, error) {
	return q.QueryContext(context.Background(), query, args...)
}

func (q querier) Exec(query string, args ...any) (sql.Result, error) {
	return q.ExecContext(context.Background(), query, args...)
}

func (t Tx[S]) Dialect() Dialect { return t.dialect }

// Tenancy is true when the database runs the tenancy part (its tables carry tenant_id under row-level security).
func (t Tx[S]) Tenancy() bool { return t.tenancy }

// Hook runs inside a transaction: Begin hooks right after BEGIN, BeforeCommit hooks right before COMMIT.
type Hook func(ctx context.Context, q qrm.DB) error

type hookSet struct {
	mu           sync.RWMutex
	begin        [scopeCount][]Hook
	beforeCommit [scopeCount][]Hook
}

// OnBegin registers h to run first in every transaction of scope S. Register during wiring, before serving;
// lint allows it only in internal/kit/tenancy.
func OnBegin[S Scope](d *DB, h Hook) {
	var s S
	d.hooks.mu.Lock()
	defer d.hooks.mu.Unlock()
	d.hooks.begin[s.scope()] = append(d.hooks.begin[s.scope()], h)
}

// BeforeCommit registers h to run last in every transaction of scope S; an error rolls the transaction back.
func BeforeCommit[S Scope](d *DB, h Hook) {
	var s S
	d.hooks.mu.Lock()
	defer d.hooks.mu.Unlock()
	d.hooks.beforeCommit[s.scope()] = append(d.hooks.beforeCommit[s.scope()], h)
}

func (h *hookSet) tenancy() bool {
	begin, _ := h.forScope(tenantScope)
	return len(begin) > 0
}

func (h *hookSet) forScope(k scopeKind) (begin, beforeCommit []Hook) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.begin[k], h.beforeCommit[k]
}

var (
	ErrNoTx                 = errors.New("db: no transaction in context")
	ErrNestedTx             = errors.New("db: a transaction is already open in this context")
	ErrTenancyNotConfigured = errors.New("db: tenant transactions need the tenancy begin hook")
	ErrNoOperatorAccess     = errors.New("db: operator access was not granted")
	ErrCommitUncertain      = errors.New("db: commit outcome unknown")
)

// OperatorAccess is the capability to open operator transactions (D29). Only Open mints it, so
// internal/app holds the one value and hands it to operator-realm wiring.
type OperatorAccess struct {
	d *DB
}

// LoginRole is the Postgres role the operator pool logs in as, from its URL.
func (a *OperatorAccess) LoginRole() string {
	if a == nil || a.d == nil {
		return ""
	}
	return a.d.operatorRole
}

type txOptions struct {
	readOnly  bool
	isolation sql.IsolationLevel
	retries   int
}

type TxOption func(*txOptions)

func ReadOnly() TxOption { return func(o *txOptions) { o.readOnly = true } }

func Isolation(level sql.IsolationLevel) TxOption {
	return func(o *txOptions) { o.isolation = level }
}

// Retry sets how many times a transaction is retried after a serialization failure or deadlock (default 2).
func Retry(n int) TxOption { return func(o *txOptions) { o.retries = max(0, n) } }

const (
	defaultRetries     = 2
	backoffBase        = 10 * time.Millisecond
	backoffCap         = 250 * time.Millisecond
	afterCommitTimeout = 30 * time.Second
)

// InTx runs fn in a transaction on the app pool and commits when fn returns nil.
// fn may run more than once when the database asks for a retry; keep side effects in AfterCommit.
func InTx[S AppScope](ctx context.Context, d *DB, fn func(ctx context.Context, tx Tx[S]) error, opts ...TxOption) error {
	var s S
	if s.scope() == tenantScope && !d.hooks.tenancy() {
		return ErrTenancyNotConfigured
	}
	return run(ctx, d, d.app, fn, opts)
}

// InAppTx runs fn on the app pool in a tenant transaction when ctx carries a tenant (WithTenant), else in
// a plain one, for kit code that serves apps with and without tenancy. Under tenancy a plain transaction
// sees no tenant's rows.
func InAppTx(ctx context.Context, d *DB, fn func(ctx context.Context, tx Transaction) error, opts ...TxOption) error {
	if _, ok := TenantOf(ctx); ok {
		return InTx(ctx, d, func(ctx context.Context, tx Tx[Tenant]) error { return fn(ctx, tx) }, opts...)
	}
	return InTx(ctx, d, func(ctx context.Context, tx Tx[Plain]) error { return fn(ctx, tx) }, opts...)
}

type tenantKey struct{}

// WithTenant sets the tenant that tenant transactions opened with ctx run as; kit/tenancy and the job
// worker set it, and audit, files and rate limits read it.
func WithTenant(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, tenantKey{}, id)
}

// TenantOf is the context's tenant.
func TenantOf(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(tenantKey{}).(uuid.UUID)
	return id, ok && id != uuid.Nil
}

// InOperatorTx runs fn in a transaction on the operator pool.
func InOperatorTx(ctx context.Context, access *OperatorAccess, fn func(ctx context.Context, tx Tx[Operator]) error, opts ...TxOption) error {
	if access == nil || access.d == nil || access.d.operator == nil {
		return ErrNoOperatorAccess
	}
	return run(ctx, access.d, access.d.operator, fn, opts)
}

type txKey struct{}

type txState struct {
	mu          sync.Mutex
	afterCommit []func(context.Context)
}

// AfterCommit registers fn to run once the transaction in ctx has committed. It never runs after a rollback
// or when the commit outcome is unknown. fn runs even if ctx is cancelled after the commit, with a
// bounded timeout of its own.
func AfterCommit(ctx context.Context, fn func(ctx context.Context)) error {
	st, ok := ctx.Value(txKey{}).(*txState)
	if !ok {
		return ErrNoTx
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.afterCommit = append(st.afterCommit, fn)
	return nil
}

func runAfterCommit(ctx context.Context, st *txState) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), afterCommitTimeout)
	defer cancel()
	for _, f := range st.afterCommit {
		f(ctx)
	}
}

func run[S Scope](ctx context.Context, d *DB, pool *sql.DB, fn func(context.Context, Tx[S]) error, opts []TxOption) error {
	if ctx.Value(txKey{}) != nil {
		return ErrNestedTx
	}
	o := txOptions{retries: defaultRetries}
	for _, opt := range opts {
		opt(&o)
	}
	var s S
	begin, beforeCommit := d.hooks.forScope(s.scope())
	tenancy := d.hooks.tenancy()
	for attempt := 0; ; attempt++ {
		st := &txState{}
		err := attemptTx(context.WithValue(ctx, txKey{}, st), d.dialect, tenancy, pool, fn, o, begin, beforeCommit)
		if err == nil {
			runAfterCommit(ctx, st)
			return nil
		}
		if attempt >= o.retries || !IsRetryable(err) {
			return err
		}
		if ctxErr := backoff(ctx, attempt); ctxErr != nil {
			return errors.Join(err, ctxErr)
		}
	}
}

func attemptTx[S Scope](ctx context.Context, dialect Dialect, tenancy bool, pool *sql.DB, fn func(context.Context, Tx[S]) error,
	o txOptions, begin, beforeCommit []Hook,
) error {
	sqlTx, err := pool.BeginTx(ctx, &sql.TxOptions{Isolation: o.isolation, ReadOnly: o.readOnly})
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		// Rollback takes no context, so it still runs when ctx is already cancelled, and during a panic.
		_ = sqlTx.Rollback() // the transaction's own error is the one to report
	}()

	q := querier{sqlTx}
	for _, h := range begin {
		if err := h(ctx, q); err != nil {
			return fmt.Errorf("begin hook: %w", err)
		}
	}
	if err := fn(ctx, Tx[S]{tx: sqlTx, dialect: dialect, tenancy: tenancy}); err != nil {
		return err
	}
	for _, h := range beforeCommit {
		if err := h(ctx, q); err != nil {
			return fmt.Errorf("before commit: %w", err)
		}
	}
	committed = true
	if err := sqlTx.Commit(); err != nil {
		return classifyCommit(err)
	}
	return nil
}

// classifyCommit separates a commit the database refused or never received (rolled back, maybe
// retryable) from one whose outcome is unknown because the connection failed while COMMIT was in flight.
func classifyCommit(err error) error {
	if serverError(err) || notSent(err) || errors.Is(err, sql.ErrTxDone) {
		return fmt.Errorf("commit: %w", err)
	}
	return fmt.Errorf("%w: %w", ErrCommitUncertain, err)
}

func backoff(ctx context.Context, attempt int) error {
	d := min(backoffCap, backoffBase<<attempt)
	d += time.Duration(rand.Int64N(int64(d) + 1)) //nolint:gosec // jitter, not secrecy
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

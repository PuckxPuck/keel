// Package tenancy is the optional tenancy part (D16): tenants, memberships, the tenant setting each app-pool
// transaction runs under, host resolution, access state and the catalogue check. Postgres only.
package tenancy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-jet/jet/v2/qrm"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/logx"
)

type tenantTag struct{}

type ID = ids.ID[tenantTag]

func ParseID(s string) (ID, error) { return ids.Parse[tenantTag](s) }

// Status is a tenant's access state (docs/tenancy.md section 6).
type Status string

const (
	Active    Status = "active"
	ReadOnly  Status = "read_only"
	Suspended Status = "suspended"
)

func (s Status) Valid() bool {
	switch s {
	case Active, ReadOnly, Suspended:
		return true
	}
	return false
}

type Tenant struct {
	ID           ID        `json:"id"`
	Slug         string    `json:"slug"`
	Name         string    `json:"name"`
	Status       Status    `json:"status"`
	StatusReason string    `json:"statusReason,omitempty"`
	Version      int       `json:"version"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

const (
	CodeNotAMember = "not_a_member"
	CodeReadOnly   = "tenant_read_only"
	CodeSuspended  = "tenant_suspended"
	CodeNotFound   = "tenant_not_found"
)

var (
	ErrNotFound    = errors.New("tenancy: tenant not found")
	ErrNotAMember  = errors.New("tenancy: not a member of this tenant")
	ErrSuspended   = errors.New("tenancy: the tenant is suspended")
	ErrReadOnly    = errors.New("tenancy: the tenant is read-only")
	ErrInvalid     = errors.New("tenancy: invalid tenant")
	ErrSlugTaken   = errors.New("tenancy: the slug is taken")
	ErrNoTenant    = errors.New("tenancy: a tenant transaction needs a tenant in its context")
	ErrSettingMove = errors.New("tenancy: the tenant setting changed inside the transaction")
	ErrNoReset     = errors.New("tenancy: open the database with db.Open and db.ResetTenant, so no connection carries a tenant to its next borrower")
)

func Mapper(err error) (*problem.Problem, bool) {
	switch {
	case errors.Is(err, ErrNotFound):
		return problem.New(http.StatusNotFound, CodeNotFound, "no such tenant"), true
	case errors.Is(err, ErrNotAMember):
		return problem.New(http.StatusForbidden, CodeNotAMember, "you are not a member of this tenant"), true
	case errors.Is(err, ErrSuspended):
		return problem.New(http.StatusForbidden, CodeSuspended, "this tenant is suspended"), true
	case errors.Is(err, ErrReadOnly):
		return problem.New(http.StatusForbidden, CodeReadOnly, "this tenant is read-only"), true
	case errors.Is(err, ErrSlugTaken):
		return problem.New(http.StatusConflict, "tenant_slug_taken", "another tenant uses this slug"), true
	case errors.Is(err, ErrInvalid):
		return problem.New(http.StatusUnprocessableEntity, problem.CodeValidationFailed, err.Error()), true
	}
	return nil, false
}

type ctxKey struct{}

// WithTenant makes t the tenant of ctx: tenant transactions opened with it run as t, log lines and audit
// rows carry it, and FromContext returns it.
func WithTenant(ctx context.Context, t Tenant) context.Context {
	ctx = db.WithTenant(ctx, t.ID.UUID())
	ctx = logx.With(ctx, slog.String(logx.KeyTenantID, t.ID.String()))
	return context.WithValue(ctx, ctxKey{}, t)
}

// FromContext is the request's tenant, once the tenant guard (or WithTenant) has loaded it.
func FromContext(ctx context.Context) (Tenant, bool) {
	t, ok := ctx.Value(ctxKey{}).(Tenant)
	if !ok {
		return Tenant{}, false
	}
	id, set := db.TenantOf(ctx)
	return t, set && id == t.ID.UUID()
}

// Config is the tenancy part of an app's configuration (APP_TENANCY_*).
type Config struct {
	// HostSuffix resolves <slug><suffix> to the tenant with that slug, for example ".example.app".
	HostSuffix string `env:"HOST_SUFFIX"`
	// CustomDomains resolves hosts listed in tenant_domains.
	CustomDomains bool `env:"CUSTOM_DOMAINS"`
}

var hostSuffix = regexp.MustCompile(`^(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

func (c Config) Validate(bool) error {
	if c.HostSuffix != "" && !hostSuffix.MatchString(c.HostSuffix) {
		return fmt.Errorf("host suffix %q must be a lower-case domain starting with a dot, such as .example.app", c.HostSuffix)
	}
	return nil
}

// Set reports whether any tenancy setting is given, for the check that refuses tenancy on MySQL.
func (c Config) Set() bool { return c.HostSuffix != "" || c.CustomDomains }

var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidSlug is true for a slug a tenant may take: a DNS label in lower case, since it names the
// tenant's host under the suffix.
func ValidSlug(s string) bool { return slugPattern.MatchString(s) }

func normaliseSlug(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

const setTenant = "select set_config('app.tenant_id', $1, true)"

var installed sync.Map

// Install registers, once per database, the hooks every tenant transaction runs (D30): the first
// statement sets the tenant from the context, transaction-local, and the last re-reads it and rolls
// back if anything changed it. New calls it, and so does internal/app when it opens a tenancy database.
// A database whose pool does not clear the setting on every checkout is ErrNoReset.
func Install(d *db.DB) error {
	if !d.ResetsTenant() {
		return ErrNoReset
	}
	if _, done := installed.LoadOrStore(d, true); done {
		return nil
	}
	db.OnBegin[db.Tenant](d, func(ctx context.Context, q qrm.DB) error {
		id, ok := db.TenantOf(ctx)
		if !ok {
			return ErrNoTenant
		}
		_, err := q.ExecContext(ctx, setTenant, id.String())
		return err
	})
	db.BeforeCommit[db.Tenant](d, func(ctx context.Context, q qrm.DB) error {
		id, ok := db.TenantOf(ctx)
		if !ok {
			return ErrNoTenant
		}
		rows, err := q.QueryContext(ctx, "select current_setting('app.tenant_id', true)")
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		var got *string
		if rows.Next() {
			if err := rows.Scan(&got); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if got == nil || *got != id.String() {
			return ErrSettingMove
		}
		return nil
	})
	return nil
}

// Runner opens, for kit services and job handlers under tenancy, a tenant transaction on the app pool.
// A context without a tenant is ErrNoTenant: it never falls back to another pool.
func Runner(d *db.DB) func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error {
	return func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error {
		if _, ok := db.TenantOf(ctx); !ok {
			return ErrNoTenant
		}
		return db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Tenant]) error { return fn(ctx, tx) })
	}
}

// OperatorRunner opens operator transactions for global work (kinds registered jobs.Global, sweeps
// across tenants). Only internal/app holds the access it needs, and wires it to that work by name.
func OperatorRunner(access *db.OperatorAccess) func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error {
	return func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error {
		return db.InOperatorTx(ctx, access, func(ctx context.Context, tx db.Tx[db.Operator]) error { return fn(ctx, tx) })
	}
}

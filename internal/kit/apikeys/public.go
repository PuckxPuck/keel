package apikeys

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/idempotency"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

const (
	// MinNotice is the least time between deprecating a public operation and its sunset.
	MinNotice           = 183 * 24 * time.Hour
	sinceLayout         = time.DateOnly
	headerAuthorization = "Authorization"
	bearerScheme        = "bearer "
	maxAuthorization    = 512
)

// SecurityScheme names the bearer scheme in the api realm's document.
const SecurityScheme = "apiKey"

// Document declares the api realm's bearer scheme; Expose attaches it to every operation that needs a key.
func Document(api huma.API) {
	oa := api.OpenAPI()
	if oa.Components == nil {
		oa.Components = &huma.Components{}
	}
	if oa.Components.SecuritySchemes == nil {
		oa.Components.SecuritySchemes = map[string]*huma.SecurityScheme{}
	}
	oa.Components.SecuritySchemes[SecurityScheme] = &huma.SecurityScheme{
		Type: "http", Scheme: "bearer", Description: "An API key, sent as Authorization: Bearer <key>",
	}
}

// Expose adjusts the api realm's copy of a public operation: the date it became public, the
// deprecation flag, and the bearer requirement unless its Need is public.
func Expose(op *huma.Operation) {
	m, _ := httpx.PublicOf(op)
	op.Extensions = maps.Clone(op.Extensions)
	if op.Extensions == nil {
		op.Extensions = map[string]any{}
	}
	op.Extensions["x-since"] = m.Since
	if !m.Deprecated.IsZero() {
		op.Deprecated = true
		op.Extensions["x-sunset"] = m.Sunset.Format(sinceLayout)
	}
	if need, ok := rbac.NeedOf(op); ok && !need.IsPublic() {
		op.Security = []map[string][]string{{SecurityScheme: {}}}
	}
}

// Check reports operations on the api realm that are not marked httpx.Public, carry a bad since date, a
// deprecation after now or too short a notice, or create (POST answering 201) without an
// Idempotency-Key.
func Check(api huma.API, now time.Time) error {
	var errs []error
	for _, op := range httpx.Operations(api) {
		name := op.Method + " " + op.Path + " (" + op.OperationID + ")"
		m, ok := httpx.PublicOf(op)
		if !ok {
			errs = append(errs, fmt.Errorf("%s is on the api realm without httpx.Public", name))
			continue
		}
		if _, err := time.Parse(sinceLayout, m.Since); err != nil {
			errs = append(errs, fmt.Errorf("%s: Public needs a since date such as 2026-10-22, got %q", name, m.Since))
		}
		if !m.Deprecated.IsZero() && m.Sunset.Sub(m.Deprecated) < MinNotice {
			errs = append(errs, fmt.Errorf("%s: the sunset must be at least six months after the deprecation", name))
		}
		if m.Deprecated.After(now) {
			errs = append(errs, fmt.Errorf("%s: deprecated from %s, which has not come; add Sunset in the release that deprecates", name,
				m.Deprecated.Format(sinceLayout)))
		}
		if op.Method == http.MethodPost && op.DefaultStatus == http.StatusCreated && !idempotency.IsRequired(op) {
			errs = append(errs, fmt.Errorf("%s creates on the public API and needs idempotency.Required", name))
		}
	}
	return errors.Join(errs...)
}

// Lifecycle sets Deprecation (RFC 9745) and Sunset (RFC 8594) on answers of deprecated operations.
func Lifecycle(ctx huma.Context, next func(huma.Context)) {
	if m, ok := httpx.PublicOf(ctx.Operation()); ok && !m.Deprecated.IsZero() {
		ctx.SetHeader("Deprecation", "@"+strconv.FormatInt(m.Deprecated.Unix(), 10))
		ctx.SetHeader("Sunset", m.Sunset.Format(http.TimeFormat))
	}
	next(ctx)
}

// Tenant is the tenant a key belongs to; the zero value is the one tenant of an app without tenancy.
type Tenant struct{ ID uuid.UUID }

// Locator is the first step of checking a presented key: it finds the key's tenant from the key id
// alone, before any tenant transaction exists. Under tenancy it reads a global
// api_key_tenants (key_id, tenant_id) table; found is false for a key it does not know.
type Locator interface {
	Locate(ctx context.Context, id ID) (t Tenant, found bool, err error)
}

// NoTenancy locates every key in the app's one tenant.
type NoTenancy struct{}

func (NoTenancy) Locate(context.Context, ID) (Tenant, bool, error) { return Tenant{}, true, nil }

// TenantLocator locates keys under tenancy in the global api_key_tenants table, which Create fills.
type TenantLocator struct{ DB *db.DB }

func (l TenantLocator) Locate(ctx context.Context, id ID) (Tenant, bool, error) {
	var t Tenant
	found := false
	err := db.InTx(ctx, l.DB, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		rows, err := tx.Q().QueryContext(ctx, "SELECT tenant_id FROM api_key_tenants WHERE key_id = $1", id)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		if found = rows.Next(); found {
			if err := rows.Scan(&t.ID); err != nil {
				return err
			}
		}
		return rows.Err()
	}, db.ReadOnly())
	return t, found, err
}

// TxRunner is the second step: it opens the transaction a located key is read and checked in, plain
// without tenancy and the key's tenant's under it.
type TxRunner func(ctx context.Context, t Tenant, fn func(ctx context.Context, tx db.Transaction) error) error

// TenantTx is the TxRunner under tenancy: the key's tenant's transaction on the app pool.
func TenantTx(d *db.DB) TxRunner {
	return func(ctx context.Context, t Tenant, fn func(ctx context.Context, tx db.Transaction) error) error {
		return db.InTx(db.WithTenant(ctx, t.ID), d, func(ctx context.Context, tx db.Tx[db.Tenant]) error { return fn(ctx, tx) })
	}
}

type keyCtx struct{}

// FromContext is the key the request authenticated with.
func FromContext(ctx context.Context) (Key, bool) {
	k, ok := ctx.Value(keyCtx{}).(Key)
	return k, ok
}

// Middleware authenticates the api realm: a bearer key only, never a cookie or a query string. A
// request without one stays anonymous for rbac.Enforce to judge; a presented key that does not check
// out is 401 invalid_api_key, so a client learns its key stopped working. locate and run find and open
// the key's tenant transaction.
func (s *Service) Middleware(api huma.API, locate Locator, run TxRunner) func(huma.Context, func(huma.Context)) {
	return resolver{s: s, api: api, locate: locate, run: run}.handle
}

type resolver struct {
	s      *Service
	api    huma.API
	locate Locator
	run    TxRunner
}

func (r resolver) handle(hctx huma.Context, next func(huma.Context)) {
	h := hctx.Header(headerAuthorization)
	if h == "" {
		next(hctx)
		return
	}
	if len(h) > maxAuthorization || len(h) <= len(bearerScheme) || !strings.EqualFold(h[:len(bearerScheme)], bearerScheme) {
		r.refuse(hctx)
		return
	}
	raw := strings.TrimSpace(h[len(bearerScheme):])
	id, _, err := r.s.format.Parse(raw)
	if err != nil {
		r.refuse(hctx)
		return
	}
	ctx := hctx.Context()
	got, tenant, err := r.resolve(ctx, ids.FromUUID[keyTag](id), raw)
	switch {
	case errors.Is(err, ErrInvalidKey):
		r.refuse(hctx)
		return
	case err != nil:
		logx.From(ctx).Error("resolve API key", "error", err)
		_ = huma.WriteErr(r.api, hctx, http.StatusServiceUnavailable, "", problem.New(http.StatusServiceUnavailable, problem.CodeUnavailable, "try again shortly"))
		return
	}
	keyID := got.Key.ID.UUID()
	if tenant.ID != uuid.Nil {
		ctx = db.WithTenant(ctx, tenant.ID)
	}
	ctx = rbac.WithPrincipal(ctx, got.Principal)
	ctx = audit.WithActor(ctx, audit.Actor{Type: audit.ActorAPIKey, ID: &keyID})
	ctx = context.WithValue(ctx, keyCtx{}, got.Key)
	ctx = logx.With(ctx, slog.String("api_key_id", keyID.String()))
	next(huma.WithContext(hctx, ctx))
}

// resolve locates the key's tenant, then checks the key in that tenant's transaction.
func (r resolver) resolve(ctx context.Context, id ID, raw string) (Resolved, Tenant, error) {
	tenant, found, err := r.locate.Locate(ctx, id)
	switch {
	case err != nil:
		return Resolved{}, Tenant{}, err
	case !found:
		return Resolved{}, Tenant{}, ErrInvalidKey
	}
	var got Resolved
	err = r.run(ctx, tenant, func(ctx context.Context, tx db.Transaction) error {
		var err error
		got, err = r.s.Resolve(ctx, tx, raw, httpx.ClientIP(ctx))
		return err
	})
	return got, tenant, err
}

func (r resolver) refuse(hctx huma.Context) {
	hctx.SetHeader("WWW-Authenticate", `Bearer error="invalid_token"`)
	_ = huma.WriteErr(r.api, hctx, http.StatusUnauthorized, "", problem.New(http.StatusUnauthorized, CodeInvalidKey, ErrInvalidKey.Error()))
}

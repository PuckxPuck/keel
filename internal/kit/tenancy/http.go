package tenancy

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

const metaReadOnly = "keel:allowWhileReadOnly"

type allowReadOnly struct{}

func (allowReadOnly) Apply(op *huma.Operation) { httpx.SetMeta(op, metaReadOnly, true) }

// AllowWhileReadOnly lets an unsafe operation, public ones included, through while its tenant is
// read-only (billing, export, sign-in and sign-out).
func AllowWhileReadOnly() httpx.Option { return allowReadOnly{} }

// hostTTL bounds how long a host keeps resolving to a tenant after its slug or domain changes; state
// and membership are read fresh on every request.
const (
	hostTTL       = 30 * time.Second
	maxHostsCache = 10000
)

type hostEntry struct {
	id    uuid.UUID
	found bool
	until time.Time
}

type hostCache struct {
	mu      sync.Mutex
	entries map[string]hostEntry
}

func newHostCache() *hostCache { return &hostCache{entries: map[string]hostEntry{}} }

func (c *hostCache) get(host string, now time.Time) (hostEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[host]
	return e, ok && now.Before(e.until)
}

func (c *hostCache) put(host string, e hostEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxHostsCache {
		clear(c.entries)
	}
	c.entries[host] = e
}

// Resolve puts the tenant the request's host names into the context: <slug><HostSuffix>, or a custom
// domain when CustomDomains is on. A host under the suffix that names no tenant is 404; any other
// host leaves the tenant to the session (auth.Sessions.Resolve).
func (s *Service) Resolve(api huma.API) func(huma.Context, func(huma.Context)) {
	return resolver{s: s, api: api}.handle
}

type resolver struct {
	s   *Service
	api huma.API
}

func (r resolver) handle(hctx huma.Context, next func(huma.Context)) {
	s, api := r.s, r.api
	host, ok := realm.Host(hctx.Host())
	if !ok {
		next(hctx)
		return
	}
	id, found, under, err := s.byHost(hctx.Context(), host)
	switch {
	case err != nil:
		logx.From(hctx.Context()).Error("resolve tenant host", "error", err)
		_ = huma.WriteErr(api, hctx, http.StatusServiceUnavailable, "", problem.New(http.StatusServiceUnavailable, problem.CodeUnavailable, "try again shortly"))
		return
	case !found && under:
		_ = huma.WriteErr(api, hctx, http.StatusNotFound, "", problem.New(http.StatusNotFound, CodeNotFound, "no such tenant"))
		return
	case found:
		hctx = huma.WithContext(hctx, context.WithValue(db.WithTenant(hctx.Context(), id), hostKey{}, id))
	}
	next(hctx)
}

// hostKey marks a tenant the host named, as against one the session carried.
type hostKey struct{}

// HostTenant is the tenant the request's host named (Resolve), whatever the context's tenant is now.
func HostTenant(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(hostKey{}).(uuid.UUID)
	return id, ok
}

// byHost reports the tenant host names, and whether host sits under the suffix at all.
func (s *Service) byHost(ctx context.Context, host string) (uuid.UUID, bool, bool, error) {
	slug, under := "", false
	if suffix := s.o.Config.HostSuffix; suffix != "" {
		if label, ok := strings.CutSuffix(host, suffix); ok && label != "" && !strings.Contains(label, ".") {
			slug, under = label, true
		}
	}
	if !under && !s.o.Config.CustomDomains {
		return uuid.Nil, false, false, nil
	}
	at := wallNow(ctx)
	if e, ok := s.hosts.get(host, at); ok {
		return e.id, e.found, under, nil
	}
	var t Tenant
	err := db.InTx(ctx, s.o.DB, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		if under {
			t, err = BySlug(ctx, tx, slug)
		} else {
			t, err = ByDomain(ctx, tx, host)
		}
		return err
	}, db.ReadOnly())
	found := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return uuid.Nil, false, under, err
	}
	s.hosts.put(host, hostEntry{id: t.ID.UUID(), found: found, until: at.Add(hostTTL)})
	return t.ID.UUID(), found, under, nil
}

// Guard enforces the request's tenant once the caller is known: a signed-in person must hold an active
// membership there (403 not_a_member), a suspended tenant answers 403 tenant_suspended to everyone, and
// a read-only one refuses unsafe methods with 403 tenant_read_only unless the operation is allowed. A
// person who is not a member still reaches the operations in Options.AllowNonMember, outside any
// tenant, and a session whose current tenant they left drops it instead. It loads the tenant fresh on
// every request and puts it in the context (FromContext, logs).
func (s *Service) Guard(api huma.API, principals rbac.Principals) func(huma.Context, func(huma.Context)) {
	return guard{s: s, api: api, principals: principals}.handle
}

type guard struct {
	s          *Service
	api        huma.API
	principals rbac.Principals
}

func (g guard) handle(hctx huma.Context, next func(huma.Context)) {
	s, api, principals := g.s, g.api, g.principals
	ctx := hctx.Context()
	id, ok := db.TenantOf(ctx)
	if !ok {
		next(hctx)
		return
	}
	var user *users.ID
	p, signedIn := principals.Principal(ctx)
	if signedIn && p.Kind() == rbac.SubjectUser {
		user = &p.UserID
	}
	var t Tenant
	var member bool
	err := db.InTx(ctx, s.o.DB, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		t, member, err = entry(ctx, tx, id, user)
		return err
	}, db.ReadOnly())
	if err != nil && !errors.Is(err, ErrNotFound) {
		logx.From(ctx).Error("load tenant", "error", err)
		_ = huma.WriteErr(api, hctx, http.StatusServiceUnavailable, "", problem.New(http.StatusServiceUnavailable, problem.CodeUnavailable, "try again shortly"))
		return
	}
	if err == nil && user != nil && !member && g.outside(hctx, next, id, p) {
		return
	}
	refusal := s.refusal(hctx.Operation(), hctx.Method(), t, err == nil, user == nil || member)
	if refusal != nil {
		p, _ := Mapper(refusal)
		_ = huma.WriteErr(api, hctx, p.Status, "", p)
		return
	}
	next(huma.WithContext(hctx, WithTenant(ctx, t)))
}

// outside serves a signed-in person who is not a member of the request's tenant, when the operation
// allows it or the tenant came from their own session, with no tenant and no grants; it reports
// whether it took the request.
func (g guard) outside(hctx huma.Context, next func(huma.Context), id uuid.UUID, p rbac.Principal) bool {
	ctx := hctx.Context()
	s, hasSession := auth.SessionFrom(ctx)
	own := ctx.Value(hostKey{}) == nil && hasSession && s.Tenant != nil && *s.Tenant == id
	if !own && !g.s.allowedNonMember(hctx.Operation().OperationID) {
		return false
	}
	if own {
		err := db.InTx(ctx, g.s.o.DB, func(ctx context.Context, tx db.Tx[db.Plain]) error { return leaveTenant(ctx, tx, s.ID, id) })
		if err != nil {
			logx.From(ctx).Error("leave tenant", "error", err)
			_ = huma.WriteErr(g.api, hctx, http.StatusServiceUnavailable, "", problem.New(http.StatusServiceUnavailable, problem.CodeUnavailable, "try again shortly"))
			return true
		}
	}
	ctx = rbac.WithPrincipal(db.WithTenant(ctx, uuid.Nil), rbac.NewPrincipal(p.UserID, p.Realm))
	next(huma.WithContext(hctx, ctx))
	return true
}

func (s *Service) refusal(op *huma.Operation, method string, t Tenant, found, member bool) error {
	switch {
	case !found || !member:
		return ErrNotAMember
	case t.Status == Suspended:
		return ErrSuspended
	case t.Status == ReadOnly && !safe(method):
		if allowed, _ := op.Metadata[metaReadOnly].(bool); allowed || s.allowedReadOnly(op.OperationID) {
			return nil
		}
		return ErrReadOnly
	}
	return nil
}

func safe(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

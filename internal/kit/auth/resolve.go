package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

const (
	CodeUnauthenticated    = "unauthenticated"
	CodeSessionExpired     = "session_expired"
	CodeMFARequired        = "mfa_required"
	CodeStepUpRequired     = "mfa_step_up_required"
	metaAllowRestricted    = "keel:allowRestricted"
	metaRecentMFA          = "keel:recentMFA"
	headerAuthorization    = "Authorization"
	bearerScheme           = "bearer "
	maxAuthorizationHeader = 512
)

// state is what Resolve learned about the request's credentials, for Start, End and Require.
type state struct {
	hctx      huma.Context
	mu        sync.Mutex
	realm     *realmSessions
	presented []byte
	session   *Session
	expired   bool
	userAgent string
}

func (st *state) setCookie(c *http.Cookie) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.hctx.AppendHeader("Set-Cookie", c.String())
}

type stateKey struct{}

func stateFrom(ctx context.Context) *state {
	st, _ := ctx.Value(stateKey{}).(*state)
	return st
}

// SessionFrom is the request's session: a user's (possibly restricted) or a device's.
func SessionFrom(ctx context.Context) (Session, bool) {
	st := stateFrom(ctx)
	if st == nil || st.session == nil {
		return Session{}, false
	}
	return *st.session, true
}

// PrincipalFrom is the request's principal, as rbac.FromContext reads it.
func PrincipalFrom(ctx context.Context) (rbac.Principal, bool) {
	return rbac.FromContext{}.Principal(ctx)
}

// Resolve reads the request's session for the operation's realm and puts the principal, the audit
// actor and the session in the context. It never refuses: a missing, expired or revoked session, or
// one of another realm, leaves the request anonymous for Require and Enforce to judge.
func (s *Sessions) Resolve() func(huma.Context, func(huma.Context)) {
	return resolver{s: s}.handle
}

type resolver struct{ s *Sessions }

func (r resolver) handle(hctx huma.Context, next func(huma.Context)) {
	rs := r.s.realms[httpx.RealmOf(hctx.Operation())]
	if rs == nil || r.s.db == nil {
		next(hctx)
		return
	}
	st := &state{hctx: hctx, realm: rs, userAgent: hctx.Header("User-Agent")}
	ctx := context.WithValue(hctx.Context(), stateKey{}, st)
	ctx = r.s.resolve(ctx, st)
	next(huma.WithContext(hctx, ctx))
}

func (s *Sessions) resolve(ctx context.Context, st *state) context.Context {
	raw, viaCookie := credentials(st.hctx, st.realm.cookie)
	if raw == "" {
		return ctx
	}
	if !viaCookie && s.devices != nil && strings.Contains(raw, ".") {
		return s.resolveDevice(ctx, st, raw)
	}
	hash, err := HashSecret(raw)
	if err != nil {
		s.forget(st, viaCookie)
		return ctx
	}
	st.presented = hash
	want := KindAPI
	if viaCookie {
		want = KindBrowser
	}
	var p rbac.Principal
	var found storedSession
	live, later := false, false
	_, hostTenant := db.TenantOf(ctx)
	err = db.InAppTx(ctx, s.db, func(ctx context.Context, tx db.Transaction) error {
		var ok bool
		var err error
		found, ok, err = sessionByHash(ctx, tx, hash)
		if err != nil || !ok || found.Realm != st.realm.Name || found.Kind != want {
			return err
		}
		now := s.now(ctx)
		if found.revokedAt != nil || !now.Before(found.IdleExpiresAt) || !now.Before(found.AbsoluteExpiresAt) {
			st.expired = true
			return nil
		}
		if now.Sub(found.LastSeenAt) >= touchEvery {
			found.LastSeenAt = now
			found.IdleExpiresAt = minTime(now.Add(st.realm.Idle), found.AbsoluteExpiresAt)
			if err := touchSession(ctx, tx, found.ID, found.LastSeenAt, found.IdleExpiresAt); err != nil {
				return err
			}
		}
		if found.AccessVersion != found.userVersion {
			if err := s.rotate(ctx, tx, st, &found); err != nil {
				return err
			}
		}
		// The session's tenant is known only now; its grants are read in that tenant's transaction.
		if later = !hostTenant && found.Tenant != nil; later {
			live = true
			return nil
		}
		p, err = s.principal(ctx, tx, st.realm, found)
		live = err == nil
		return err
	})
	if err == nil && later {
		ctx = db.WithTenant(ctx, *found.Tenant)
		err = db.InAppTx(ctx, s.db, func(ctx context.Context, tx db.Transaction) error {
			var err error
			p, err = s.principal(ctx, tx, st.realm, found)
			return err
		}, db.ReadOnly())
	}
	switch {
	case errors.Is(err, rbac.ErrUserDisabled), errors.Is(err, users.ErrNotFound):
		s.forget(st, viaCookie)
		return ctx
	case err != nil:
		logx.From(ctx).Error("resolve session", "error", err)
		return ctx
	case !live:
		s.forget(st, viaCookie)
		return ctx
	}
	sess := found.Session
	st.session = &sess
	uid := sess.UserID.UUID()
	ctx = rbac.WithPrincipal(ctx, p)
	ctx = audit.WithActor(ctx, audit.Actor{Type: audit.ActorUser, ID: &uid})
	return logx.With(ctx, slog.String(logx.KeyUserID, sess.UserID.String()))
}

// rotate follows a change to the user's access: a browser session gets a new token (the old one stops
// working) and a bearer session records the new version. When a concurrent request rotated first,
// this one is served on the reload alone and sets no cookie.
func (s *Sessions) rotate(ctx context.Context, tx db.Transaction, st *state, found *storedSession) error {
	found.AccessVersion = found.userVersion
	if found.Kind != KindBrowser {
		return setSessionVersion(ctx, tx, found.ID, found.userVersion)
	}
	raw, hash := NewSecret()
	rotated, err := rotateSession(ctx, tx, found.ID, st.presented, hash, found.userVersion)
	if err != nil || !rotated {
		return err
	}
	st.presented = hash
	cookie := s.cookie(st.realm, raw, found.AbsoluteExpiresAt)
	return db.AfterCommit(ctx, func(context.Context) { st.setCookie(cookie) })
}

// principal loads the session's principal. One waiting for its second factor gets the user's identity
// and no grants, so nothing it reaches can act on permissions whatever the middleware order.
func (s *Sessions) principal(ctx context.Context, tx db.Transaction, rs *realmSessions, sess storedSession) (rbac.Principal, error) {
	now := s.now(ctx)
	tenant, inTenant := db.TenantOf(ctx)
	key := principalKey{user: sess.UserID, realm: rs.Name, version: sess.userVersion, tenant: tenant}
	p, ok := s.cache.get(key, now)
	if !ok {
		var err error
		if p, err = rs.Loader.Load(ctx, tx, sess.UserID); err != nil {
			return rbac.Principal{}, err
		}
		s.cache.put(key, p, now)
	}
	if sess.Restricted() {
		p = rbac.NewPrincipal(p.UserID, p.Realm)
	}
	if inTenant {
		p = p.InTenant(tenant)
	}
	return p, nil
}

func (s *Sessions) resolveDevice(ctx context.Context, st *state, raw string) context.Context {
	var p rbac.Principal
	err := db.InAppTx(ctx, s.db, func(ctx context.Context, tx db.Transaction) error {
		var err error
		p, err = s.devices.ResolveDevice(ctx, tx, st.realm.Name, raw)
		return err
	})
	if err != nil {
		if !errors.Is(err, ErrInvalidToken) {
			logx.From(ctx).Error("resolve device", "error", err)
		}
		return ctx
	}
	id := p.Subject()
	if tenant, ok := db.TenantOf(ctx); ok {
		p = p.InTenant(tenant)
	}
	st.session = &Session{ID: id, Realm: st.realm.Name, Kind: KindDevice, MFA: MFANone}
	actor := audit.Actor{Type: audit.ActorDevice, ID: &id}
	if u, ok := p.OnBehalfOf(); ok {
		uid := u.UUID()
		actor.OnBehalfOf = &uid
	}
	ctx = rbac.WithPrincipal(ctx, p)
	ctx = audit.WithActor(ctx, actor)
	return logx.With(ctx, slog.String("device_id", id.String()))
}

// forget clears a cookie that names no live session, so the browser stops sending it.
func (s *Sessions) forget(st *state, viaCookie bool) {
	if viaCookie {
		st.setCookie(s.clearCookie(st.realm))
	}
}

// credentials reads the bearer token, else the realm's cookie. Tokens never come from a query string,
// and a realm without a cookie name reads no cookie.
func credentials(hctx huma.Context, cookie string) (raw string, viaCookie bool) {
	if h := hctx.Header(headerAuthorization); h != "" {
		if len(h) > maxAuthorizationHeader || len(h) <= len(bearerScheme) || !strings.EqualFold(h[:len(bearerScheme)], bearerScheme) {
			return "", false
		}
		return strings.TrimSpace(h[len(bearerScheme):]), false
	}
	if cookie == "" {
		return "", false
	}
	c, err := huma.ReadCookie(hctx, cookie)
	if err != nil {
		return "", false
	}
	return c.Value, true
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

type allowRestricted struct{}

func (allowRestricted) Apply(op *huma.Operation) { httpx.SetMeta(op, metaAllowRestricted, true) }

// AllowWhileRestricted lets a session that has not passed the realm's second factor reach the
// operation (completing MFA, signing out, reading /me).
func AllowWhileRestricted() httpx.Option { return allowRestricted{} }

type recentMFA time.Duration

func (r recentMFA) Apply(op *huma.Operation) { httpx.SetMeta(op, metaRecentMFA, time.Duration(r)) }

// RecentMFA asks for a session that passed the second factor within the last within (step-up for
// sensitive operations).
func RecentMFA(within time.Duration) httpx.Option { return recentMFA(within) }

// Require answers 401 session_expired when a non-public operation is called with a session that
// expired or was revoked; Enforce answers every other signed-out caller.
func (s *Sessions) Require(api huma.API, principals rbac.Principals) func(huma.Context, func(huma.Context)) {
	return requirer{api: api, principals: principals}.handle
}

type requirer struct {
	api        huma.API
	principals rbac.Principals
}

func (r requirer) handle(hctx huma.Context, next func(huma.Context)) {
	st := stateFrom(hctx.Context())
	need, _ := rbac.NeedOf(hctx.Operation())
	if st == nil || !st.expired || need.IsPublic() {
		next(hctx)
		return
	}
	if _, ok := r.principals.Principal(hctx.Context()); ok {
		next(hctx)
		return
	}
	_ = huma.WriteErr(r.api, hctx, http.StatusUnauthorized, "", problem.New(http.StatusUnauthorized, CodeSessionExpired, "your session has ended; sign in again"))
}

// Restrict refuses a restricted session everything but public operations and those marked
// AllowWhileRestricted, and enforces RecentMFA. It runs after Enforce.
func (s *Sessions) Restrict(api huma.API) func(huma.Context, func(huma.Context)) {
	return restricter{s: s, api: api}.handle
}

type restricter struct {
	s   *Sessions
	api huma.API
}

func (r restricter) handle(hctx huma.Context, next func(huma.Context)) {
	op := hctx.Operation()
	sess, ok := SessionFrom(hctx.Context())
	need, _ := rbac.NeedOf(op)
	if !ok || need.IsPublic() {
		next(hctx)
		return
	}
	if allowed, _ := op.Metadata[metaAllowRestricted].(bool); sess.Restricted() && !allowed {
		_ = huma.WriteErr(r.api, hctx, http.StatusForbidden, "", problem.New(http.StatusForbidden, CodeMFARequired, "complete the second sign-in step first"))
		return
	}
	if within, ok := op.Metadata[metaRecentMFA].(time.Duration); ok {
		if sess.MFAAt == nil || r.s.now(hctx.Context()).Sub(*sess.MFAAt) > within {
			_ = huma.WriteErr(r.api, hctx, http.StatusForbidden, "", problem.New(http.StatusForbidden, CodeStepUpRequired, "confirm your second factor again to continue"))
			return
		}
	}
	next(hctx)
}

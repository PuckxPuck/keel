// Package auth is sessions per realm: opaque tokens stored hashed, idle and absolute expiry, rotation
// on sign-in and on passing MFA, and the middleware that turns a request's cookie or bearer token into
// a principal.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

// Kind is how a session's token travels: a cookie (browser), a bearer token (api), or a device token.
type Kind string

const (
	KindBrowser Kind = "browser"
	KindAPI     Kind = "api"
	KindDevice  Kind = "device"
)

// MFAState is how far a session got with the realm's second factor.
type MFAState string

const (
	MFANone    MFAState = "none"
	MFAPending MFAState = "pending"
	MFAPassed  MFAState = "passed"
)

type Session struct {
	ID                uuid.UUID
	Realm             string
	UserID            users.ID
	Kind              Kind
	MFA               MFAState
	MFAAt             *time.Time
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	// AccessVersion is the user's access version (users.BumpAccess) the session was issued or last
	// rotated at.
	AccessVersion int64
	// Tenant is the session's current tenant under tenancy; requests on a host that names no tenant work in it.
	Tenant *uuid.UUID
}

// Restricted is true for a session that passed the first factor but not the second.
func (s Session) Restricted() bool { return s.MFA == MFAPending }

// Meta describes how a session starts. Kind defaults to browser; Provider names the sign-in method
// (password, dev, oidc, passkey) for the audit log. SecondFactorPassed is for a sign-in that proved two
// factors itself (a passkey with user verification): the session starts past the realm's MFA.
type Meta struct {
	Kind               Kind
	Provider           string
	SecondFactorPassed bool
}

// Started is a new session and its token: set as the cookie for browser sessions, returned to the
// client once for bearer sessions.
type Started struct {
	Session Session
	Token   string
}

// SecondFactor reports whether a user has a confirmed second factor, so optional-MFA realms hold
// enrolled users' sessions until they pass it.
type SecondFactor interface {
	Enrolled(ctx context.Context, tx db.Transaction, userID users.ID) (bool, error)
}

// Tenancy is the tenancy part's say in sign-in (kit/tenancy implements it); nil without tenancy.
type Tenancy interface {
	// Admit picks the tenant a sign-in to realm lands in (the host's, else the user's default) and checks
	// the user's membership there, answering ErrNoAccess when they hold none. scoped is false for a realm
	// without tenants, which keeps the role check.
	Admit(ctx context.Context, tx db.Transaction, realm string, userID users.ID) (tenant uuid.UUID, scoped bool, err error)
}

// DeviceResolver turns a device token into the device's principal; auth/devices implements it.
type DeviceResolver interface {
	ResolveDevice(ctx context.Context, tx db.Transaction, realm, raw string) (rbac.Principal, error)
}

type Options struct {
	DB    *db.DB
	Audit *audit.Recorder
	// Realms with sessions; each needs Idle, Absolute and a Loader.
	Realms []realm.Realm
	// Secure marks cookies Secure and gives them the __Host- prefix; on in production.
	Secure       bool
	CacheTTL     time.Duration
	SecondFactor SecondFactor
	Devices      DeviceResolver
	Tenancy      Tenancy
}

const (
	defaultCacheTTL = 5 * time.Second
	touchEvery      = time.Minute
	maxUserAgent    = 256
	hostPrefix      = "__Host-"
	// PendingFor is how long a session waiting for its second factor lives.
	PendingFor = 10 * time.Minute
)

type realmSessions struct {
	realm.Realm
	cookie string
}

// Sessions starts, resolves and ends sessions for every realm that has them.
type Sessions struct {
	db      *db.DB
	audit   *audit.Recorder
	realms  map[string]*realmSessions
	secure  bool
	cache   *principalCache
	second  SecondFactor
	devices DeviceResolver
	tenancy Tenancy
}

func NewSessions(opts Options) (*Sessions, error) {
	if opts.Audit == nil {
		return nil, errors.New("auth: sessions need an audit recorder")
	}
	ttl := opts.CacheTTL
	if ttl == 0 {
		ttl = defaultCacheTTL
	}
	s := &Sessions{
		db: opts.DB, audit: opts.Audit, realms: map[string]*realmSessions{}, secure: opts.Secure,
		cache: newPrincipalCache(ttl), second: opts.SecondFactor, devices: opts.Devices, tenancy: opts.Tenancy,
	}
	var errs []error
	for _, r := range opts.Realms {
		switch {
		case r.Idle <= 0 || r.Absolute < r.Idle:
			errs = append(errs, fmt.Errorf("auth: realm %s needs an idle expiry and an absolute expiry at least as long", r.Name))
		case r.Loader == nil:
			errs = append(errs, fmt.Errorf("auth: realm %s needs a principal loader", r.Name))
		}
		rs := &realmSessions{Realm: r}
		if r.Cookie != "" {
			rs.cookie = r.Cookie
			if s.secure {
				rs.cookie = hostPrefix + r.Cookie
			}
		}
		s.realms[r.Name] = rs
	}
	return s, errors.Join(errs...)
}

// CookieName is the realm's session cookie as browsers see it.
func (s *Sessions) CookieName(realmName string) string {
	if rs := s.realms[realmName]; rs != nil {
		return rs.cookie
	}
	return ""
}

var (
	ErrNoRealm   = errors.New("auth: the request has no realm with sessions")
	ErrNoSession = errors.New("auth: the request has no session")
	// ErrNoAccess is a sign-in by a user who holds no role in the realm; callers answer it like bad
	// credentials.
	ErrNoAccess = errors.New("auth: the user holds no role in the realm")
	// ErrInvalidToken is a credential that names nothing live; other resolver errors are failures.
	ErrInvalidToken = errors.New("auth: invalid token")
	errBadKind      = errors.New("auth: sessions start as browser or api")
	errNoCookie     = errors.New("auth: the realm takes no cookie sessions")
)

// Start opens a session for userID in the request's realm, refusing with ErrNoAccess a user who holds
// no role there. It deletes the session the request arrived with (no fixation) and audits
// session.start in tx. A browser session's cookie is set once tx commits. Under tenancy, a sign-in
// that lands in a tenant the request did not name also records session.entered on that tenant's trail
// once tx commits, since tx cannot write it.
func (s *Sessions) Start(ctx context.Context, tx db.Transaction, userID users.ID, meta Meta) (Started, error) {
	rs := s.realms[httpx.Realm(ctx)]
	if rs == nil {
		return Started{}, ErrNoRealm
	}
	kind := meta.Kind
	if kind == "" {
		kind = KindBrowser
	}
	if kind != KindBrowser && kind != KindAPI {
		return Started{}, errBadKind
	}
	if kind == KindBrowser && rs.cookie == "" {
		return Started{}, errNoCookie
	}
	tenant, err := s.admit(ctx, tx, rs.Name, userID)
	if err != nil {
		return Started{}, err
	}
	mfa, err := s.initialMFA(ctx, tx, rs, userID)
	if err != nil {
		return Started{}, err
	}
	var mfaAt *time.Time
	if meta.SecondFactorPassed {
		at := s.now(ctx)
		mfa, mfaAt = MFAPassed, &at
	}
	st := stateFrom(ctx)
	if err := s.dropPresented(ctx, tx, st); err != nil {
		return Started{}, err
	}
	started, err := s.open(ctx, tx, rs, userID, kind, mfa, mfaAt, tenant, "session.start", meta.Provider)
	if err != nil {
		return Started{}, err
	}
	if _, named := db.TenantOf(ctx); tenant != nil && !named {
		err = db.AfterCommit(ctx, func(ctx context.Context) { s.entered(ctx, started.Session, *tenant) })
	}
	return started, err
}

// entered records that a session landed in tenant, in that tenant's transaction.
func (s *Sessions) entered(ctx context.Context, sess Session, tenant uuid.UUID) {
	uid := sess.UserID.UUID()
	ctx = audit.WithActor(db.WithTenant(ctx, tenant), audit.Actor{Type: audit.ActorUser, ID: &uid})
	err := db.InTx(ctx, s.db, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		return s.audit.Record(ctx, tx, audit.Event{Action: "session.entered", Entity: "session", EntityID: sess.ID.String()})
	})
	if err != nil {
		logx.From(ctx).Error("audit session.entered", "error", err)
	}
}

// admit is the entry check of a sign-in: a role in the realm, or under tenancy an active membership in
// the tenant the sign-in lands in, which it returns.
func (s *Sessions) admit(ctx context.Context, tx db.Transaction, realmName string, userID users.ID) (*uuid.UUID, error) {
	if s.tenancy != nil {
		tenant, scoped, err := s.tenancy.Admit(ctx, tx, realmName, userID)
		if err != nil || scoped {
			return &tenant, err
		}
	}
	member, err := rbac.HoldsAnyRole(ctx, tx, realmName, userID)
	if err != nil {
		return nil, err
	}
	if !member {
		return nil, ErrNoAccess
	}
	return nil, nil
}

// PassMFA rotates the request's restricted session into one that passed the second factor. It also
// serves as a step-up for a session that passed before, refreshing the time of the last pass.
func (s *Sessions) PassMFA(ctx context.Context, tx db.Transaction, method string) (Started, error) {
	st := stateFrom(ctx)
	if st == nil || st.session == nil || st.session.Kind == KindDevice {
		return Started{}, ErrNoSession
	}
	cur := *st.session
	if err := s.dropPresented(ctx, tx, st); err != nil {
		return Started{}, err
	}
	at := s.now(ctx)
	return s.open(ctx, tx, st.realm, cur.UserID, cur.Kind, MFAPassed, &at, cur.Tenant, "session.mfa_passed", method)
}

// Switch rotates the request's session into tenant (a new token, the second-factor state kept) and
// drops the user's cached principals. The caller checks the user's membership there first.
func (s *Sessions) Switch(ctx context.Context, tx db.Transaction, tenant uuid.UUID) (Started, error) {
	st := stateFrom(ctx)
	if st == nil || st.session == nil || st.session.Kind == KindDevice {
		return Started{}, ErrNoSession
	}
	cur := *st.session
	if err := s.dropPresented(ctx, tx, st); err != nil {
		return Started{}, err
	}
	s.cache.forgetUser(cur.UserID)
	return s.open(ctx, tx, st.realm, cur.UserID, cur.Kind, cur.MFA, cur.MFAAt, &tenant, "session.tenant_switched", "")
}

func (s *Sessions) initialMFA(ctx context.Context, tx db.Transaction, rs *realmSessions, userID users.ID) (MFAState, error) {
	switch rs.MFA {
	case realm.MFARequired:
		return MFAPending, nil
	case realm.MFAOptional:
		if s.second == nil {
			return MFANone, nil
		}
		enrolled, err := s.second.Enrolled(ctx, tx, userID)
		if err != nil || !enrolled {
			return MFANone, err
		}
		return MFAPending, nil
	case realm.MFAOff, "":
	}
	return MFANone, nil
}

type sessionImage struct {
	Kind     Kind     `json:"kind"`
	MFA      MFAState `json:"mfa"`
	Provider string   `json:"provider,omitempty"`
	Realm    string   `json:"realm"`
}

func (s *Sessions) open(ctx context.Context, tx db.Transaction, rs *realmSessions, userID users.ID, kind Kind, mfa MFAState,
	mfaAt *time.Time, tenant *uuid.UUID, action, provider string,
) (Started, error) {
	version, err := users.AccessVersion(ctx, tx, userID)
	if err != nil {
		return Started{}, err
	}
	now := s.now(ctx)
	raw, hash := NewSecret()
	sess := Session{
		ID: ids.New(), Realm: rs.Name, UserID: userID, Kind: kind, MFA: mfa, MFAAt: mfaAt,
		CreatedAt: now, LastSeenAt: now,
		IdleExpiresAt: now.Add(rs.Idle), AbsoluteExpiresAt: now.Add(rs.Absolute), AccessVersion: version, Tenant: tenant,
	}
	if mfa == MFAPending {
		sess.AbsoluteExpiresAt = minTime(sess.AbsoluteExpiresAt, now.Add(PendingFor))
		sess.IdleExpiresAt = minTime(sess.IdleExpiresAt, sess.AbsoluteExpiresAt)
	}
	if err := insertSession(ctx, tx, sess, hash, clientIP(ctx), userAgent(ctx)); err != nil {
		return Started{}, err
	}
	uid := userID.UUID()
	actx := audit.WithActor(ctx, audit.Actor{Type: audit.ActorUser, ID: &uid})
	if err := s.audit.Record(actx, tx, audit.Event{
		Action: action, Entity: "session", EntityID: sess.ID.String(),
		After: sessionImage{Kind: kind, MFA: mfa, Provider: provider, Realm: rs.Name},
	}); err != nil {
		return Started{}, err
	}
	if kind == KindBrowser {
		if st := stateFrom(ctx); st != nil {
			cookie := s.cookie(rs, raw, sess.AbsoluteExpiresAt)
			if err := db.AfterCommit(ctx, func(context.Context) { st.setCookie(cookie) }); err != nil {
				return Started{}, err
			}
		}
	}
	return Started{Session: sess, Token: raw}, nil
}

// dropPresented deletes whatever session the request's token named, valid or not.
func (s *Sessions) dropPresented(ctx context.Context, tx db.Transaction, st *state) error {
	if st == nil || st.presented == nil {
		return nil
	}
	return deleteByHash(ctx, tx, st.presented)
}

// End deletes the request's session and clears its cookie (sign-out).
func (s *Sessions) End(ctx context.Context, tx db.Transaction) error {
	st := stateFrom(ctx)
	if st == nil || st.session == nil || st.session.Kind == KindDevice {
		return ErrNoSession
	}
	sess := *st.session
	if err := s.dropPresented(ctx, tx, st); err != nil {
		return err
	}
	if err := s.audit.Record(ctx, tx, audit.Event{
		Action: "session.end", Entity: "session", EntityID: sess.ID.String(),
		Before: sessionImage{Kind: sess.Kind, MFA: sess.MFA, Realm: sess.Realm},
	}); err != nil {
		return err
	}
	if sess.Kind == KindBrowser {
		return db.AfterCommit(ctx, func(context.Context) { st.setCookie(s.clearCookie(st.realm)) })
	}
	return nil
}

type revokedImage struct {
	Sessions int64  `json:"sessions"`
	Realm    string `json:"realm,omitempty"`
}

// RevokeUser revokes every session of the user in every realm (password reset, disabling, incidents).
func (s *Sessions) RevokeUser(ctx context.Context, tx db.Transaction, userID users.ID) error {
	return s.revoke(ctx, tx, userID, revokeScope{})
}

// RevokeOthers revokes every session of the user except keep (enabling a second factor).
func (s *Sessions) RevokeOthers(ctx context.Context, tx db.Transaction, userID users.ID, keep uuid.UUID) error {
	return s.revoke(ctx, tx, userID, revokeScope{except: &keep})
}

func (s *Sessions) revoke(ctx context.Context, tx db.Transaction, userID users.ID, scope revokeScope) error {
	n, err := revokeSessions(ctx, tx, userID, scope, s.now(ctx))
	if err != nil {
		return err
	}
	return s.audit.Record(ctx, tx, audit.Event{
		Action: "user.sessions_revoked", Entity: "user", EntityID: userID.String(),
		After: revokedImage{Sessions: n, Realm: scope.realm},
	})
}

// UserAccessChanged revokes the user's sessions in the realm when the change left them without a role
// there; under tenancy only those working in the context's tenant. It makes Sessions an rbac.Hook.
func (s *Sessions) UserAccessChanged(ctx context.Context, tx db.Transaction, realmName string, user users.ID) error {
	holds, err := rbac.HoldsAnyRole(ctx, tx, realmName, user)
	if err != nil || holds {
		return err
	}
	scope := revokeScope{realm: realmName}
	if id, ok := db.TenantOf(ctx); ok && tx.Tenancy() {
		scope.tenant = &id
	}
	return s.revoke(ctx, tx, user, scope)
}

var _ rbac.Hook = (*Sessions)(nil)

func (s *Sessions) now(ctx context.Context) time.Time {
	return clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond)
}

func (s *Sessions) cookie(rs *realmSessions, value string, expires time.Time) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is set from the production profile
		Name: rs.cookie, Value: value, Path: "/", Expires: expires,
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteLaxMode,
	}
}

func (s *Sessions) clearCookie(rs *realmSessions) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is set from the production profile
		Name: rs.cookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteLaxMode,
	}
}

func clientIP(ctx context.Context) *string {
	ip := httpx.ClientIP(ctx)
	if !ip.IsValid() {
		return nil
	}
	v := ip.String()
	return &v
}

func userAgent(ctx context.Context) *string {
	st := stateFrom(ctx)
	if st == nil || st.userAgent == "" {
		return nil
	}
	ua := st.userAgent
	if !utf8.ValidString(ua) {
		return nil
	}
	if utf8.RuneCountInString(ua) > maxUserAgent {
		ua = string([]rune(ua)[:maxUserAgent])
	}
	return &ua
}

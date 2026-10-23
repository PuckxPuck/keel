package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/auth/devlogin"
	"github.com/PuckxPuck/keel/internal/kit/auth/password"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/auth/tokens"
	"github.com/PuckxPuck/keel/internal/kit/auth/totp"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

type SessionType string

const (
	SessionCookie SessionType = "cookie"
	SessionBearer SessionType = "bearer"
)

type signInInput struct {
	Body struct {
		Email    string      `json:"email" maxLength:"254"`
		Password string      `json:"password" maxLength:"128" doc:"At most 128 characters and 512 bytes"`
		Session  SessionType `json:"session,omitempty" enum:"cookie,bearer" default:"cookie" doc:"cookie for browsers; bearer returns a token for other clients"`
	}
}

type devLoginInput struct {
	Body struct {
		Email   string      `json:"email" maxLength:"254"`
		Session SessionType `json:"session,omitempty" enum:"cookie,bearer" default:"cookie"`
	}
}

// SignedIn is a new session. Token is set only for bearer sessions; browsers get the cookie.
type SignedIn struct {
	MFA       auth.MFAState `json:"mfa" enum:"none,pending,passed" doc:"pending: complete the second factor before anything else"`
	Token     string        `json:"token,omitempty"`
	ExpiresAt time.Time     `json:"expiresAt"`
}

type codeInput struct {
	Body struct {
		Code string `json:"code" minLength:"1" maxLength:"64"`
	}
}

type emailInput struct {
	Body struct {
		Email string `json:"email" maxLength:"254"`
	}
}

type tokenInput struct {
	Body struct {
		Token string `json:"token" maxLength:"128"`
	}
}

type tokenPasswordInput struct {
	Body struct {
		Token    string `json:"token" maxLength:"128"`
		Password string `json:"password" maxLength:"128" doc:"At most 128 characters and 512 bytes"`
	}
}

// Me is the caller. A session waiting for its second factor gets only mfaRequired, kind, realm and mfa.
type Me struct {
	Kind        rbac.SubjectKind `json:"kind" enum:"user,apikey,device"`
	User        *users.User      `json:"user"`
	Realm       string           `json:"realm"`
	MFA         auth.MFAState    `json:"mfa" enum:"none,pending,passed"`
	MFARequired bool             `json:"mfaRequired" doc:"true until the session passes the second factor; nothing else is shown until then"`
	Roles       []rbac.HeldRole  `json:"roles"`
	Permissions []rbac.Code      `json:"permissions"`
}

type Enrolment = totp.Enrolment

type Confirmed struct {
	RecoveryCodes []string      `json:"recoveryCodes" doc:"Shown once; each works once"`
	MFA           auth.MFAState `json:"mfa" enum:"none,pending,passed"`
	Token         string        `json:"token,omitempty"`
}

var (
	authClass = ratelimit.Class(ratelimit.ClassAuth)
	tagAuth   = []string{"auth"}
)

func (w *wiring) registerAuth(api huma.API) {
	post := func(id, path, summary string) huma.Operation {
		return huma.Operation{OperationID: id, Method: http.MethodPost, Path: path, Summary: summary, Tags: tagAuth}
	}
	httpx.Register(api, post("signIn", "/auth/sign-in", "Sign in with email and password"), w.signIn, rbac.Public(), authClass)
	httpx.Register(api, post("signOut", "/auth/sign-out", "End the current session"), w.signOut,
		rbac.SignedIn(), ratelimit.Class(ratelimit.ClassAPIWrite), auth.AllowWhileRestricted())
	httpx.Register(api, huma.Operation{OperationID: "getMe", Method: http.MethodGet, Path: "/me", Summary: "The caller, their roles and permissions", Tags: tagAuth},
		w.me, rbac.SignedIn(), ratelimit.Class(ratelimit.ClassAPIRead), auth.AllowWhileRestricted(), httpx.Public(publicSince))
	httpx.Register(api, post("enrolTotp", "/auth/mfa/totp/enrol", "Start setting up an authenticator app"), w.enrolTotp,
		rbac.SignedIn(), authClass, auth.AllowWhileRestricted())
	httpx.Register(api, post("confirmTotp", "/auth/mfa/totp/confirm", "Finish setting up an authenticator app"), w.confirmTotp,
		rbac.SignedIn(), authClass, auth.AllowWhileRestricted())
	httpx.Register(api, post("verifyTotp", "/auth/mfa/totp/verify", "Pass the second factor with an authenticator code"), w.verifyTotp,
		rbac.SignedIn(), authClass, auth.AllowWhileRestricted())
	httpx.Register(api, post("useRecoveryCode", "/auth/mfa/recovery", "Pass the second factor with a recovery code"), w.useRecovery,
		rbac.SignedIn(), authClass, auth.AllowWhileRestricted())
	httpx.Register(api, post("requestPasswordReset", "/auth/password/reset-request", "Send a password reset link"), w.requestReset, rbac.Public(), authClass)
	httpx.Register(api, post("resetPassword", "/auth/password/reset", "Set a new password with a reset link"), w.resetPassword, rbac.Public(), authClass)
	httpx.Register(api, post("requestEmailVerification", "/auth/email/verification", "Send a link that confirms the signed-in user's email address"),
		w.requestVerification, rbac.SignedIn(), authClass)
	httpx.Register(api, post("verifyEmail", "/auth/email/verify", "Confirm an email address with a verification link"), w.verifyEmail, rbac.Public(), authClass)
	httpx.Register(api, post("acceptInvite", "/auth/invites/accept", "Accept an invite and set a password"), w.acceptInvite, rbac.Public(), authClass)
	dev := post("devLogin", "/auth/dev-login", "Sign in as any user (local development only)")
	dev.Middlewares = huma.Middlewares{devlogin.Middleware}
	httpx.Register(api, dev, w.devLogin, rbac.Public(), authClass)
}

// personSession is the request's own session, when it is a person's.
func personSession(ctx context.Context) (auth.Session, error) { //nolint:unused // used by the passkey and tenancy parts
	s, ok := auth.SessionFrom(ctx)
	if !ok || s.Kind == auth.KindDevice {
		return auth.Session{}, problem.New(http.StatusForbidden, problem.CodeForbidden, "only a person's session can do this")
	}
	return s, nil
}

var errUnavailable = problem.New(http.StatusServiceUnavailable, problem.CodeUnavailable, "try again shortly")

func (w *wiring) ready() error {
	if w.db == nil {
		return errUnavailable
	}
	return nil
}

func (w *wiring) signIn(ctx context.Context, in *signInInput) (*httpx.One[SignedIn], error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	if w.passwords == nil {
		return nil, problem.New(http.StatusNotFound, problem.CodeNotFound, "password sign-in is not enabled")
	}
	var out SignedIn
	_, err := w.passwords.Authenticate(ctx, w.db, in.Body.Email, in.Body.Password, func(ctx context.Context, tx db.Transaction, u users.User) error {
		var err error
		out, err = w.start(ctx, tx, u.ID, in.Body.Session, "password")
		return err
	})
	if errors.Is(err, auth.ErrNoAccess) {
		err = password.ErrInvalidCredentials
	}
	return one(out, err)
}

func (w *wiring) devLogin(ctx context.Context, in *devLoginInput) (*httpx.One[SignedIn], error) {
	if !w.cfg.DevLogin || !devlogin.Allowed(ctx) {
		return nil, problem.New(http.StatusNotFound, problem.CodeNotFound, "no such route")
	}
	if err := w.ready(); err != nil {
		return nil, err
	}
	var out SignedIn
	err := db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		u, err := users.ByEmail(ctx, tx, in.Body.Email)
		if err != nil {
			return err
		}
		out, err = w.start(ctx, tx, u.ID, in.Body.Session, "dev")
		return err
	})
	if errors.Is(err, auth.ErrNoAccess) {
		err = problem.New(http.StatusUnprocessableEntity, problem.CodeForbidden, "the user holds no role in this realm; grant one with user:grant")
	}
	return one(out, err)
}

func (w *wiring) start(ctx context.Context, tx db.Transaction, userID users.ID, st SessionType, provider string) (SignedIn, error) {
	kind := auth.KindBrowser
	if st == SessionBearer {
		kind = auth.KindAPI
	}
	started, err := w.sessions.Start(ctx, tx, userID, auth.Meta{Kind: kind, Provider: provider})
	if err != nil {
		return SignedIn{}, err
	}
	return signedIn(started), nil
}

func signedIn(s auth.Started) SignedIn {
	out := SignedIn{MFA: s.Session.MFA, ExpiresAt: s.Session.AbsoluteExpiresAt}
	if s.Session.Kind == auth.KindAPI {
		out.Token = s.Token
	}
	return out
}

func (w *wiring) signOut(ctx context.Context, _ *struct{}) (*httpx.NoContent, error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	return noContent(db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		return w.sessions.End(ctx, tx)
	}))
}

func (w *wiring) me(ctx context.Context, _ *struct{}) (*httpx.One[Me], error) {
	p, ok := auth.PrincipalFrom(ctx)
	if !ok {
		return nil, auth.ErrNoSession
	}
	out := Me{Kind: p.Kind(), Realm: p.Realm, MFA: auth.MFANone, Permissions: p.Permissions(), Roles: []rbac.HeldRole{}}
	if s, ok := auth.SessionFrom(ctx); ok {
		out.MFA = s.MFA
		out.MFARequired = s.Restricted()
	}
	if out.Permissions == nil {
		out.Permissions = []rbac.Code{}
	}
	if p.Kind() != rbac.SubjectUser || out.MFARequired {
		return httpx.OneOf(out), nil
	}
	if err := w.ready(); err != nil {
		return nil, err
	}
	err := db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		u, err := users.Get(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		out.User = &u
		roles, err := rbac.RolesOf(ctx, tx, p.Realm, p.UserID)
		if roles != nil {
			out.Roles = roles
		}
		return err
	}, db.ReadOnly())
	return one(out, err)
}

// signedInUser is the user behind the request's own session; devices and keys have none.
func (w *wiring) signedInUser(ctx context.Context) (users.ID, error) {
	if err := w.ready(); err != nil {
		return users.ID{}, err
	}
	if w.totp == nil {
		return users.ID{}, problem.New(http.StatusNotFound, problem.CodeNotFound, "second factors are not enabled")
	}
	s, ok := auth.SessionFrom(ctx)
	if !ok || s.Kind == auth.KindDevice {
		return users.ID{}, problem.New(http.StatusForbidden, problem.CodeForbidden, "only a person's session can do this")
	}
	return s.UserID, nil
}

func (w *wiring) enrolTotp(ctx context.Context, _ *struct{}) (*httpx.One[Enrolment], error) {
	userID, err := w.signedInUser(ctx)
	if err != nil {
		return nil, err
	}
	var out Enrolment
	err = db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		u, err := users.Get(ctx, tx, userID)
		if err != nil {
			return err
		}
		out, err = w.totp.Enrol(ctx, tx, u)
		return err
	})
	return one(out, err)
}

// mfaLimits count every code attempt by user and, from a known address, by user and address.
func (w *wiring) mfaLimits(ctx context.Context, userID users.ID) []auth.Limit {
	out := []auth.Limit{{Key: auth.Key("mfa-user", userID.String()), Rate: mfaPerUser}}
	if addr, known := auth.Address(ctx); known {
		out = append(out, auth.Limit{Key: auth.Key("mfa", userID.String(), addr), Rate: mfaPerAccount, Reset: true})
	}
	return out
}

func mfaStreakLimit(userID users.ID) auth.Limit {
	return auth.Limit{Key: auth.Key("mfa-streak", userID.String()), Rate: mfaStreak, Reset: true}
}

// secondFactor counts the attempt (D31), checks a code with check and passes the session's MFA. A
// wrong code rolls back and extends the user's run of failures; the run reaching mfaStreak revokes
// every session of the user. A right code clears the run. With revokeOthers (enabling a factor), the
// user's other sessions end.
func (w *wiring) secondFactor(ctx context.Context, method string, revokeOthers bool, check func(ctx context.Context, tx db.Transaction, userID users.ID) ([]string, error)) (Confirmed, error) {
	userID, err := w.signedInUser(ctx)
	if err != nil {
		return Confirmed{}, err
	}
	limits := w.mfaLimits(ctx, userID)
	if err := w.failures.Attempt(ctx, limits...); err != nil {
		return Confirmed{}, err
	}
	var out Confirmed
	err = db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		codes, err := check(ctx, tx, userID)
		if err != nil {
			return err
		}
		started, err := w.sessions.PassMFA(ctx, tx, method)
		if err != nil {
			return err
		}
		if revokeOthers {
			if err := w.sessions.RevokeOthers(ctx, tx, userID, started.Session.ID); err != nil {
				return err
			}
		}
		s := signedIn(started)
		out = Confirmed{RecoveryCodes: codes, MFA: s.MFA, Token: s.Token}
		return nil
	})
	switch {
	case errors.Is(err, totp.ErrInvalidCode):
		return Confirmed{}, errors.Join(err, w.mfaFailed(ctx, userID))
	case err != nil:
		return Confirmed{}, err
	}
	if err := w.failures.Succeeded(ctx, append(limits, mfaStreakLimit(userID))...); err != nil {
		logx.From(ctx).Warn("clear second factor failures", "error", err)
	}
	if out.RecoveryCodes == nil {
		out.RecoveryCodes = []string{}
	}
	return out, nil
}

func (w *wiring) mfaFailed(ctx context.Context, userID users.ID) error {
	reached, err := w.failures.Fail(ctx, mfaStreakLimit(userID))
	if err != nil || !reached {
		return err
	}
	return db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		if err := w.audit.Record(ctx, tx, audit.Event{Action: "mfa.failure_limit_reached", Entity: "user", EntityID: userID.String()}); err != nil {
			return err
		}
		return w.sessions.RevokeUser(ctx, tx, userID)
	})
}

func (w *wiring) confirmTotp(ctx context.Context, in *codeInput) (*httpx.One[Confirmed], error) {
	return one(w.secondFactor(ctx, "totp", true, func(ctx context.Context, tx db.Transaction, userID users.ID) ([]string, error) {
		return w.totp.Confirm(ctx, tx, userID, in.Body.Code)
	}))
}

func (w *wiring) verifyTotp(ctx context.Context, in *codeInput) (*httpx.One[Confirmed], error) {
	return one(w.secondFactor(ctx, "totp", false, func(ctx context.Context, tx db.Transaction, userID users.ID) ([]string, error) {
		return nil, w.totp.Verify(ctx, tx, userID, in.Body.Code)
	}))
}

func (w *wiring) useRecovery(ctx context.Context, in *codeInput) (*httpx.One[Confirmed], error) {
	return one(w.secondFactor(ctx, "recovery_code", false, func(ctx context.Context, tx db.Transaction, userID users.ID) ([]string, error) {
		return nil, w.totp.UseRecovery(ctx, tx, userID, in.Body.Code)
	}))
}

// requestFloor is the least time a link request takes, so known and unknown addresses answer alike.
const requestFloor = 250 * time.Millisecond

// requestReset answers 204 after at least requestFloor whether or not the account exists, and whether
// or not this address or account asked too often; only the link is withheld. The link is handed to
// the notifier in the transaction that issues it.
func (w *wiring) requestReset(ctx context.Context, in *emailInput) (*httpx.NoContent, error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	if w.passwords == nil {
		return nil, problem.New(http.StatusNotFound, problem.CodeNotFound, "password sign-in is not enabled")
	}
	defer waitFloor(ctx, now(ctx))
	email, valid := normalisedEmail(in.Body.Email)
	if !valid {
		return &httpx.NoContent{}, nil
	}
	limits := []auth.Limit{{Key: auth.Key("reset-request", email), Rate: resetRequests}}
	if addr, known := auth.Address(ctx); known {
		limits = append(limits, auth.Limit{Key: auth.Key("reset-request-address", addr), Rate: resetPerAddress})
	}
	var throttled *auth.ThrottledError
	switch err := w.failures.Attempt(ctx, limits...); {
	case errors.As(err, &throttled):
		return &httpx.NoContent{}, nil
	case err != nil:
		return nil, err
	}
	return noContent(db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		u, err := users.ByEmail(ctx, tx, email)
		if errors.Is(err, users.ErrNotFound) || (err == nil && u.Status != users.Active) {
			return nil
		}
		if err != nil {
			return err
		}
		// On a tenant's host only its members get a link, so its trail never names anyone else.
		if member, err := w.memberHere(ctx, tx, u.ID); err != nil || !member {
			return err
		}
		raw, err := tokens.Issue(ctx, tx, u.ID, tokens.PasswordReset, w.cfg.Tokens.TTLFor(tokens.PasswordReset))
		if err != nil {
			return err
		}
		if err := w.audit.Record(ctx, tx, audit.Event{Action: "password.reset_requested", Entity: "user", EntityID: u.ID.String()}); err != nil {
			return err
		}
		return w.notifier.SendReset(ctx, tx, u, raw)
	}))
}

// waitFloor returns once requestFloor has passed since start, or ctx ends.
func waitFloor(ctx context.Context, start time.Time) {
	t := time.NewTimer(requestFloor - now(ctx).Sub(start))
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// requestVerification sends the signed-in user a link that confirms their address; an address already
// confirmed gets none. The answer is 204 either way.
func (w *wiring) requestVerification(ctx context.Context, _ *struct{}) (*httpx.NoContent, error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	s, ok := auth.SessionFrom(ctx)
	if !ok || s.Kind == auth.KindDevice {
		return nil, problem.New(http.StatusForbidden, problem.CodeForbidden, "only a person's session can do this")
	}
	if err := w.failures.Attempt(ctx, auth.Limit{Key: auth.Key("verify-request", s.UserID.String()), Rate: verifyRequests}); err != nil {
		return nil, err
	}
	return noContent(db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		u, err := users.Get(ctx, tx, s.UserID)
		if err != nil || u.EmailVerifiedAt != nil {
			return err
		}
		raw, err := tokens.Issue(ctx, tx, u.ID, tokens.VerifyEmail, w.cfg.Tokens.TTLFor(tokens.VerifyEmail))
		if err != nil {
			return err
		}
		if err := w.audit.Record(ctx, tx, audit.Event{Action: "user.email_verification_requested", Entity: "user", EntityID: u.ID.String()}); err != nil {
			return err
		}
		return w.notifier.SendVerify(ctx, tx, u, raw)
	}))
}

func normalisedEmail(raw string) (string, bool) {
	email, err := users.NormaliseEmail(raw)
	return email, err == nil
}

// policy is the password rule of the request's realm.
func (w *wiring) policy(ctx context.Context) password.Policy {
	for _, r := range configuredRealms(w.cfg) {
		if r.Name == httpx.Realm(ctx) {
			return w.cfg.Password.Policy(r.MFA == realm.MFARequired)
		}
	}
	return w.cfg.Password.Policy(false)
}

// resetPassword sets the password, marks the address verified (the link proved it) and revokes every
// session of the user.
func (w *wiring) resetPassword(ctx context.Context, in *tokenPasswordInput) (*httpx.NoContent, error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	if w.passwords == nil {
		return nil, problem.New(http.StatusNotFound, problem.CodeNotFound, "password sign-in is not enabled")
	}
	hashed, err := w.passwords.Prepare(ctx, in.Body.Password, w.policy(ctx))
	if err != nil {
		return nil, err
	}
	return noContent(db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		userID, err := tokens.Consume(ctx, tx, in.Body.Token, tokens.PasswordReset)
		if err != nil {
			return err
		}
		member, err := w.memberHere(ctx, tx, userID)
		if err != nil {
			return err
		}
		if !member {
			return tokens.ErrInvalid
		}
		if err := w.passwords.Set(ctx, tx, userID, hashed); err != nil {
			return err
		}
		if err := users.MarkEmailVerified(ctx, tx, userID, now(ctx)); err != nil {
			return err
		}
		return w.sessions.RevokeUser(ctx, tx, userID)
	}))
}

func (w *wiring) verifyEmail(ctx context.Context, in *tokenInput) (*httpx.NoContent, error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	return noContent(db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		userID, err := tokens.Consume(ctx, tx, in.Body.Token, tokens.VerifyEmail)
		if err != nil {
			return err
		}
		if err := users.MarkEmailVerified(ctx, tx, userID, now(ctx)); err != nil {
			return err
		}
		return w.audit.Record(ctx, tx, audit.Event{Action: "user.email_verified", Entity: "user", EntityID: userID.String()})
	}))
}

func (w *wiring) acceptInvite(ctx context.Context, in *tokenPasswordInput) (*httpx.NoContent, error) {
	if err := w.ready(); err != nil {
		return nil, err
	}
	if w.passwords == nil {
		return nil, problem.New(http.StatusNotFound, problem.CodeNotFound, "password sign-in is not enabled")
	}
	hashed, err := w.passwords.Prepare(ctx, in.Body.Password, w.policy(ctx))
	if err != nil {
		return nil, err
	}
	return noContent(db.InAppTx(ctx, w.db, func(ctx context.Context, tx db.Transaction) error {
		userID, err := tokens.Consume(ctx, tx, in.Body.Token, tokens.Invite)
		if err != nil {
			return err
		}
		if err := w.passwords.Set(ctx, tx, userID, hashed); err != nil {
			return err
		}
		if err := users.MarkEmailVerified(ctx, tx, userID, now(ctx)); err != nil {
			return err
		}
		return w.audit.Record(ctx, tx, audit.Event{Action: "user.invite_accepted", Entity: "user", EntityID: userID.String()})
	}))
}

func one[T any](v T, err error) (*httpx.One[T], error) {
	if err != nil {
		return nil, err
	}
	return httpx.OneOf(v), nil
}

func noContent(err error) (*httpx.NoContent, error) {
	if err != nil {
		return nil, err
	}
	return &httpx.NoContent{}, nil
}

func now(ctx context.Context) time.Time {
	return clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond)
}

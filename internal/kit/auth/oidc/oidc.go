// Package oidc signs people in with an OpenID Connect provider: the authorisation code flow with PKCE
// S256, state and nonce kept server-side and single use (kit/oauthstate), the state also bound to the
// browser by a cookie, and the ID token checked for issuer, audience, expiry, issue time and nonce.
// A provider subject is linked to an existing user only when the app's Corroborator agrees, and an
// identity signs in only on the realm it was linked in.
package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/oauthstate"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

// Config is APP_OIDC_*. EmailTrusted marks the provider as trusted for verified email addresses, which
// the default Corroborator needs before it links a new subject to an existing user.
type Config struct {
	Issuer       string        `env:"ISSUER"`
	ClientID     string        `env:"CLIENT_ID"`
	ClientSecret config.Secret `env:"CLIENT_SECRET"`
	Scopes       []string      `env:"SCOPES" envDefault:"openid,email,profile"`
	EmailTrusted bool          `env:"EMAIL_TRUSTED"`
}

func (c Config) Enabled() bool { return c.Issuer != "" }

func (c Config) Validate(prod bool) error {
	if !c.Enabled() {
		return nil
	}
	var errs []error
	u, err := url.Parse(c.Issuer)
	switch {
	case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.RawQuery != "" || u.Fragment != "":
		errs = append(errs, errors.New("OIDC issuer must be an absolute URL"))
	case prod && u.Scheme != "https":
		errs = append(errs, errors.New("OIDC issuer must be https in production"))
	}
	if c.ClientID == "" {
		errs = append(errs, errors.New("OIDC client id is required with an issuer"))
	}
	if !slices.Contains(c.Scopes, gooidc.ScopeOpenID) {
		errs = append(errs, errors.New("OIDC scopes must include openid"))
	}
	return errors.Join(errs...)
}

const (
	purpose = "oidc_sign_in"
	// stateProvider names the provider in oauth_states, whose column is short; identities record the issuer.
	stateProvider = "oidc"
	// CookieName binds a round trip to the browser that started it; auth adds __Host- in production.
	CookieName = "oidc_state"
	hostPrefix = "__Host-"
	// issuedSkew is how far an ID token's issue time may sit in the future, and maxAge how old it may be.
	issuedSkew = 5 * time.Minute
	maxAge     = 10 * time.Minute
	maxClaim   = 255
	// failedFor is how long a failed discovery answers every sign-in before the provider is asked again.
	failedFor = 30 * time.Second
)

var (
	ErrInvalidState = errors.New("oidc: the sign-in is invalid or has expired; start again")
	ErrToken        = errors.New("oidc: the provider's answer could not be verified")
	ErrUnavailable  = errors.New("oidc: the provider could not be reached")
	// ErrRefused is a verified person who cannot sign in here: no user with their address, a link the
	// Corroborator refused, a user already linked to another subject of the provider, or a disabled user.
	ErrRefused    = errors.New("oidc: this account cannot sign in here")
	ErrNotEnabled = errors.New("oidc: OIDC sign-in is not enabled here")
)

const (
	CodeInvalidState = "oidc_state_invalid"
	CodeUnverified   = "oidc_token_invalid"
	CodeRefused      = "oidc_sign_in_refused"
)

func Mapper(err error) (*problem.Problem, bool) {
	switch {
	case errors.Is(err, ErrInvalidState):
		return problem.New(http.StatusBadRequest, CodeInvalidState, ErrInvalidState.Error()), true
	case errors.Is(err, ErrToken):
		return problem.New(http.StatusUnauthorized, CodeUnverified, ErrToken.Error()), true
	case errors.Is(err, ErrUnavailable):
		return problem.New(http.StatusServiceUnavailable, problem.CodeUnavailable, "the sign-in provider could not be reached; try again shortly"), true
	case errors.Is(err, ErrRefused):
		return problem.New(http.StatusForbidden, CodeRefused, ErrRefused.Error()), true
	case errors.Is(err, ErrNotEnabled):
		return problem.New(http.StatusNotFound, problem.CodeNotFound, "OIDC sign-in is not enabled"), true
	}
	return nil, false
}

// Claims are what a verified ID token says about the person.
type Claims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// Corroborator decides whether a subject seen for the first time may be linked to the existing user
// whose address matches its email claim.
type Corroborator interface {
	Corroborate(ctx context.Context, tx db.Transaction, c Claims, u users.User) (bool, error)
}

// VerifiedEmail is the default Corroborator: it links only when the provider is trusted for verified
// addresses and the token says this one is verified.
type VerifiedEmail struct{ Trusted bool }

func (v VerifiedEmail) Corroborate(_ context.Context, _ db.Transaction, c Claims, _ users.User) (bool, error) {
	return v.Trusted && c.EmailVerified, nil
}

type Options struct {
	Config Config
	// Realms are the realms OIDC sign-in works on.
	Realms []string
	// RedirectURL is the callback operation's absolute URL.
	RedirectURL string
	Tx          oauthstate.Runner
	Audit       *audit.Recorder
	// Corroborate defaults to VerifiedEmail{Trusted: Config.EmailTrusted}.
	Corroborate Corroborator
	// HTTPClient carries discovery, key and token requests; nil means a client with a 15s timeout.
	HTTPClient *http.Client
	// Secure gives the binding cookie Secure and the __Host- prefix; on in production.
	Secure bool
}

// Service runs sign-ins against one provider. Discovery happens on first use, not at startup.
type Service struct {
	cfg         Config
	realms      []string
	redirect    string
	tx          oauthstate.Runner
	audit       *audit.Recorder
	corroborate Corroborator
	client      *http.Client
	secure      bool

	mu       sync.Mutex
	provider *gooidc.Provider
	failed   time.Time
	failure  error
}

func New(o Options) (*Service, error) {
	switch {
	case !o.Config.Enabled() || o.Config.ClientID == "":
		return nil, errors.New("oidc: an issuer and a client id are required")
	case o.RedirectURL == "" || o.Tx == nil || o.Audit == nil || len(o.Realms) == 0:
		return nil, errors.New("oidc: realms, a redirect URL, a transaction runner and an audit recorder are required")
	}
	s := &Service{
		cfg: o.Config, realms: slices.Clone(o.Realms), redirect: o.RedirectURL, tx: o.Tx, audit: o.Audit, corroborate: o.Corroborate,
		client: o.HTTPClient, secure: o.Secure,
	}
	if s.corroborate == nil {
		s.corroborate = VerifiedEmail{Trusted: o.Config.EmailTrusted}
	}
	if s.client == nil {
		s.client = &http.Client{Timeout: 15 * time.Second}
	}
	return s, nil
}

// Enabled is true when OIDC sign-in works on the named realm.
func (s *Service) Enabled(realm string) bool { return slices.Contains(s.realms, realm) }

// discover fetches the provider's metadata once. Callers hold no transaction: the provider may be slow.
// A failure answers every caller for failedFor, so a provider that is down costs one wait, not one each.
func (s *Service) discover(ctx context.Context) (*gooidc.Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.provider != nil {
		return s.provider, nil
	}
	now := clock.Wall(ctx).Now()
	if s.failure != nil && now.Sub(s.failed) < failedFor {
		return nil, s.failure
	}
	p, err := s.fetch(ctx)
	if err != nil {
		s.failed, s.failure = now, err
		return nil, err
	}
	s.provider, s.failure = p, nil
	return p, nil
}

func (s *Service) fetch(ctx context.Context) (*gooidc.Provider, error) {
	// The provider's key set refreshes outside this request, so it must not inherit its cancellation.
	p, err := gooidc.NewProvider(gooidc.ClientContext(context.WithoutCancel(ctx), s.client), s.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: discovery: %w", ErrUnavailable, err)
	}
	var meta struct {
		JWKS string `json:"jwks_uri"`
	}
	if err := p.Claims(&meta); err != nil || meta.JWKS == "" {
		return nil, fmt.Errorf("%w: discovery has no jwks_uri", ErrUnavailable)
	}
	return p, nil
}

func (s *Service) oauth2(p *gooidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID: s.cfg.ClientID, ClientSecret: s.cfg.ClientSecret.Reveal(), Endpoint: p.Endpoint(),
		RedirectURL: s.redirect, Scopes: s.cfg.Scopes,
	}
}

// Started is the provider URL to send the browser to and the cookie that binds the round trip to it.
type Started struct {
	URL    string
	Cookie *http.Cookie
}

// Start discovers the provider, then records a state, nonce and PKCE verifier in a transaction of its
// own and returns the provider's authorisation URL. returnTo must already have passed
// httpx.SafeReturnPath.
func (s *Service) Start(ctx context.Context, returnTo string) (Started, error) {
	if !s.Enabled(httpx.Realm(ctx)) {
		return Started{}, ErrNotEnabled
	}
	p, err := s.discover(ctx)
	if err != nil {
		return Started{}, err
	}
	var st oauthstate.Started
	err = s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		var err error
		st, err = oauthstate.Put(ctx, tx, oauthstate.New{Purpose: purpose, Provider: stateProvider, ReturnTo: returnTo, Nonce: true})
		return err
	})
	if err != nil {
		return Started{}, err
	}
	authURL := s.oauth2(p).AuthCodeURL(st.State, gooidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier))
	return Started{URL: authURL, Cookie: s.cookie(st.State, int(oauthstate.DefaultTTL.Seconds()))}, nil
}

// ClearCookie expires the binding cookie once the callback has used it.
func (s *Service) ClearCookie() *http.Cookie { return s.cookie("", -1) }

// CookieName is the binding cookie as browsers see it.
func (s *Service) CookieName() string {
	if s.secure {
		return hostPrefix + CookieName
	}
	return CookieName
}

func (s *Service) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is set from the production profile
		Name: s.CookieName(), Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteLaxMode,
	}
}

// Finish checks that state is the one bound to this browser (bound, the cookie's value), spends it
// (once, whatever happens next), exchanges code with the PKCE verifier and verifies the ID token. It
// returns the claims and the return path given to Start. No transaction is held while the provider is
// asked anything.
func (s *Service) Finish(ctx context.Context, state, bound, code string) (Claims, string, error) {
	if state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(bound)) != 1 {
		return Claims{}, "", ErrInvalidState
	}
	p, err := s.discover(ctx)
	if err != nil {
		return Claims{}, "", err
	}
	var taken oauthstate.Taken
	var refused error
	err = s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		var err error
		taken, err = oauthstate.Take(ctx, tx, state, purpose, stateProvider)
		if errors.Is(err, oauthstate.ErrInvalid) {
			refused = ErrInvalidState
			return nil
		}
		return err
	})
	if err = errors.Join(err, refused); err != nil {
		return Claims{}, "", err
	}
	if code == "" {
		return Claims{}, "", ErrToken
	}
	tok, err := s.oauth2(p).Exchange(context.WithValue(ctx, oauth2.HTTPClient, s.client), code, oauth2.VerifierOption(taken.Verifier))
	if err != nil {
		return Claims{}, "", exchangeError(err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return Claims{}, "", fmt.Errorf("%w: no id_token", ErrToken)
	}
	c, err := s.verify(ctx, p, raw, taken)
	if err != nil {
		return Claims{}, "", err
	}
	return c, taken.ReturnTo, nil
}

func (s *Service) verify(ctx context.Context, p *gooidc.Provider, raw string, taken oauthstate.Taken) (Claims, error) {
	now := clock.Wall(ctx).Now()
	// The provider's verifier accepts the signing algorithms it advertises and shares its cached key set.
	verifier := p.Verifier(&gooidc.Config{ClientID: s.cfg.ClientID, Now: func() time.Time { return now }})
	idt, err := verifier.Verify(gooidc.ClientContext(ctx, s.client), raw)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrToken, err)
	}
	var extra struct {
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
		Name          string `json:"name"`
		AZP           string `json:"azp"`
	}
	if err := idt.Claims(&extra); err != nil {
		return Claims{}, fmt.Errorf("%w: claims: %w", ErrToken, err)
	}
	switch {
	case !taken.NonceMatches(idt.Nonce):
		return Claims{}, fmt.Errorf("%w: nonce", ErrToken)
	case idt.IssuedAt.IsZero() || idt.IssuedAt.After(now.Add(issuedSkew)) || idt.IssuedAt.Before(now.Add(-maxAge)):
		return Claims{}, fmt.Errorf("%w: issued at", ErrToken)
	case len(idt.Audience) > 1 && extra.AZP != s.cfg.ClientID:
		return Claims{}, fmt.Errorf("%w: authorised party", ErrToken)
	case idt.Subject == "" || len(idt.Subject) > maxClaim || len(idt.Issuer) > maxClaim:
		return Claims{}, fmt.Errorf("%w: subject", ErrToken)
	}
	return Claims{
		Issuer: idt.Issuer, Subject: idt.Subject, Email: extra.Email, Name: extra.Name,
		EmailVerified: extra.EmailVerified == true || extra.EmailVerified == "true",
	}, nil
}

// exchangeError keeps only the OAuth error code: response bodies can echo request values.
func exchangeError(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) && re.ErrorCode != "" {
		return fmt.Errorf("%w: token endpoint: %s", ErrToken, re.ErrorCode)
	}
	return fmt.Errorf("%w: token endpoint", ErrUnavailable)
}

type identityTag struct{}

type identityImage struct {
	UserID   users.ID `json:"userId"`
	Realm    string   `json:"realm"`
	Provider string   `json:"provider"`
	Subject  string   `json:"subject"`
}

// Link returns the user the verified claims sign in as on the request's realm: the user already linked
// to the subject there, or the existing user with the claimed address when the Corroborator agrees,
// linking them in tx. A user already linked to another subject of the same provider is refused, so an
// address the provider gave to someone new does not reach the old account. It never creates users.
func (s *Service) Link(ctx context.Context, tx db.Transaction, c Claims) (users.ID, error) {
	realm := httpx.Realm(ctx)
	if !s.Enabled(realm) {
		return users.ID{}, ErrNotEnabled
	}
	id, found, err := linkedUser(ctx, tx, realm, c.Issuer, c.Subject, false)
	if err != nil {
		return users.ID{}, err
	}
	if found {
		return active(ctx, tx, id)
	}
	email, err := users.NormaliseEmail(c.Email)
	if err != nil {
		return users.ID{}, ErrRefused
	}
	u, err := users.ByEmail(ctx, tx, email)
	switch {
	case errors.Is(err, users.ErrNotFound):
		return users.ID{}, ErrRefused
	case err != nil:
		return users.ID{}, err
	case u.Status != users.Active:
		return users.ID{}, ErrRefused
	}
	other, err := hasOtherSubject(ctx, tx, u.ID, c.Issuer, c.Subject)
	if err != nil {
		return users.ID{}, err
	}
	if other {
		return users.ID{}, ErrRefused
	}
	ok, err := s.corroborate.Corroborate(ctx, tx, c, u)
	if err != nil {
		return users.ID{}, err
	}
	if !ok {
		return users.ID{}, ErrRefused
	}
	return s.link(ctx, tx, u.ID, realm, c, email)
}

// link records the identity. A concurrent first sign-in of the same subject may have linked it first;
// then this one signs in as that link says.
func (s *Service) link(ctx context.Context, tx db.Transaction, userID users.ID, realm string, c Claims, email string) (users.ID, error) {
	q := "INSERT INTO identities (id, user_id, realm, provider, subject, email_at_link, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (realm, provider, subject) DO NOTHING"
	if tx.Dialect() == db.MySQL {
		q = "INSERT INTO identities (id, user_id, realm, provider, subject, email_at_link, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE id = id"
	}
	identity := ids.NewOf[identityTag]()
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), identity, userID, realm, c.Issuer, c.Subject, email,
		clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return users.ID{}, fmt.Errorf("oidc: link identity: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return users.ID{}, err
	}
	if n == 0 {
		winner, found, err := linkedUser(ctx, tx, realm, c.Issuer, c.Subject, true)
		switch {
		case err != nil:
			return users.ID{}, err
		case !found || winner != userID:
			return users.ID{}, ErrRefused
		}
		return userID, nil
	}
	if err := s.audit.Record(ctx, tx, audit.Event{
		Action: "identity.linked", Entity: "identity", EntityID: identity.String(),
		After: identityImage{UserID: userID, Realm: realm, Provider: c.Issuer, Subject: c.Subject},
	}); err != nil {
		return users.ID{}, err
	}
	return userID, nil
}

// linkedUser reads the identity; shared reads the latest committed row (after losing a link race).
func linkedUser(ctx context.Context, tx db.Transaction, realm, provider, subject string, shared bool) (users.ID, bool, error) {
	q := "SELECT user_id FROM identities WHERE realm = ? AND provider = ? AND subject = ?"
	if shared {
		q += " FOR SHARE"
	}
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), q), realm, provider, subject)
	if err != nil {
		return users.ID{}, false, fmt.Errorf("oidc: load identity: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return users.ID{}, false, rows.Err()
	}
	var id users.ID
	if err := rows.Scan(&id); err != nil {
		return users.ID{}, false, err
	}
	return id, true, rows.Close()
}

func hasOtherSubject(ctx context.Context, tx db.Transaction, userID users.ID, provider, subject string) (bool, error) {
	q := db.Rebind(tx.Dialect(), "SELECT id FROM identities WHERE user_id = ? AND provider = ? AND subject <> ? LIMIT 1")
	rows, err := tx.Q().QueryContext(ctx, q, userID, provider, subject)
	if err != nil {
		return false, fmt.Errorf("oidc: load identities: %w", err)
	}
	defer func() { _ = rows.Close() }()
	found := rows.Next()
	return found, errors.Join(rows.Err(), rows.Close())
}

func active(ctx context.Context, tx db.Transaction, id users.ID) (users.ID, error) {
	u, err := users.Get(ctx, tx, id)
	if err != nil {
		return users.ID{}, err
	}
	if u.Status != users.Active {
		return users.ID{}, ErrRefused
	}
	return u.ID, nil
}

// RedirectURL is the callback URL under publicURL and path.
func RedirectURL(publicURL, path string) string {
	return strings.TrimSuffix(publicURL, "/") + path
}

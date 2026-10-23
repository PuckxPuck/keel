// Package connections holds OAuth 2.0 connections to other services made by the app's users, with
// tokens encrypted at rest and refreshed under a lease so a rotated refresh token is never lost.
package connections

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/netguard"
	"github.com/PuckxPuck/keel/internal/kit/oauthstate"
	"github.com/PuckxPuck/keel/internal/kit/seal"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

type connectionTag struct{}

type ID = ids.ID[connectionTag]

// Config is APP_CONNECTION_*.
type Config struct {
	Keys []config.Secret `env:"KEYS"`
}

// Validate checks the keys given; without keys the app runs no connections (New needs a keyring).
func (c Config) Validate(prod bool) error {
	var errs []error
	for i, k := range c.Keys {
		errs = append(errs, config.RequireStrong(fmt.Sprintf("connection key %d", i+1), k, prod))
	}
	return errors.Join(errs...)
}

// Account is the provider-side account a connection belongs to.
type Account struct {
	ExternalID string
	Scopes     []string
}

// Provider is an app-side adapter for one service.
type Provider interface {
	Name() string
	// OAuth2 is the client configuration: client id and secret, endpoints, redirect URL and scopes.
	OAuth2() *oauth2.Config
	// APIOrigins are the origins (https://api.example.com) the connection's client may send the token to.
	APIOrigins() []string
	// Account identifies the account the user connected, calling the provider with client.
	Account(ctx context.Context, client *http.Client) (Account, error)
	// Revoke revokes the token at the provider, or returns ErrRevokeUnsupported.
	Revoke(ctx context.Context, client *http.Client, token *oauth2.Token) error
}

// AuthOptioner is a Provider that adds options to its authorisation URL (oauth2.AccessTypeOffline for Google).
type AuthOptioner interface {
	AuthCodeOptions() []oauth2.AuthCodeOption
}

// TxRunner opens the transactions the service works in: plain, or tenant transactions under tenancy.
type TxRunner = oauthstate.Runner

func PlainTx(d *db.DB) TxRunner { return oauthstate.PlainTx(d) }

type Options struct {
	Tx        TxRunner
	Keys      *seal.Keyring
	Providers []Provider
	// HTTPClient carries token requests, revocations and API calls; nil means a netguard client (public
	// addresses only) with a 30s timeout. Its Timeout also bounds each provider call.
	HTTPClient *http.Client
	// StateTTL bounds the authorisation round trip (default 10m).
	StateTTL time.Duration
}

type Status string

const (
	Active         Status = "active"
	NeedsReauth    Status = "needs_reauth"
	Disconnecting  Status = "disconnecting"
	purpose               = "connection"
	refreshSkew           = time.Minute
	maxScopesText         = 2000
	defaultTimeout        = 30 * time.Second
	leaseMargin           = 15 * time.Second
)

type Connection struct {
	ID                ID         `json:"id"`
	Provider          string     `json:"provider"`
	ExternalAccountID string     `json:"externalAccountId"`
	Scopes            []string   `json:"scopes"`
	Status            Status     `json:"status"`
	ExpiresAt         *time.Time `json:"expiresAt"`
	CreatedAt         time.Time  `json:"createdAt"`
	UpdatedAt         time.Time  `json:"updatedAt"`
}

var (
	ErrUnknownProvider   = errors.New("connections: unknown provider")
	ErrInvalidState      = errors.New("connections: the authorisation is invalid or has expired; start again")
	ErrNotFound          = errors.New("connections: connection not found")
	ErrReauthRequired    = errors.New("connections: the connection must be authorised again")
	ErrRevokeUnsupported = errors.New("connections: the provider does not support revocation")
	ErrBusy              = errors.New("connections: the connection is being refreshed; try again shortly")
	ErrChanged           = errors.New("connections: the connection changed meanwhile; try again")
	ErrOriginNotAllowed  = errors.New("connections: the URL is not one of the provider's API origins")
)

type Service struct {
	tx        TxRunner
	keys      *seal.Keyring
	providers map[string]Provider
	origins   map[string][]string
	client    *http.Client
	timeout   time.Duration
	stateTTL  time.Duration
	flight    singleflight.Group
}

func New(o Options) (*Service, error) {
	if o.Tx == nil || o.Keys == nil {
		return nil, errors.New("connections: transaction runner and keys are required")
	}
	s := &Service{tx: o.Tx, keys: o.Keys, providers: map[string]Provider{}, origins: map[string][]string{}, client: o.HTTPClient, stateTTL: o.StateTTL}
	if s.client == nil {
		s.client = netguard.NewDialer(defaultTimeout).Client(defaultTimeout)
	}
	s.timeout = s.client.Timeout
	if s.timeout <= 0 {
		s.timeout = defaultTimeout
	}
	if s.stateTTL <= 0 {
		s.stateTTL = oauthstate.DefaultTTL
	}
	for _, p := range o.Providers {
		if p.Name() == "" || len(p.Name()) > 64 || p.OAuth2() == nil {
			return nil, fmt.Errorf("connections: provider %q needs a name of 1 to 64 characters and an OAuth2 config", p.Name())
		}
		if _, dup := s.providers[p.Name()]; dup {
			return nil, fmt.Errorf("connections: duplicate provider %q", p.Name())
		}
		origins, err := parseOrigins(p.APIOrigins())
		if err != nil {
			return nil, fmt.Errorf("connections: provider %q: %w", p.Name(), err)
		}
		s.providers[p.Name()], s.origins[p.Name()] = p, origins
	}
	return s, nil
}

// parseOrigins accepts https origins, and http only on loopback (tests and local fakes).
func parseOrigins(list []string) ([]string, error) {
	if len(list) == 0 {
		return nil, errors.New("at least one API origin is required")
	}
	out := make([]string, len(list))
	for i, raw := range list {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" ||
			(u.Scheme != "https" && (u.Scheme != "http" || !loopback(u.Hostname()))) {
			return nil, fmt.Errorf("API origin %q must be https://host[:port]", raw)
		}
		out[i] = origin(u)
	}
	return out, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// origin is scheme://host[:port], lower-cased, without a default port.
func origin(u *url.URL) string {
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host
}

func (s *Service) provider(name string) (Provider, error) {
	p, ok := s.providers[name]
	if !ok {
		return nil, ErrUnknownProvider
	}
	return p, nil
}

// oauthCtx makes the oauth2 package use the service's client for token requests.
func (s *Service) oauthCtx(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, s.client)
}

func now(ctx context.Context) time.Time {
	return clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond)
}

// Start records a single-use state with a PKCE verifier for user and returns the provider's
// authorisation URL. returnTo is stored as given; pass it through httpx.SafeReturnPath first.
func (s *Service) Start(ctx context.Context, tx db.Transaction, providerName string, user users.ID, returnTo string) (string, error) {
	p, err := s.provider(providerName)
	if err != nil {
		return "", err
	}
	st, err := oauthstate.Put(ctx, tx, oauthstate.New{Purpose: purpose, Provider: providerName, ReturnTo: returnTo, UserID: &user, TTL: s.stateTTL})
	if err != nil {
		return "", fmt.Errorf("connections: start: %w", err)
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(st.Verifier)}
	if o, ok := p.(AuthOptioner); ok {
		opts = append(opts, o.AuthCodeOptions()...)
	}
	return p.OAuth2().AuthCodeURL(st.State, opts...), nil
}

// Finish spends the state (once, whatever happens next), exchanges the code with the PKCE verifier,
// identifies the account and stores the connection; reconnecting an account replaces its tokens.
func (s *Service) Finish(ctx context.Context, providerName string, user users.ID, state, code string) (Connection, string, error) {
	p, err := s.provider(providerName)
	if err != nil {
		return Connection{}, "", err
	}
	var taken oauthstate.Taken
	// A refused state is still spent: the transaction commits and the refusal is returned after.
	var refused error
	err = s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		var err error
		taken, err = oauthstate.Take(ctx, tx, state, purpose, providerName)
		switch {
		case errors.Is(err, oauthstate.ErrInvalid):
			refused = ErrInvalidState
			return nil
		case err == nil && (taken.UserID == nil || *taken.UserID != user):
			refused = ErrInvalidState
		}
		return err
	})
	if err = errors.Join(err, refused); err != nil {
		return Connection{}, "", err
	}
	tok, err := p.OAuth2().Exchange(s.oauthCtx(ctx), code, oauth2.VerifierOption(taken.Verifier))
	if err != nil {
		return Connection{}, "", providerError("exchange", err)
	}
	// A fixed token: a refresh here would rotate the refresh token before it is stored.
	acct, err := p.Account(ctx, s.apiClient(func(context.Context) (Provider, string, string, error) {
		return p, tok.AccessToken, tok.Type(), nil
	}))
	if err != nil {
		return Connection{}, "", providerError("identify account", err)
	}
	if acct.ExternalID == "" || len(acct.ExternalID) > 255 || len(strings.Join(acct.Scopes, " ")) > maxScopesText {
		return Connection{}, "", errors.New("connections: the provider returned an unusable account")
	}
	c, err := s.save(ctx, providerName, acct, tok, user)
	return c, taken.ReturnTo, err
}

// aad binds a sealed token to its row and field.
func aad(id ID, field string) []byte { return append(id[:], field...) }

func (s *Service) seal(id ID, field string, value string) []byte {
	return s.keys.Seal([]byte(value), aad(id, field))
}

func (s *Service) open(id ID, field string, sealed []byte) (string, error) {
	plain, _, err := s.keys.Open(sealed, aad(id, field))
	return string(plain), err
}

func expiry(tok *oauth2.Token) *time.Time {
	if tok.Expiry.IsZero() {
		return nil
	}
	e := tok.Expiry.UTC().Truncate(time.Microsecond)
	return &e
}

// PruneStates deletes authorisation states that expired before before; schedule it with the other
// retention jobs.
func PruneStates(ctx context.Context, tx db.Transaction, before time.Time) (int64, error) {
	n, err := oauthstate.Prune(ctx, tx, before.UTC())
	if err != nil {
		return 0, fmt.Errorf("connections: prune states: %w", err)
	}
	return n, nil
}

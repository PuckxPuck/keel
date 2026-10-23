package connections

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

// A refresh, a reconnect and a disconnect each change a connection in short transactions around their
// provider call, never inside one. A refresh first takes a lease (refresh_owner, refreshing_until) in a
// committed write; the others wait while a lease is live, and every write after a provider call is
// conditioned on the version it started from.

type stored struct {
	Connection
	access, refresh []byte
	tokenType       string
	version         int
	owner           sql.NullString
	leaseUntil      sql.NullTime
}

func (c stored) fresh(at time.Time) bool {
	return c.ExpiresAt == nil || c.ExpiresAt.After(at.Add(refreshSkew))
}

func (c stored) leased(at time.Time) bool {
	return c.owner.Valid && c.leaseUntil.Valid && c.leaseUntil.Time.After(at)
}

const selectColumns = "id, provider, external_account_id, scopes, status, expires_at, created_at, updated_at, access_token, refresh_token, " +
	"token_type, version, refresh_owner, refreshing_until"

func (s *Service) load(ctx context.Context, tx db.Transaction, id ID, lock bool) (stored, error) {
	q := "SELECT " + selectColumns + " FROM connections WHERE id = ?"
	if lock {
		q += " FOR UPDATE"
	}
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), q), id)
	if err != nil {
		return stored{}, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return stored{}, errors.Join(rows.Err(), ErrNotFound)
	}
	var c stored
	var scopes string
	if err := rows.Scan(&c.ID, &c.Provider, &c.ExternalAccountID, &scopes, &c.Status, &c.ExpiresAt, &c.CreatedAt, &c.UpdatedAt,
		&c.access, &c.refresh, &c.tokenType, &c.version, &c.owner, &c.leaseUntil); err != nil {
		return stored{}, err
	}
	c.Scopes = strings.Fields(scopes)
	return c, rows.Close()
}

// Get returns a connection without its tokens.
func (s *Service) Get(ctx context.Context, tx db.Transaction, id ID) (Connection, error) {
	c, err := s.load(ctx, tx, id, false)
	return c.Connection, err
}

func (s *Service) lease() time.Duration { return s.timeout + leaseMargin }

// token returns the connection's provider and a usable access token, refreshing it when it is about to expire.
func (s *Service) token(ctx context.Context, id ID) (Provider, string, string, error) {
	var c stored
	if err := s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		var err error
		c, err = s.load(ctx, tx, id, false)
		return err
	}); err != nil {
		return nil, "", "", err
	}
	p, err := s.provider(c.Provider)
	if err != nil {
		return nil, "", "", err
	}
	switch c.Status {
	case Disconnecting:
		return nil, "", "", ErrNotFound
	case NeedsReauth:
		return nil, "", "", ErrReauthRequired
	case Active:
	}
	if c.fresh(now(ctx)) {
		access, err := s.open(id, "access", c.access)
		return p, access, c.tokenType, err
	}
	tok, err := s.sharedRefresh(ctx, id)
	if err != nil {
		return nil, "", "", err
	}
	return p, tok.AccessToken, tok.Type(), nil
}

// sharedRefresh runs one refresh per connection in this process. It runs detached from the caller, so a
// caller that gives up after the provider answered does not lose the rotated token.
func (s *Service) sharedRefresh(ctx context.Context, id ID) (*oauth2.Token, error) {
	ch := s.flight.DoChan(id.String(), func() (any, error) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*s.lease())
		defer cancel()
		return s.refresh(ctx, id)
	})
	select {
	case r := <-ch:
		if r.Err != nil {
			return nil, r.Err
		}
		return r.Val.(*oauth2.Token), nil //nolint:forcetypeassert // refresh returns only *oauth2.Token
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

type refreshStep int

const (
	stepUse refreshStep = iota
	stepWait
	stepReauth
	stepCall
)

const maxRefreshRounds = 3

func (s *Service) refresh(ctx context.Context, id ID) (*oauth2.Token, error) {
	waiter := newBackoff(ctx, s.lease())
	for round := 0; round < maxRefreshRounds; {
		var c stored
		var step refreshStep
		owner := newOwner()
		err := s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
			var err error
			if c, err = s.load(ctx, tx, id, true); err != nil {
				return err
			}
			at := now(ctx)
			switch {
			case c.Status == Disconnecting:
				return ErrNotFound
			case c.Status != Active:
				return ErrReauthRequired
			case c.fresh(at):
				step = stepUse
			case c.leased(at):
				step = stepWait
			case c.refresh == nil:
				step = stepReauth
				_, err = exec(ctx, tx, "UPDATE connections SET status = 'needs_reauth', version = version + 1, updated_at = ? WHERE id = ?", at, id)
			default:
				step = stepCall
				c.version++
				_, err = exec(ctx, tx, "UPDATE connections SET refresh_owner = ?, refreshing_until = ?, version = ?, updated_at = ? WHERE id = ?",
					owner, at.Add(s.lease()), c.version, at, id)
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		switch step {
		case stepUse:
			access, err := s.open(id, "access", c.access)
			return &oauth2.Token{AccessToken: access, TokenType: c.tokenType}, err
		case stepReauth:
			return nil, ErrReauthRequired
		case stepWait:
			if !waiter.wait() {
				return nil, ErrBusy
			}
			continue
		case stepCall:
		}
		round++
		tok, won, err := s.callAndStore(ctx, c, owner)
		if err != nil || won {
			return tok, err
		}
	}
	return nil, ErrChanged
}

// callAndStore asks the provider for new tokens under the lease and stores them. won is false when the
// connection changed meanwhile (the lease ran out and someone else moved it); the new tokens are then revoked.
func (s *Service) callAndStore(ctx context.Context, c stored, owner string) (*oauth2.Token, bool, error) {
	p, err := s.provider(c.Provider)
	if err != nil {
		return nil, false, errors.Join(err, s.endLease(ctx, c.ID, owner, false))
	}
	rt, err := s.open(c.ID, "refresh", c.refresh)
	if err != nil {
		return nil, false, errors.Join(err, s.endLease(ctx, c.ID, owner, false))
	}
	call, cancel := context.WithTimeout(ctx, s.timeout)
	tok, err := p.OAuth2().TokenSource(s.oauthCtx(call), &oauth2.Token{RefreshToken: rt, Expiry: time.Unix(1, 0)}).Token()
	cancel()
	if err != nil {
		if invalidGrant(err) {
			return nil, false, errors.Join(ErrReauthRequired, s.endLease(ctx, c.ID, owner, true))
		}
		return nil, false, errors.Join(providerError("refresh", err), s.endLease(ctx, c.ID, owner, false))
	}
	if tok.RefreshToken == "" {
		tok.RefreshToken = rt
	}
	won, err := s.persist(ctx, c, owner, tok)
	if err != nil {
		logx.From(ctx).Error("connections: refreshed token not stored", "connection_id", c.ID.String(), "error", err)
		return nil, false, fmt.Errorf("connections: store refreshed token: %w", err)
	}
	if !won {
		s.revoke(ctx, p, tok)
	}
	return tok, won, nil
}

const persistTries = 5

// persist writes the new tokens if the lease is still this refresh's. Only the write is retried: the
// provider has already spent the old refresh token. A write that finds the row changed checks whether
// its own earlier commit landed (an uncertain commit) before calling it lost.
func (s *Service) persist(ctx context.Context, c stored, owner string, tok *oauth2.Token) (bool, error) {
	var won bool
	var err error
	for try := 1; ; try++ {
		err = s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
			n, err := exec(ctx, tx, "UPDATE connections SET access_token = ?, refresh_token = ?, token_type = ?, expires_at = ?, "+
				"refresh_owner = NULL, refreshing_until = NULL, version = version + 1, updated_at = ? WHERE id = ? AND refresh_owner = ? AND version = ?",
				s.seal(c.ID, "access", tok.AccessToken), s.seal(c.ID, "refresh", tok.RefreshToken), tok.Type(), expiry(tok), now(ctx),
				c.ID, owner, c.version)
			if err != nil || n == 1 {
				won = n == 1
				return err
			}
			cur, err := s.load(ctx, tx, c.ID, false)
			if errors.Is(err, ErrNotFound) {
				won = false
				return nil
			}
			if err != nil {
				return err
			}
			stored, err := s.open(c.ID, "refresh", cur.refresh)
			won = err == nil && stored == tok.RefreshToken
			return nil
		})
		if err == nil || try == persistTries || !db.IsRetryable(err) && !errors.Is(err, db.ErrCommitUncertain) {
			return won, err
		}
		if !sleep(ctx, time.Duration(try)*50*time.Millisecond) {
			return false, err
		}
	}
}

// endLease gives the lease up after a failed provider call, marking the connection for reauthorisation
// when the refresh token was refused.
func (s *Service) endLease(ctx context.Context, id ID, owner string, reauth bool) error {
	set := ""
	if reauth {
		set = "status = 'needs_reauth', "
	}
	return s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
		_, err := exec(ctx, tx, "UPDATE connections SET "+set+"refresh_owner = NULL, refreshing_until = NULL, version = version + 1, updated_at = ? "+
			"WHERE id = ? AND refresh_owner = ?", now(ctx), id, owner)
		return err
	})
}

func (s *Service) revoke(ctx context.Context, p Provider, tok *oauth2.Token) {
	call, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.timeout)
	defer cancel()
	if err := p.Revoke(call, s.client, tok); err != nil && !errors.Is(err, ErrRevokeUnsupported) {
		logx.From(ctx).Warn("connections: could not revoke an unstored token", "provider", p.Name(), "error", providerError("revoke", err))
	}
}

// Disconnect revokes the tokens at the provider when it supports revocation, then deletes the
// connection. It waits while a refresh holds the lease, so it always revokes the newest tokens. A failed
// revocation keeps the connection so the caller can try again.
func (s *Service) Disconnect(ctx context.Context, id ID) error {
	var c stored
	var prev Status
	waiter := newBackoff(ctx, s.lease())
	for {
		busy := false
		err := s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
			var err error
			if c, err = s.load(ctx, tx, id, true); err != nil {
				return err
			}
			at := now(ctx)
			if busy = c.leased(at); busy {
				return nil
			}
			prev = c.Status
			c.version++
			_, err = exec(ctx, tx, "UPDATE connections SET status = 'disconnecting', version = ?, updated_at = ? WHERE id = ?", c.version, at, id)
			return err
		})
		if err != nil {
			return err
		}
		if !busy {
			break
		}
		if !waiter.wait() {
			return ErrBusy
		}
	}
	if err := s.revokeStored(ctx, c); err != nil {
		restore := s.tx(context.WithoutCancel(ctx), func(ctx context.Context, tx db.Transaction) error {
			_, err := exec(ctx, tx, "UPDATE connections SET status = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?",
				string(prev), now(ctx), id, c.version)
			return err
		})
		return errors.Join(err, restore)
	}
	return s.tx(context.WithoutCancel(ctx), func(ctx context.Context, tx db.Transaction) error {
		n, err := exec(ctx, tx, "DELETE FROM connections WHERE id = ? AND version = ?", id, c.version)
		if err == nil && n == 0 {
			return ErrChanged
		}
		return err
	})
}

func (s *Service) revokeStored(ctx context.Context, c stored) error {
	p, err := s.provider(c.Provider)
	if err != nil {
		return err
	}
	tok := &oauth2.Token{TokenType: c.tokenType}
	if tok.AccessToken, err = s.open(c.ID, "access", c.access); err != nil {
		return err
	}
	if c.refresh != nil {
		if tok.RefreshToken, err = s.open(c.ID, "refresh", c.refresh); err != nil {
			return err
		}
	}
	if err := p.Revoke(ctx, s.client, tok); err != nil && !errors.Is(err, ErrRevokeUnsupported) {
		return providerError("revoke", err)
	}
	return nil
}

// save stores the tokens of a new or reconnected account, waiting while a refresh holds the lease.
func (s *Service) save(ctx context.Context, provider string, acct Account, tok *oauth2.Token, user users.ID) (Connection, error) {
	waiter := newBackoff(ctx, s.lease())
	for retried := false; ; {
		var c Connection
		busy := false
		err := s.tx(ctx, func(ctx context.Context, tx db.Transaction) error {
			var err error
			busy, c, err = s.saveIn(ctx, tx, provider, acct, tok, user)
			return err
		})
		switch {
		case db.IsUniqueViolation(err) && !retried:
			// Two first connects of one account at once: the second becomes a reconnect.
			retried = true
			continue
		case err != nil:
			return Connection{}, fmt.Errorf("connections: save: %w", err)
		case !busy:
			return c, nil
		}
		if !waiter.wait() {
			return Connection{}, ErrBusy
		}
	}
}

func (s *Service) saveIn(ctx context.Context, tx db.Transaction, provider string, acct Account, tok *oauth2.Token, user users.ID) (bool, Connection, error) {
	t := now(ctx)
	scopes := strings.Join(acct.Scopes, " ")
	var id ID
	q := db.Rebind(tx.Dialect(), "SELECT id FROM connections WHERE provider = ? AND external_account_id = ? FOR UPDATE")
	exists, err := findAccount(ctx, tx, q, provider, acct.ExternalID, &id)
	if err != nil {
		return false, Connection{}, err
	}
	if !exists {
		id = ids.NewOf[connectionTag]()
	}
	var refresh []byte
	if tok.RefreshToken != "" {
		refresh = s.seal(id, "refresh", tok.RefreshToken)
	}
	access := s.seal(id, "access", tok.AccessToken)
	if exists {
		cur, err := s.load(ctx, tx, id, true)
		if err != nil {
			return false, Connection{}, err
		}
		if cur.leased(t) {
			return true, Connection{}, nil
		}
		if cur.refresh != nil && refresh == nil {
			// The provider sent no new refresh token: keep the stored one, sealed again with the newest key.
			rt, err := s.open(id, "refresh", cur.refresh)
			if err != nil {
				return false, Connection{}, err
			}
			refresh = s.seal(id, "refresh", rt)
		}
		if _, err := exec(ctx, tx, "UPDATE connections SET scopes = ?, status = 'active', access_token = ?, refresh_token = ?, token_type = ?, "+
			"expires_at = ?, refresh_owner = NULL, refreshing_until = NULL, version = version + 1, updated_at = ? WHERE id = ? AND version = ?",
			scopes, access, refresh, tok.Type(), expiry(tok), t, id, cur.version); err != nil {
			return false, Connection{}, err
		}
		c, err := s.Get(ctx, tx, id)
		return false, c, err
	}
	if _, err := exec(ctx, tx, "INSERT INTO connections (id, provider, external_account_id, scopes, status, access_token, refresh_token, "+
		"token_type, expires_at, created_by, created_at, updated_at, version) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, 1)",
		id, provider, acct.ExternalID, scopes, access, refresh, tok.Type(), expiry(tok), user, t, t); err != nil {
		return false, Connection{}, err
	}
	c, err := s.Get(ctx, tx, id)
	return false, c, err
}

func findAccount(ctx context.Context, tx db.Transaction, q, provider, external string, id *ID) (bool, error) {
	rows, err := tx.Q().QueryContext(ctx, q, provider, external)
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return false, rows.Err()
	}
	return true, errors.Join(rows.Scan(id), rows.Close())
}

func exec(ctx context.Context, tx db.Transaction, query string, args ...any) (int64, error) {
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), query), args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func newOwner() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	return hex.EncodeToString(b[:])
}

// backoff waits with growing pauses, holding no connection, until a total budget is spent.
type backoff struct {
	ctx   context.Context //nolint:containedctx // the waits of one operation
	until time.Time
	next  time.Duration
}

func newBackoff(ctx context.Context, budget time.Duration) *backoff {
	return &backoff{ctx: ctx, until: clock.Wall(ctx).Now().Add(budget), next: 25 * time.Millisecond}
}

func (b *backoff) wait() bool {
	left := b.until.Sub(clock.Wall(b.ctx).Now())
	if left <= 0 {
		return false
	}
	d := min(b.next, left)
	b.next = min(2*b.next, time.Second)
	return sleep(b.ctx, d)
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

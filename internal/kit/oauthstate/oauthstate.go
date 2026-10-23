// Package oauthstate keeps the server side of an OAuth or OIDC round trip in oauth_states: the state is
// stored only as its hash, with the PKCE verifier, the nonce's hash, the return path and the user who
// started it. Each state is single use and expires.
package oauthstate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

// DefaultTTL bounds the round trip to the provider and back.
const DefaultTTL = 10 * time.Minute

const maxState = 128

// ErrInvalid is a state that is unknown, already used, expired, or made for another purpose,
// provider or user.
var ErrInvalid = errors.New("oauthstate: the authorisation is invalid or has expired; start again")

// Runner opens the transactions a round trip works in: plain, or tenant transactions under tenancy.
type Runner func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error

// PlainTx runs fn in a plain transaction on d.
func PlainTx(d *db.DB) Runner {
	return func(ctx context.Context, fn func(context.Context, db.Transaction) error) error {
		return db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error { return fn(ctx, tx) })
	}
}

// New describes a round trip to start. Nonce asks for an OIDC nonce; UserID binds the state to the user
// who started it (connecting an account), nil for a sign-in.
type New struct {
	Purpose  string
	Provider string
	ReturnTo string
	UserID   *users.ID
	Nonce    bool
	TTL      time.Duration
}

// Started holds the values for the authorisation URL; none of them is stored in the clear but the
// verifier, which the token request needs.
type Started struct {
	State    string
	Verifier string
	Nonce    string
}

// Put records a new state in tx.
func Put(ctx context.Context, tx db.Transaction, in New) (Started, error) {
	ttl := in.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	out := Started{State: random(), Verifier: oauth2.GenerateVerifier()}
	var nonce, returnTo sql.NullString
	if in.Nonce {
		out.Nonce = random()
		nonce = sql.NullString{String: encodeHash(out.Nonce), Valid: true}
	}
	if in.ReturnTo != "" {
		returnTo = sql.NullString{String: in.ReturnTo, Valid: true}
	}
	t := now(ctx)
	q := db.Rebind(tx.Dialect(), `INSERT INTO oauth_states (id, state_hash, purpose, provider, verifier, nonce, return_to, user_id,
		expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if _, err := tx.Q().ExecContext(ctx, q, ids.New(), hash(out.State), in.Purpose, in.Provider, out.Verifier, nonce, returnTo,
		in.UserID, t.Add(ttl), t); err != nil {
		return Started{}, fmt.Errorf("oauthstate: put: %w", err)
	}
	return out, nil
}

// Taken is a spent state.
type Taken struct {
	Verifier  string
	ReturnTo  string
	UserID    *users.ID
	nonceHash string
}

// NonceMatches compares nonce with the one Put made, in constant time; false when Put made none.
func (t Taken) NonceMatches(nonce string) bool {
	return t.nonceHash != "" && subtle.ConstantTimeCompare([]byte(encodeHash(nonce)), []byte(t.nonceHash)) == 1
}

// Take deletes the state and returns it, or ErrInvalid when it is unknown, expired, or was made for
// another purpose or provider. The row is deleted whatever the answer, so commit tx on ErrInvalid too:
// a refused state is spent.
func Take(ctx context.Context, tx db.Transaction, state, purpose, provider string) (Taken, error) {
	if state == "" || len(state) > maxState {
		return Taken{}, ErrInvalid
	}
	cols := "id, purpose, provider, verifier, nonce, return_to, user_id, expires_at"
	if tx.Tenancy() {
		cols += ", tenant_id"
	}
	q := db.Rebind(tx.Dialect(), "SELECT "+cols+" FROM oauth_states WHERE state_hash = ? FOR UPDATE")
	rows, err := tx.Q().QueryContext(ctx, q, hash(state))
	if err != nil {
		return Taken{}, fmt.Errorf("oauthstate: take: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return Taken{}, errors.Join(rows.Err(), ErrInvalid)
	}
	var id uuid.UUID
	var gotPurpose, gotProvider string
	var nonce, returnTo sql.NullString
	var out Taken
	var expires time.Time
	var tenant *uuid.UUID
	dest := []any{&id, &gotPurpose, &gotProvider, &out.Verifier, &nonce, &returnTo, &out.UserID, &expires}
	if tx.Tenancy() {
		dest = append(dest, &tenant)
	}
	if err := rows.Scan(dest...); err != nil {
		return Taken{}, fmt.Errorf("oauthstate: take: %w", err)
	}
	if err := rows.Close(); err != nil {
		return Taken{}, err
	}
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM oauth_states WHERE id = ?"), id); err != nil {
		return Taken{}, fmt.Errorf("oauthstate: spend: %w", err)
	}
	if gotPurpose != purpose || gotProvider != provider || !now(ctx).Before(expires) || !sameTenant(ctx, tx, tenant) {
		return Taken{}, ErrInvalid
	}
	out.nonceHash, out.ReturnTo = nonce.String, returnTo.String
	return out, nil
}

// sameTenant holds a round trip to the tenant it started in (the column default records it), so a
// callback cannot finish a connection in another tenant.
func sameTenant(ctx context.Context, tx db.Transaction, stored *uuid.UUID) bool {
	if !tx.Tenancy() {
		return true
	}
	current, ok := db.TenantOf(ctx)
	if stored == nil || !ok {
		return stored == nil && !ok
	}
	return *stored == current
}

// Prune deletes states that expired before before.
func Prune(ctx context.Context, tx db.Transaction, before time.Time) (int64, error) {
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM oauth_states WHERE expires_at < ?"), before)
	if err != nil {
		return 0, fmt.Errorf("oauthstate: prune: %w", err)
	}
	return res.RowsAffected()
}

func random() string {
	var b [32]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func hash(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func encodeHash(s string) string { return base64.RawURLEncoding.EncodeToString(hash(s)) }

func now(ctx context.Context) time.Time {
	return clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond)
}

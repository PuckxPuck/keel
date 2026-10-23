package password

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

const CodeInvalidCredentials = "invalid_credentials" //nolint:gosec // a problem code, not a credential

var (
	// ErrInvalidCredentials is every sign-in failure: unknown account, wrong password, no password,
	// disabled user. One answer, so the response does not tell which.
	ErrInvalidCredentials = errors.New("invalid credentials")
	errNoPassword         = errors.New("password: none set")
)

// Verifier is what the service needs from a Hasher.
type Verifier interface {
	Hash(ctx context.Context, plain string) (string, error)
	Verify(ctx context.Context, encoded, plain string) (ok, rehash bool, err error)
	DummyHash() string
}

// Throttle is how many sign-in failures an account may see from one address, and one address in
// total, per window.
type Throttle struct {
	PerAccount ratelimit.Rate
	PerAddress ratelimit.Rate
}

var DefaultThrottle = Throttle{
	PerAccount: ratelimit.Rate{Limit: 5, Period: 15 * time.Minute},
	PerAddress: ratelimit.Rate{Limit: 50, Period: 15 * time.Minute},
}

type Service struct {
	hasher   Verifier
	failures *auth.Failures
	throttle Throttle
	audit    *audit.Recorder
}

func NewService(h Verifier, f *auth.Failures, t Throttle, rec *audit.Recorder) *Service {
	if h == nil || f == nil || rec == nil {
		panic("password: NewService needs a hasher, a failure counter and a recorder")
	}
	return &Service{hasher: h, failures: f, throttle: t, audit: rec}
}

// limits count every attempt by address, and by account from that address; the account count is
// skipped when the address is unknown, so one such caller cannot slow the account for every other.
func (s *Service) limits(ctx context.Context, email string) []auth.Limit {
	addr, known := auth.Address(ctx)
	out := []auth.Limit{{Key: auth.Key("password-address", addr), Rate: s.throttle.PerAddress}}
	if !known {
		return out
	}
	normalised, err := users.NormaliseEmail(email)
	if err != nil {
		normalised = email
	}
	return append(out, auth.Limit{Key: auth.Key("password", normalised, addr), Rate: s.throttle.PerAccount, Reset: true})
}

// Then finishes a sign-in in the transaction that stores any rehash; it starts the session.
type Then func(ctx context.Context, tx db.Transaction, u users.User) error

// Authenticate checks an email and password, then runs then. The attempt is counted before anything
// else; the user and hash are read in a short read-only transaction and verified with no connection
// held, and only the closing write (rehash and then) takes a transaction. Unknown, disabled and
// passwordless accounts verify against a dummy hash, so every failure answers alike in about the same
// time. A success clears the account's count and gives the attempt back to the address.
func (s *Service) Authenticate(ctx context.Context, d *db.DB, email, plain string, then Then) (users.User, error) {
	limits := s.limits(ctx, email)
	if err := s.failures.Attempt(ctx, limits...); err != nil {
		return users.User{}, err
	}
	u, stored, usable, err := lookup(ctx, d, email)
	if err != nil {
		return users.User{}, err
	}
	if !usable {
		stored = s.hasher.DummyHash()
	}
	ok, rehash, err := s.hasher.Verify(ctx, stored, plain)
	switch {
	case errors.Is(err, ErrBusy), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return users.User{}, err
	case err != nil:
		logx.From(ctx).Error("stored password hash is unusable", "error", err, logx.KeyUserID, u.ID.String())
	}
	if !ok || !usable {
		return users.User{}, ErrInvalidCredentials
	}
	var fresh string
	if rehash {
		if fresh, err = s.hasher.Hash(ctx, plain); err != nil {
			return users.User{}, err
		}
	}
	err = db.InAppTx(ctx, d, func(ctx context.Context, tx db.Transaction) error {
		if fresh != "" {
			if err := s.store(ctx, tx, u.ID, fresh, "password.rehashed"); err != nil {
				return err
			}
		}
		return then(ctx, tx, u)
	})
	if err != nil {
		return users.User{}, err
	}
	if err := s.failures.Succeeded(ctx, limits...); err != nil {
		logx.From(ctx).Warn("clear sign-in failures", "error", err)
	}
	return u, nil
}

// lookup reads the user and their hash; usable is false when there is nothing to check against.
func lookup(ctx context.Context, d *db.DB, email string) (u users.User, stored string, usable bool, err error) {
	err = db.InTx(ctx, d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		u, err = users.ByEmail(ctx, tx, email)
		if errors.Is(err, users.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		stored, err = hashOf(ctx, tx, u.ID)
		if errors.Is(err, errNoPassword) {
			return nil
		}
		usable = err == nil && u.Status == users.Active
		return err
	}, db.ReadOnly())
	return u, stored, usable, err
}

// Hashed is a new password, checked and hashed before its transaction opens.
type Hashed struct{ encoded string }

// Prepare checks plain against policy and hashes it. Call it before the transaction that stores it,
// so argon2id never runs while a connection is held.
func (s *Service) Prepare(ctx context.Context, plain string, policy Policy) (Hashed, error) {
	if err := policy.Check(plain); err != nil {
		return Hashed{}, err
	}
	encoded, err := s.hasher.Hash(ctx, plain)
	return Hashed{encoded: encoded}, err
}

// Set gives the user a prepared password and moves their access version, so their other sessions
// rotate on their next request.
func (s *Service) Set(ctx context.Context, tx db.Transaction, userID users.ID, h Hashed) error {
	if h.encoded == "" {
		return errors.New("password: Set needs a prepared password")
	}
	if err := s.store(ctx, tx, userID, h.encoded, "password.changed"); err != nil {
		return err
	}
	return users.BumpAccess(ctx, tx, userID)
}

func (s *Service) store(ctx context.Context, tx db.Transaction, userID users.ID, encoded, action string) error {
	if err := upsert(ctx, tx, userID, encoded, clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond)); err != nil {
		return err
	}
	if audit.ActorFrom(ctx).Type == audit.ActorSystem && inRequest(ctx) {
		uid := userID.UUID()
		ctx = audit.WithActor(ctx, audit.Actor{Type: audit.ActorUser, ID: &uid})
	}
	return s.audit.Record(ctx, tx, audit.Event{Action: action, Entity: "user", EntityID: userID.String()})
}

var upsertSQL = map[db.Dialect]string{
	db.Postgres: `INSERT INTO credentials (user_id, password_hash, created_at, updated_at) VALUES ($1, $2, $3, $3)
		ON CONFLICT (user_id) DO UPDATE SET password_hash = excluded.password_hash, updated_at = excluded.updated_at`,
	db.MySQL: `INSERT INTO credentials (user_id, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?) AS new
		ON DUPLICATE KEY UPDATE password_hash = new.password_hash, updated_at = new.updated_at`,
}

func upsert(ctx context.Context, tx db.Transaction, userID users.ID, encoded string, now time.Time) error {
	args := []any{userID, encoded, now}
	if tx.Dialect() == db.MySQL {
		args = append(args, now)
	}
	if _, err := tx.Q().ExecContext(ctx, upsertSQL[tx.Dialect()], args...); err != nil {
		return fmt.Errorf("store password: %w", err)
	}
	return nil
}

// inRequest is true in a request: there an anonymous change (sign-in, reset link) is the user's own.
func inRequest(ctx context.Context) bool { return httpx.Realm(ctx) != "" }

func hashOf(ctx context.Context, tx db.Transaction, userID users.ID) (string, error) {
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), "SELECT password_hash FROM credentials WHERE user_id = ?"), userID)
	if err != nil {
		return "", fmt.Errorf("load password: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", err
		}
		return "", errNoPassword
	}
	var h string
	if err := rows.Scan(&h); err != nil {
		return "", err
	}
	return h, rows.Err()
}

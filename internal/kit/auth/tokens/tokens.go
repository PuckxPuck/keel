// Package tokens issues single-use link tokens (password reset, email verification, invites): 32
// random bytes for the link, SHA-256 stored, bound to one purpose and one user, consumed in the
// transaction of the change they authorise.
package tokens

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

type Purpose string

const (
	PasswordReset Purpose = "reset"
	VerifyEmail   Purpose = "verify_email"
	Invite        Purpose = "invite"
)

func (p Purpose) Valid() bool {
	switch p {
	case PasswordReset, VerifyEmail, Invite:
		return true
	}
	return false
}

// ErrInvalid is every refusal: malformed, unknown, used, expired or meant for another purpose.
var ErrInvalid = errors.New("the link is invalid or has expired")

const CodeInvalidToken = "invalid_token"

// Mapper answers ErrInvalid with 422 invalid_token.
func Mapper(err error) (*problem.Problem, bool) {
	if errors.Is(err, ErrInvalid) {
		return problem.New(http.StatusUnprocessableEntity, CodeInvalidToken, err.Error()), true
	}
	return nil, false
}

// Config is APP_TOKENS_*.
type Config struct {
	TTL       time.Duration `env:"TTL" envDefault:"60m"`
	InviteTTL time.Duration `env:"INVITE_TTL" envDefault:"168h"`
}

func (c Config) Validate(bool) error {
	if c.TTL < time.Minute || c.TTL > 24*time.Hour || c.InviteTTL < time.Hour || c.InviteTTL > 30*24*time.Hour {
		return errors.New("token TTL must be 1m to 24h and invite TTL 1h to 720h")
	}
	return nil
}

// TTLFor is the configured lifetime of a purpose's tokens.
func (c Config) TTLFor(p Purpose) time.Duration {
	if p == Invite {
		return c.InviteTTL
	}
	return c.TTL
}

var issueSQL = map[db.Dialect]string{
	db.Postgres: `INSERT INTO auth_tokens (id, user_id, purpose, token_hash, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, purpose) DO UPDATE SET id = excluded.id, token_hash = excluded.token_hash,
		expires_at = excluded.expires_at, created_at = excluded.created_at, used_at = NULL`,
	db.MySQL: `INSERT INTO auth_tokens (id, user_id, purpose, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?) AS new
		ON DUPLICATE KEY UPDATE id = new.id, token_hash = new.token_hash, expires_at = new.expires_at,
		created_at = new.created_at, used_at = NULL`,
}

// Issue makes a token for userID and purpose, valid for ttl. There is one row per user and purpose,
// and issuing replaces it in one statement, so only the latest link works even when two are issued at
// once. The raw token is returned once, for the link.
func Issue(ctx context.Context, tx db.Transaction, userID users.ID, purpose Purpose, ttl time.Duration) (string, error) {
	if !purpose.Valid() || ttl <= 0 {
		return "", fmt.Errorf("tokens: invalid purpose %q or ttl", purpose)
	}
	now := now(ctx)
	raw, hash := auth.NewSecret()
	if _, err := tx.Q().ExecContext(ctx, issueSQL[tx.Dialect()], ids.New(), userID, string(purpose), hash, now.Add(ttl), now); err != nil {
		return "", fmt.Errorf("issue token: %w", err)
	}
	return raw, nil
}

// Consume spends a token of purpose in tx and returns its user. A token of another purpose is refused
// and stays usable for its own.
func Consume(ctx context.Context, tx db.Transaction, raw string, purpose Purpose) (users.ID, error) {
	hash, err := auth.HashSecret(raw)
	if err != nil {
		return users.ID{}, ErrInvalid
	}
	q := db.Rebind(tx.Dialect(), "SELECT id, user_id, purpose, expires_at, used_at FROM auth_tokens WHERE token_hash = ? FOR UPDATE")
	rows, err := tx.Q().QueryContext(ctx, q, hash)
	if err != nil {
		return users.ID{}, fmt.Errorf("load token: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return users.ID{}, err
		}
		return users.ID{}, ErrInvalid
	}
	var id, user users.ID
	var got string
	var expires time.Time
	var used sql.NullTime
	if err := rows.Scan(&id, &user, &got, &expires, &used); err != nil {
		return users.ID{}, err
	}
	if err := rows.Close(); err != nil {
		return users.ID{}, err
	}
	now := now(ctx)
	if Purpose(got) != purpose || used.Valid || !now.Before(expires) {
		return users.ID{}, ErrInvalid
	}
	spend := db.Rebind(tx.Dialect(), "UPDATE auth_tokens SET used_at = ? WHERE id = ? AND token_hash = ? AND used_at IS NULL")
	res, err := tx.Q().ExecContext(ctx, spend, now, id, hash)
	if err != nil {
		return users.ID{}, fmt.Errorf("spend token: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return users.ID{}, errors.Join(err, ErrInvalid)
	}
	return user, nil
}

// Prune deletes tokens that expired before before.
func Prune(ctx context.Context, tx db.Transaction, before time.Time) (int64, error) {
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM auth_tokens WHERE expires_at < ?"), before)
	if err != nil {
		return 0, fmt.Errorf("prune tokens: %w", err)
	}
	return res.RowsAffected()
}

func now(ctx context.Context) time.Time {
	return clock.Wall(ctx).Now().UTC().Truncate(time.Microsecond)
}

// Notifier hands a link to delivery inside the transaction that issued its token: it enqueues (a mail
// job in the same transaction) and does no network I/O, so a rolled-back change sends nothing and a
// request answers in the same time whether or not a link was made. An error rolls the change back.
type Notifier interface {
	SendReset(ctx context.Context, tx db.Transaction, to users.User, token string) error
	SendVerify(ctx context.Context, tx db.Transaction, to users.User, token string) error
	SendInvite(ctx context.Context, tx db.Transaction, to users.User, token string) error
}

// LogNotifier writes links to the log once the transaction commits, for local development where there
// is no mail. Apps use it only with APP_ENV=local; it prints live tokens.
type LogNotifier struct{}

func (n LogNotifier) SendReset(ctx context.Context, _ db.Transaction, to users.User, token string) error {
	return n.log(ctx, PasswordReset, to, token)
}

func (n LogNotifier) SendVerify(ctx context.Context, _ db.Transaction, to users.User, token string) error {
	return n.log(ctx, VerifyEmail, to, token)
}

func (n LogNotifier) SendInvite(ctx context.Context, _ db.Transaction, to users.User, token string) error {
	return n.log(ctx, Invite, to, token)
}

func (LogNotifier) log(ctx context.Context, p Purpose, to users.User, token string) error {
	return db.AfterCommit(ctx, func(ctx context.Context) {
		logx.From(ctx).Info("link for local development", "purpose", string(p), logx.KeyUserID, to.ID.String(), slog.String("link_code", token))
	})
}

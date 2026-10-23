package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

func insertSession(ctx context.Context, tx db.Transaction, s Session, hash []byte, ip, ua *string) error {
	cols := "id, token_hash, realm, user_id, kind, mfa_state, mfa_at, created_at, last_seen_at, idle_expires_at, absolute_expires_at, ip, user_agent, access_version"
	marks := "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?"
	args := []any{
		s.ID, hash, s.Realm, s.UserID, string(s.Kind), string(s.MFA), s.MFAAt,
		s.CreatedAt, s.LastSeenAt, s.IdleExpiresAt, s.AbsoluteExpiresAt, ip, ua, s.AccessVersion,
	}
	if tx.Tenancy() {
		cols, marks, args = cols+", current_tenant_id", marks+", ?", append(args, s.Tenant)
	}
	_, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "INSERT INTO sessions ("+cols+") VALUES ("+marks+")"), args...)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

type storedSession struct {
	Session
	revokedAt *time.Time
	// userVersion is the user's access version now, read with the session.
	userVersion int64
}

func sessionByHash(ctx context.Context, tx db.Transaction, hash []byte) (storedSession, bool, error) {
	tenant := ""
	if tx.Tenancy() {
		tenant = ", s.current_tenant_id"
	}
	q := db.Rebind(tx.Dialect(), `SELECT s.id, s.realm, s.user_id, s.kind, s.mfa_state, s.mfa_at, s.created_at, s.last_seen_at,
		s.idle_expires_at, s.absolute_expires_at, s.revoked_at, s.access_version, u.access_version`+tenant+`
		FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`)
	rows, err := tx.Q().QueryContext(ctx, q, hash)
	if err != nil {
		return storedSession{}, false, fmt.Errorf("load session: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return storedSession{}, false, rows.Err()
	}
	var s storedSession
	var kind, mfa string
	var mfaAt, revokedAt sql.NullTime
	dest := []any{
		&s.ID, &s.Realm, &s.UserID, &kind, &mfa, &mfaAt, &s.CreatedAt, &s.LastSeenAt,
		&s.IdleExpiresAt, &s.AbsoluteExpiresAt, &revokedAt, &s.AccessVersion, &s.userVersion,
	}
	if tx.Tenancy() {
		dest = append(dest, &s.Tenant)
	}
	if err := rows.Scan(dest...); err != nil {
		return storedSession{}, false, fmt.Errorf("scan session: %w", err)
	}
	s.Kind, s.MFA = Kind(kind), MFAState(mfa)
	s.MFAAt = optionalTime(mfaAt)
	s.revokedAt = optionalTime(revokedAt)
	return s, true, rows.Err()
}

func optionalTime(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time.UTC()
	return &v
}

func touchSession(ctx context.Context, tx db.Transaction, id uuid.UUID, seen, idleUntil time.Time) error {
	q := db.Rebind(tx.Dialect(), "UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ? AND revoked_at IS NULL")
	if _, err := tx.Q().ExecContext(ctx, q, seen, idleUntil, id); err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

// rotateSession gives a live session a new token and access version. It reports false when another
// request rotated or ended it first.
func rotateSession(ctx context.Context, tx db.Transaction, id uuid.UUID, from, to []byte, version int64) (bool, error) {
	q := db.Rebind(tx.Dialect(), "UPDATE sessions SET token_hash = ?, access_version = ? WHERE id = ? AND token_hash = ? AND revoked_at IS NULL")
	res, err := tx.Q().ExecContext(ctx, q, to, version, id, from)
	if err != nil {
		return false, fmt.Errorf("rotate session: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// setSessionVersion records a bearer session's new access version; its token cannot change under a
// client that has no way to learn the new one.
func setSessionVersion(ctx context.Context, tx db.Transaction, id uuid.UUID, version int64) error {
	q := db.Rebind(tx.Dialect(), "UPDATE sessions SET access_version = ? WHERE id = ?")
	if _, err := tx.Q().ExecContext(ctx, q, version, id); err != nil {
		return fmt.Errorf("update session access version: %w", err)
	}
	return nil
}

func deleteByHash(ctx context.Context, tx db.Transaction, hash []byte) error {
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM sessions WHERE token_hash = ?"), hash); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// revokeScope narrows a revocation to one realm, or spares one session; the zero value is everything.
type revokeScope struct {
	realm  string
	tenant *uuid.UUID
	except *uuid.UUID
}

// revokeSessions revokes the user's live sessions within scope.
func revokeSessions(ctx context.Context, tx db.Transaction, user users.ID, scope revokeScope, at time.Time) (int64, error) {
	q, args := "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", []any{at, user}
	if scope.realm != "" {
		q, args = q+" AND realm = ?", append(args, scope.realm)
	}
	if scope.except != nil {
		q, args = q+" AND id <> ?", append(args, *scope.except)
	}
	if scope.tenant != nil {
		q, args = q+" AND current_tenant_id = ?", append(args, *scope.tenant)
	}
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), args...)
	if err != nil {
		return 0, fmt.Errorf("revoke sessions: %w", err)
	}
	return res.RowsAffected()
}

// Prune deletes sessions past their absolute expiry, or revoked, before before.
func Prune(ctx context.Context, tx db.Transaction, before time.Time) (int64, error) {
	q := db.Rebind(tx.Dialect(), "DELETE FROM sessions WHERE absolute_expires_at < ? OR revoked_at < ?")
	res, err := tx.Q().ExecContext(ctx, q, before, before)
	if err != nil {
		return 0, fmt.Errorf("prune sessions: %w", err)
	}
	return res.RowsAffected()
}

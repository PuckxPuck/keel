package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/occ"
)

const selectUser = "SELECT id, email, name, status, email_verified_at, created_at, updated_at, updated_by, version FROM users "

func insert(ctx context.Context, tx db.Transaction, u User) error {
	q := db.Rebind(tx.Dialect(), "INSERT INTO users (id, email, name, status, created_at, updated_at, version) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if _, err := tx.Q().ExecContext(ctx, q, u.ID, u.Email, u.Name, string(u.Status), u.CreatedAt, u.UpdatedAt, u.Version); err != nil {
		if db.IsUniqueViolation(err) {
			return ErrEmailTaken
		}
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func Get(ctx context.Context, tx db.Transaction, id ID) (User, error) {
	u, _, err := one(ctx, tx, selectUser+"WHERE id = ?", id)
	return u, err
}

// getForUpdate reads the row as it is now, not as an earlier snapshot of tx saw it, and locks it.
func getForUpdate(ctx context.Context, tx db.Transaction, id ID) (User, error) {
	u, _, err := one(ctx, tx, selectUser+"WHERE id = ? FOR UPDATE", id)
	return u, err
}

// ByEmail finds a user by address; the address is normalised as on write and compared exactly.
func ByEmail(ctx context.Context, tx db.Transaction, email string) (User, error) {
	normalised, err := NormaliseEmail(email)
	if err != nil {
		return User{}, ErrNotFound
	}
	u, _, err := one(ctx, tx, selectUser+"WHERE email = ?", normalised)
	return u, err
}

func one(ctx context.Context, tx db.Transaction, query string, args ...any) (User, *uuid.UUID, error) {
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), query), args...)
	if err != nil {
		return User{}, nil, fmt.Errorf("load user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return User{}, nil, err
		}
		return User{}, nil, ErrNotFound
	}
	var u User
	var status string
	var updatedBy sql.Null[uuid.UUID]
	var verified sql.NullTime
	if err := rows.Scan(&u.ID, &u.Email, &u.Name, &status, &verified, &u.CreatedAt, &u.UpdatedAt, &updatedBy, &u.Version); err != nil {
		return User{}, nil, fmt.Errorf("scan user: %w", err)
	}
	u.Status = Status(status)
	if verified.Valid {
		at := verified.Time.UTC()
		u.EmailVerifiedAt = &at
	}
	var by *uuid.UUID
	if updatedBy.Valid {
		by = &updatedBy.V
	}
	return u, by, rows.Err()
}

func setStatus(ctx context.Context, tx db.Transaction, id ID, version int, status Status, by *ID, now time.Time) (sql.Result, error) {
	q := db.Rebind(tx.Dialect(), "UPDATE users SET status = ?, updated_at = ?, updated_by = ?, version = version + 1 WHERE id = ? AND version = ?")
	return tx.Q().ExecContext(ctx, q, string(status), now, by, id, version)
}

// current is a locking read, so on MySQL it reports the committed row rather than tx's snapshot.
func current(tx db.Transaction, id ID) func(ctx context.Context) (occ.Current, error) {
	return func(ctx context.Context) (occ.Current, error) {
		u, by, err := one(ctx, tx, selectUser+"WHERE id = ? FOR UPDATE", id)
		if errors.Is(err, ErrNotFound) {
			return occ.Current{}, ErrNotFound
		}
		if err != nil {
			return occ.Current{}, err
		}
		return occ.Current{Version: u.Version, ChangedBy: by, ChangedAt: u.UpdatedAt}, nil
	}
}

// MarkEmailVerified records that the user proved the address; a second call keeps the first time.
func MarkEmailVerified(ctx context.Context, tx db.Transaction, id ID, at time.Time) error {
	q := db.Rebind(tx.Dialect(), "UPDATE users SET email_verified_at = ? WHERE id = ? AND email_verified_at IS NULL")
	if _, err := tx.Q().ExecContext(ctx, q, at, id); err != nil {
		return fmt.Errorf("mark email verified: %w", err)
	}
	return nil
}

// BumpAccess moves the users' access version, in the transaction of a change to what they may do;
// sessions issued at an older version rotate and reload their principal on the next request.
func BumpAccess(ctx context.Context, tx db.Transaction, ids ...ID) error {
	q := db.Rebind(tx.Dialect(), "UPDATE users SET access_version = access_version + 1 WHERE id = ?")
	for _, id := range ids {
		if _, err := tx.Q().ExecContext(ctx, q, id); err != nil {
			return fmt.Errorf("bump access version: %w", err)
		}
	}
	return nil
}

// AccessVersion is the user's current access version.
func AccessVersion(ctx context.Context, tx db.Transaction, id ID) (int64, error) {
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), "SELECT access_version FROM users WHERE id = ?"), id)
	if err != nil {
		return 0, fmt.Errorf("load access version: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return 0, errors.Join(rows.Err(), ErrNotFound)
	}
	var v int64
	if err := rows.Scan(&v); err != nil {
		return 0, err
	}
	return v, rows.Err()
}

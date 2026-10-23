package files

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/db"
)

const fileColumns = "id, kind, state, uploader_kind, uploader_id, owner_type, owner_id, name, mime, size, sha256, storage_key, visibility, created_at"

func insertFile(ctx context.Context, tx db.Transaction, f File) error {
	q := "INSERT INTO files (" + fileColumns + ", updated_at) VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?)"
	_, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q),
		f.ID, f.Kind, string(f.State), f.Uploader.Kind, uploaderID(f.Uploader), f.Name, f.Mime, f.Size, f.SHA256, f.Key,
		string(f.Visibility), f.CreatedAt, f.CreatedAt)
	if err != nil {
		return fmt.Errorf("files: insert: %w", err)
	}
	return nil
}

// uploaderID is NULL for the system, which has no id.
func uploaderID(u Uploader) uuid.NullUUID {
	return uuid.NullUUID{UUID: u.ID, Valid: u != SystemUploader}
}

func loadFile(ctx context.Context, tx db.Transaction, id ID, lock bool) (File, error) {
	q := "SELECT " + fileColumns + " FROM files WHERE id = ?"
	if lock {
		q += " FOR UPDATE"
	}
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), q), id)
	if err != nil {
		return File{}, fmt.Errorf("files: load: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return File{}, fmt.Errorf("files: load: %w", err)
		}
		return File{}, ErrNotFound
	}
	f, err := scanFile(rows)
	if err != nil {
		return File{}, err
	}
	return f, rows.Err()
}

func scanFile(rows *sql.Rows) (File, error) {
	var f File
	var state, visibility string
	var ownerType sql.NullString
	var ownerID, uploader uuid.NullUUID
	if err := rows.Scan(&f.ID, &f.Kind, &state, &f.Uploader.Kind, &uploader, &ownerType, &ownerID, &f.Name, &f.Mime, &f.Size,
		&f.SHA256, &f.Key, &visibility, &f.CreatedAt); err != nil {
		return File{}, fmt.Errorf("files: scan: %w", err)
	}
	f.Uploader.ID = uploader.UUID
	if ownerType.Valid && ownerID.Valid {
		f.Owner = &Owner{Type: ownerType.String, ID: ownerID.UUID}
	}
	f.State, f.Visibility = State(state), Visibility(visibility)
	f.CreatedAt = f.CreatedAt.UTC()
	return f, nil
}

// byUploader matches the uploader's columns; the system's id is NULL.
func byUploader(u Uploader) (string, []any) {
	if u == SystemUploader {
		return "uploader_kind = ? AND uploader_id IS NULL", []any{u.Kind}
	}
	return "uploader_kind = ? AND uploader_id = ?", []any{u.Kind, u.ID}
}

func stageFile(ctx context.Context, tx db.Transaction, id ID, by Uploader, now time.Time) (bool, error) {
	cond, args := byUploader(by)
	q := "UPDATE files SET state = ?, updated_at = ? WHERE id = ? AND state = ? AND " + cond
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), append([]any{string(Staged), now, id, string(Pending)}, args...)...)
	if err != nil {
		return false, fmt.Errorf("files: stage: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func attachFile(ctx context.Context, tx db.Transaction, id ID, kind string, owner Owner, by Uploader, now time.Time) (bool, error) {
	q := "UPDATE files SET state = ?, owner_type = ?, owner_id = ?, updated_at = ? WHERE id = ? AND kind = ? AND state = ?"
	args := []any{string(Attached), owner.Type, owner.ID, now, id, kind, string(Staged)}
	if by != SystemUploader {
		cond, more := byUploader(by)
		q += " AND " + cond
		args = append(args, more...)
	}
	res, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), args...)
	if err != nil {
		return false, fmt.Errorf("files: attach: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func deleteFile(ctx context.Context, tx db.Transaction, id ID) error {
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), "DELETE FROM files WHERE id = ?"), id); err != nil {
		return fmt.Errorf("files: delete: %w", err)
	}
	return nil
}

func deletePending(ctx context.Context, tx db.Transaction, id ID) error {
	q := "DELETE FROM files WHERE id = ? AND state = ?"
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), q), id, string(Pending)); err != nil {
		return fmt.Errorf("files: delete pending: %w", err)
	}
	return nil
}

// knownKeys returns which of keys have a row.
func knownKeys(ctx context.Context, tx db.Transaction, keys []string) (map[string]bool, error) {
	args := make([]any, len(keys))
	for i, k := range keys {
		args[i] = k
	}
	q := "SELECT storage_key FROM files WHERE storage_key IN (" + placeholders(len(keys)) + ")"
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), q), args...)
	if err != nil {
		return nil, fmt.Errorf("files: known keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	known := make(map[string]bool, len(keys))
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		known[k] = true
	}
	return known, rows.Err()
}

type expired struct {
	id  ID
	key string
}

// takeExpired deletes up to limit pending or staged files last changed before before and returns them;
// SKIP LOCKED passes over a row a Stage or Attach holds, and two sweeps never wait on each other.
func takeExpired(ctx context.Context, tx db.Transaction, before time.Time, limit int) ([]expired, error) {
	out, err := selectExpired(ctx, tx, before, limit)
	if err != nil || len(out) == 0 {
		return nil, err
	}
	args := make([]any, len(out))
	for i, s := range out {
		args[i] = s.id
	}
	del := "DELETE FROM files WHERE id IN (" + placeholders(len(out)) + ")"
	if _, err := tx.Q().ExecContext(ctx, db.Rebind(tx.Dialect(), del), args...); err != nil {
		return nil, fmt.Errorf("files: delete expired: %w", err)
	}
	return out, nil
}

func selectExpired(ctx context.Context, tx db.Transaction, before time.Time, limit int) ([]expired, error) {
	q := "SELECT id, storage_key FROM files WHERE state IN (?, ?) AND updated_at < ? ORDER BY updated_at LIMIT ? FOR UPDATE SKIP LOCKED"
	rows, err := tx.Q().QueryContext(ctx, db.Rebind(tx.Dialect(), q), string(Pending), string(Staged), before, limit)
	if err != nil {
		return nil, fmt.Errorf("files: expired: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []expired
	for rows.Next() {
		var s expired
		if err := rows.Scan(&s.id, &s.key); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

package migrate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"unicode/utf8"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	mysqlLockWaitSeconds = 300
	mysqlMaxLockName     = 64
	mysqlLockPrefix      = "goose:"
)

// mysqlLocker is a goose session locker on GET_LOCK; goose ships only a table locker for MySQL.
type mysqlLocker struct{}

func (mysqlLocker) SessionLock(ctx context.Context, conn *sql.Conn) error {
	name, err := mysqlLockFor(ctx, conn)
	if err != nil {
		return fmt.Errorf("take migration lock: %w", err)
	}
	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", name, mysqlLockWaitSeconds).Scan(&got); err != nil {
		return fmt.Errorf("take migration lock: %w", err)
	}
	if !got.Valid || got.Int64 != 1 {
		return errors.New("take migration lock: another migration holds it")
	}
	return nil
}

func (mysqlLocker) SessionUnlock(ctx context.Context, conn *sql.Conn) error {
	name, err := mysqlLockFor(ctx, conn)
	if err == nil {
		_, err = conn.ExecContext(ctx, "DO RELEASE_LOCK(?)", name)
	}
	if err != nil {
		return fmt.Errorf("release migration lock: %w", err)
	}
	return nil
}

func mysqlLockFor(ctx context.Context, conn *sql.Conn) (string, error) {
	var database sql.NullString
	if err := conn.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&database); err != nil {
		return "", err
	}
	return mysqlLockName(mysqlLockPrefix, database.String), nil
}

// mysqlLockName keeps GET_LOCK names within MySQL's 64-character limit: a longer key becomes its hash.
func mysqlLockName(prefix, key string) string {
	if utf8.RuneCountInString(prefix+key) <= mysqlMaxLockName {
		return prefix + key
	}
	sum := sha256.Sum256([]byte(key))
	return prefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

// neverMigrated is the error of reading versions from a database goose has not touched yet.
func neverMigrated(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "42883" || pgErr.Code == "42P01"
	}
	var myErr *mysql.MySQLError
	return errors.As(err, &myErr) && myErr.Number == 1146
}

func baseName(p string) string { return path.Base(p) }

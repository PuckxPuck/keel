package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"

	"github.com/go-jet/jet/v2/qrm"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	pgUniqueViolation      = "23505"
	pgForeignKeyViolation  = "23503"
	pgSerializationFailure = "40001"
	pgDeadlockDetected     = "40P01"

	myDuplicateEntry   = 1062
	myRowIsReferenced  = 1451
	myNoReferencedRow  = 1452
	myRowIsReferenced0 = 1216
	myNoReferencedRow0 = 1217
	myDeadlock         = 1213
)

func IsUniqueViolation(err error) bool {
	return pgCode(err) == pgUniqueViolation || myNumber(err) == myDuplicateEntry
}

func IsForeignKeyViolation(err error) bool {
	if pgCode(err) == pgForeignKeyViolation {
		return true
	}
	switch myNumber(err) {
	case myRowIsReferenced, myNoReferencedRow, myRowIsReferenced0, myNoReferencedRow0:
		return true
	}
	return false
}

// IsRetryable reports a serialization failure or deadlock: the whole transaction was rolled back and can
// run again. Lock wait timeouts are not retried on either engine (MySQL 1205 rolls back only the statement).
func IsRetryable(err error) bool {
	switch pgCode(err) {
	case pgSerializationFailure, pgDeadlockDetected:
		return true
	}
	return myNumber(err) == myDeadlock
}

// NotFoundOr maps "no rows" to the caller's not-found error and passes every other error through.
func NotFoundOr(err, notFound error) error {
	if errors.Is(err, qrm.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
		return notFound
	}
	return err
}

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func myNumber(err error) uint16 {
	var myErr *mysql.MySQLError
	if errors.As(err, &myErr) {
		return myErr.Number
	}
	return 0
}

func serverError(err error) bool {
	return pgCode(err) != "" || myNumber(err) != 0 || errors.Is(err, pgx.ErrTxCommitRollback)
}

// notSent is true when the driver says the statement never reached the server. database/sql returns
// the bare context error, before sending COMMIT, when the transaction's context is already done.
func notSent(err error) bool {
	return pgconn.SafeToRetry(err) || errors.Is(err, driver.ErrBadConn) ||
		err == context.Canceled || err == context.DeadlineExceeded //nolint:errorlint // only the unwrapped sentinel means not sent
}

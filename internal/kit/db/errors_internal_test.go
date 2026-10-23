package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorClassification(t *testing.T) {
	pg := func(code string) error { return fmt.Errorf("query: %w", &pgconn.PgError{Code: code}) }
	my := func(n uint16) error { return fmt.Errorf("query: %w", &mysql.MySQLError{Number: n}) }
	tests := []struct {
		name                     string
		err                      error
		unique, foreign, retries bool
	}{
		{name: "postgres unique", err: pg("23505"), unique: true},
		{name: "mysql duplicate entry", err: my(1062), unique: true},
		{name: "postgres foreign key", err: pg("23503"), foreign: true},
		{name: "mysql child row without parent", err: my(1452), foreign: true},
		{name: "mysql parent row still referenced", err: my(1451), foreign: true},
		{name: "postgres serialization failure", err: pg("40001"), retries: true},
		{name: "postgres deadlock", err: pg("40P01"), retries: true},
		{name: "mysql deadlock", err: my(1213), retries: true},
		{name: "mysql lock wait timeout is not retried, like postgres 55P03", err: my(1205)},
		{name: "postgres check violation", err: pg("23514")},
		{name: "plain error", err: errors.New("other")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.unique, IsUniqueViolation(tt.err))
			assert.Equal(t, tt.foreign, IsForeignKeyViolation(tt.err))
			assert.Equal(t, tt.retries, IsRetryable(tt.err))
		})
	}
}

func TestClassifyCommit(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		uncertain bool
	}{
		{name: "server refused the commit", err: &pgconn.PgError{Code: "40001"}},
		{name: "mysql server error", err: &mysql.MySQLError{Number: 1213}},
		{name: "postgres rolled back a failed transaction", err: pgx.ErrTxCommitRollback},
		{name: "context done before COMMIT was sent", err: context.Canceled},
		{name: "driver says nothing was sent", err: driver.ErrBadConn},
		{name: "transaction already finished", err: sql.ErrTxDone},
		{name: "connection lost mid-commit", err: io.ErrUnexpectedEOF, uncertain: true},
		{name: "mysql connection lost mid-commit", err: mysql.ErrInvalidConn, uncertain: true},
		{name: "cancelled while COMMIT was in flight", err: fmt.Errorf("timeout: %w", context.Canceled), uncertain: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyCommit(tt.err)
			require.ErrorIs(t, got, tt.err)
			assert.Equal(t, tt.uncertain, errors.Is(got, ErrCommitUncertain))
		})
	}
}

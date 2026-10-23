package db

import (
	"context"
	"strconv"
	"strings"

	"github.com/go-jet/jet/v2/qrm"
)

// Transaction is a Tx of any scope, for kit code that serves every scope (audit, access, users).
// Only Tx implements it, so it still requires an open transaction.
type Transaction interface {
	Q() qrm.DB
	Dialect() Dialect
	Tenancy() bool
	lock(ctx context.Context, name string) error
}

func (t Tx[S]) lock(ctx context.Context, name string) error { return Lock(ctx, t, name) }

// LockIn is Lock for a Transaction.
func LockIn(ctx context.Context, tx Transaction, name string) error {
	return tx.lock(ctx, name)
}

// Rebind turns ? placeholders into $1, $2, ... on Postgres, so kit SQL is written once.
// Kit SQL never has a ? inside a literal.
func Rebind(d Dialect, query string) string {
	if d != Postgres {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for _, r := range query {
		if r != '?' {
			b.WriteRune(r)
			continue
		}
		n++
		b.WriteByte('$')
		b.WriteString(strconv.Itoa(n))
	}
	return b.String()
}

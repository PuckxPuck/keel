// Package occ is optimistic concurrency: updates match `id = ? and version = ?` and bump the version.
package occ

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
)

const CodeStaleVersion = "stale_version"

// Current is the row as it is now, for the client to merge against.
type Current struct {
	Version   int
	ChangedBy *uuid.UUID
	ChangedAt time.Time
}

// StaleError says the row changed since the client read it.
type StaleError struct {
	Current Current
}

func (e *StaleError) Error() string {
	return fmt.Sprintf("stale version: the record is at version %d", e.Current.Version)
}

// Check turns an update that matched no row into a StaleError, or the not-found error load returns
// when the row is gone. MySQL reports changed rows, which is fine because every update bumps version.
func Check(ctx context.Context, res sql.Result, load func(ctx context.Context) (Current, error)) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("occ: rows affected: %w", err)
	}
	if n > 0 {
		return nil
	}
	cur, err := load(ctx)
	if err != nil {
		return err
	}
	return &StaleError{Current: cur}
}

// Mapper answers a StaleError with 409 stale_version, who changed the record and when.
func Mapper(err error) (*problem.Problem, bool) {
	var stale *StaleError
	if !errors.As(err, &stale) {
		return nil, false
	}
	p := problem.New(http.StatusConflict, CodeStaleVersion, "the record was changed by someone else; reload it and try again")
	p.Extensions = map[string]any{
		"currentVersion": stale.Current.Version,
		"changedAt":      stale.Current.ChangedAt.UTC(),
	}
	if stale.Current.ChangedBy != nil {
		p.Extensions["changedBy"] = stale.Current.ChangedBy.String()
	}
	return p, true
}

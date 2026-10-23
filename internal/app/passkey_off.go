//go:build nopasskey

package app

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
)

type (
	PasskeyConfig struct{}
	passkeyWiring struct{}
)

func (w *wiring) openPasskeys(Config, func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error) error {
	return nil
}

func authPrunes() []func(context.Context, db.Transaction, time.Time) (int64, error) { return nil }

func (w *wiring) registerPasskeys(huma.API) {}

func passkeyMapper(error) (*problem.Problem, bool) { return nil, false }

func passkeyParts(Config) []string { return nil }

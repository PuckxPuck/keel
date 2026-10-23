//go:build nooidc

package app

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
)

type (
	OIDCConfig struct{}
	oidcWiring struct{}
)

func (Config) validateOIDC() error { return nil }

func (w *wiring) openOIDC(Config, func(ctx context.Context, fn func(ctx context.Context, tx db.Transaction) error) error) error {
	return nil
}

func (w *wiring) registerOIDC(huma.API) {}

func oidcMapper(error) (*problem.Problem, bool) { return nil, false }

func oidcParts(Config) []string { return nil }

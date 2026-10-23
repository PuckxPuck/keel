//go:build nootel

package app

import (
	"context"
	"net/http"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/logx"
)

type OtelConfig struct{}

func startOtel(context.Context, Config) (func(context.Context) error, error) {
	return func(context.Context) error { return nil }, nil
}

func otelMiddleware(Config) []func(http.Handler) http.Handler { return nil }

func otelOpenOptions(Config) []db.OpenOption { return nil }

func otelJobs(Config, *jobs.Options) {}

func otelLogOptions(Config) []logx.Option { return nil }

func otelParts(Config) []string { return nil }

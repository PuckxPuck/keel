//go:build !nootel

package app

import (
	"cmp"
	"context"
	"net/http"

	"github.com/PuckxPuck/keel/internal/kit/buildinfo"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/otelx"
)

// OtelConfig is APP_OTEL_*: traces and metrics go to the collector at APP_OTEL_ENDPOINT, and nowhere
// without one.
type OtelConfig = otelx.Config

// startOtel installs the exporters; shutdown flushes them.
func startOtel(ctx context.Context, cfg Config) (shutdown func(context.Context) error, err error) {
	return otelx.Start(ctx, cfg.Otel, otelx.Resource{Service: otelService(cfg), Version: buildinfo.Get().Version, Environment: string(cfg.Env)})
}

func otelService(cfg Config) string { return cmp.Or(cfg.Otel.Service, cfg.App.Name, Name) }

func otelMiddleware(cfg Config) []func(http.Handler) http.Handler {
	if !cfg.Otel.Enabled() {
		return nil
	}
	return []func(http.Handler) http.Handler{otelx.Middleware(otelService(cfg))}
}

func otelOpenOptions(cfg Config) []db.OpenOption {
	if !cfg.Otel.Enabled() {
		return nil
	}
	return []db.OpenOption{db.Connector(otelx.OpenDB)}
}

func otelJobs(cfg Config, o *jobs.Options) {
	if cfg.Otel.Enabled() {
		o.Trace, o.Metrics = otelx.Jobs()
	}
}

func otelLogOptions(cfg Config) []logx.Option {
	if !cfg.Otel.Enabled() {
		return nil
	}
	return []logx.Option{logx.ContextAttrs(otelx.LogAttrs)}
}

func otelParts(cfg Config) []string {
	if cfg.Otel.Enabled() {
		return []string{"otel"}
	}
	return nil
}

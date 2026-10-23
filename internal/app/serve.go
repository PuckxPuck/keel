package app

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"time"

	"github.com/PuckxPuck/keel/internal/kit/buildinfo"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/server"
)

// otelFlushTimeout bounds the export of the last spans and metrics at exit.
const otelFlushTimeout = 5 * time.Second

func flushOtel(ctx context.Context, stop func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), otelFlushTimeout)
	defer cancel()
	if err := stop(ctx); err != nil {
		logx.From(ctx).Warn("telemetry not flushed", "error", err)
	}
}

func serve(environ []string) runFunc {
	return func(ctx context.Context, _ *flag.FlagSet, _ []string) error {
		cfg, err := LoadConfig(environ)
		if err != nil {
			return errors.New("invalid configuration:\n" + err.Error())
		}
		logger := logx.New(cfg.Log, os.Stderr, otelLogOptions(cfg)...)
		slog.SetDefault(logger)
		ctx = logx.WithLogger(ctx, logger)
		stopOtel, err := startOtel(ctx, cfg)
		if err != nil {
			return err
		}
		defer flushOtel(ctx, stopOtel)

		deps, err := OpenDatabase(ctx, cfg)
		if err != nil {
			return err
		}
		defer func() { _ = deps.DB.Close() }()

		built, err := Build(ctx, cfg, deps)
		if err != nil {
			return err
		}

		ln, err := server.Listen(ctx, cfg.HTTP.Addr)
		if err != nil {
			return err
		}
		info := buildinfo.Get()
		logger.Info("starting", "addr", cfg.HTTP.Addr, "env", string(cfg.Env), "version", info.Version, "commit", info.Commit, "workers", cfg.Jobs.InServe)
		built.Ready()

		var background []func(context.Context) error
		if cfg.Jobs.InServe {
			background = append(background, func(ctx context.Context) error { return built.Queue.Run(ctx) })
		}
		return server.Serve(ctx, ln, server.Options{
			Handler:           built.Handler,
			ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
			ReadTimeout:       cfg.HTTP.ReadTimeout,
			WriteTimeout:      cfg.HTTP.WriteTimeout,
			IdleTimeout:       cfg.HTTP.IdleTimeout,
			MaxHeaderBytes:    int(cfg.HTTP.MaxHeaderBytes),
			DrainDelay:        cfg.HTTP.ShutdownDrain,
			ShutdownTimeout:   cfg.HTTP.ShutdownTimeout,
			OnDrain:           built.Drain,
		}, background...)
	}
}

//go:build deploytest

// Command notready is a release that passes its migrations and listens on its slot but never reports
// ready, so the switch test can prove release.sh stops it.
package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		return
	}
	if err := serve(); err != nil {
		os.Exit(1)
	}
}

func serve() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", os.Getenv("APP_HTTP_ADDR")) //nolint:forbidigo // a stand-in for the app reads its slot address the same way
	if err != nil {
		return err
	}
	srv := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}),
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

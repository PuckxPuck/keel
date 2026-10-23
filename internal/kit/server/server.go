package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/PuckxPuck/keel/internal/kit/logx"
)

const (
	unixPrefix     = "unix:"
	socketMode     = 0o660
	staleDialLimit = time.Second
)

type Options struct {
	Addr              string
	Handler           http.Handler
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
	// DrainDelay is how long the listener keeps accepting after OnDrain, so the proxy can move traffic.
	DrainDelay time.Duration
	// ShutdownTimeout bounds Shutdown and the background workers together; the whole stop takes at most DrainDelay plus this.
	ShutdownTimeout time.Duration
	// OnDrain runs first when shutdown starts; it makes readiness fail.
	OnDrain func()
}

// Run listens on opts.Addr and serves until ctx is cancelled or a component fails, then
// shuts down in order: readiness off, drain delay, graceful Shutdown, background workers.
func Run(ctx context.Context, opts Options, background ...func(ctx context.Context) error) error {
	ln, err := Listen(ctx, opts.Addr)
	if err != nil {
		return err
	}
	return Serve(ctx, ln, opts, background...)
}

// Serve is Run on a listener the caller made.
func Serve(ctx context.Context, ln net.Listener, opts Options, background ...func(ctx context.Context) error) error {
	srv := &http.Server{
		Handler:                      opts.Handler,
		DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout:            opts.ReadHeaderTimeout,
		ReadTimeout:                  opts.ReadTimeout,
		WriteTimeout:                 opts.WriteTimeout,
		IdleTimeout:                  opts.IdleTimeout,
		MaxHeaderBytes:               opts.MaxHeaderBytes,
		BaseContext:                  func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
		ErrorLog:                     slog.NewLogLogger(logx.From(ctx).Handler(), slog.LevelWarn),
	}

	// Workers outlive the signal: they stop only after the server has finished its requests.
	workerCtx, stopWorkers := context.WithCancel(context.WithoutCancel(ctx))
	defer stopWorkers()
	stopCtx, stop := context.WithCancel(ctx)
	defer stop()

	var serveFailed atomic.Bool
	var group errgroup.Group
	group.Go(func() error {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		serveFailed.Store(true)
		stop()
		return fmt.Errorf("serve: %w", err)
	})
	for _, fn := range background {
		group.Go(func() error {
			err := fn(workerCtx)
			switch {
			case err == nil:
				return nil
			case workerCtx.Err() != nil && errors.Is(err, context.Canceled):
				return nil
			}
			stop()
			return fmt.Errorf("background worker: %w", err)
		})
	}

	<-stopCtx.Done()
	logx.From(ctx).Info("shutting down")
	deadline, cancel := context.WithTimeout(context.WithoutCancel(ctx), opts.DrainDelay+opts.ShutdownTimeout)
	defer cancel()
	shutdownErr := shutdown(deadline, srv, opts, !serveFailed.Load())

	stopWorkers()
	waitErr := wait(deadline, &group)
	return errors.Join(shutdownErr, waitErr)
}

// shutdown drains whenever the server was serving, so the proxy stops routing here before the listener closes.
func shutdown(deadline context.Context, srv *http.Server, opts Options, drain bool) error {
	if opts.OnDrain != nil {
		opts.OnDrain()
	}
	if drain && opts.DrainDelay > 0 {
		time.Sleep(opts.DrainDelay)
	}
	if err := srv.Shutdown(deadline); err != nil {
		_ = srv.Close() // requests that outlived the deadline are cut
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

func wait(deadline context.Context, group *errgroup.Group) error {
	done := make(chan error, 1)
	go func() { done <- group.Wait() }()
	select {
	case err := <-done:
		return err
	case <-deadline.Done():
		return errors.New("background workers did not stop in time")
	}
}

// Listen opens a TCP address, or a unix socket for "unix:/path" (a stale socket file is removed first).
func Listen(ctx context.Context, addr string) (net.Listener, error) {
	path, isUnix := strings.CutPrefix(addr, unixPrefix)
	if isUnix {
		return listenUnix(ctx, path)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return ln, nil
}

// listenUnix binds inside a fresh 0700 directory and links the socket into place once it is 0660,
// so it is never reachable with the umask's mode; changing the process umask would race other goroutines.
func listenUnix(ctx context.Context, path string) (net.Listener, error) {
	if err := removeStaleSocket(ctx, path); err != nil {
		return nil, err
	}
	private, err := os.MkdirTemp(filepath.Dir(path), ".sock")
	if err != nil {
		return nil, fmt.Errorf("listen unix:%s: %w", path, err)
	}
	defer func() { _ = os.RemoveAll(private) }()

	bound := filepath.Join(private, "s")
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", bound)
	if err != nil {
		return nil, fmt.Errorf("listen unix:%s: %w", path, err)
	}
	ul, _ := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	if err := os.Chmod(bound, socketMode); err != nil { //nolint:gosec // group access to the socket is the point
		_ = ul.Close()
		return nil, fmt.Errorf("chmod %s: %w", path, err)
	}
	// A link never replaces an existing file, unlike a rename.
	if err := os.Link(bound, path); err != nil {
		_ = ul.Close()
		return nil, fmt.Errorf("listen unix:%s: %w", path, err)
	}
	return &unixListener{UnixListener: ul, path: path}, nil
}

type unixListener struct {
	*net.UnixListener
	path string
	once sync.Once
}

func (l *unixListener) Addr() net.Addr { return &net.UnixAddr{Name: l.path, Net: "unix"} }

func (l *unixListener) Close() error {
	err := l.UnixListener.Close()
	l.once.Do(func() { _ = os.Remove(l.path) })
	return err
}

// removeStaleSocket deletes a leftover socket only when a dial proves nobody listens on it.
// Any other dial failure (permissions, a full backlog) leaves the file alone and refuses to start.
func removeStaleSocket(ctx context.Context, path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check socket %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	dialer := net.Dialer{Timeout: staleDialLimit}
	conn, err := dialer.DialContext(ctx, "unix", path)
	switch {
	case err == nil:
		_ = conn.Close()
		return fmt.Errorf("%s is in use by another process", path)
	case errors.Is(err, os.ErrNotExist):
		return nil
	case !errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("%s exists and cannot be checked, so it is left in place: %w", path, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	return nil
}

package server_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/health"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/server"
)

const (
	drainDelay      = 5 * time.Second
	shutdownTimeout = 20 * time.Second
)

// pipeListener is an in-memory listener, so the server runs inside a synctest bubble on fake time.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return &net.UnixAddr{Name: "pipe", Net: "pipe"} }

func (l *pipeListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	server, client := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.closed:
		return nil, errors.New("connection refused")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type harness struct {
	t      *testing.T
	ln     *pipeListener
	client *http.Client
	checks *health.Health
	router chi.Router
}

func newHarness(t *testing.T) *harness {
	ln := newPipeListener()
	checks := health.New()
	checks.Ready()
	router := chi.NewRouter()
	checks.Mount(router)
	router.Get("/work", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	client := &http.Client{Transport: &http.Transport{DialContext: ln.dial, DisableKeepAlives: true}}
	t.Cleanup(client.CloseIdleConnections)
	return &harness{t: t, ln: ln, client: client, checks: checks, router: router}
}

func (h *harness) status(path string) (int, error) {
	req, err := http.NewRequestWithContext(h.t.Context(), http.MethodGet, "http://app"+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func (h *harness) serve(ctx context.Context, onDrain func(), background ...func(context.Context) error) <-chan error {
	ctx = logx.WithLogger(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx, h.ln, server.Options{
			Handler:         h.router,
			DrainDelay:      drainDelay,
			ShutdownTimeout: shutdownTimeout,
			OnDrain: func() {
				h.checks.Drain()
				if onDrain != nil {
					onDrain()
				}
			},
		}, background...)
	}()
	return done
}

func TestServe_DrainKeepsServingWhileReadinessFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t)
		h.router.Get("/slow", func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(drainDelay + time.Second)
			w.WriteHeader(http.StatusNoContent)
		})
		var mu sync.Mutex
		var order []string
		mark := func(s string) {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, s)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := h.serve(ctx, func() { mark("drain") }, func(ctx context.Context) error {
			<-ctx.Done()
			mark("worker stopped")
			return ctx.Err()
		})

		code, err := h.status("/readyz")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
		slow := make(chan error, 1)
		go func() {
			code, err := h.status("/slow")
			if err == nil && code != http.StatusNoContent {
				err = errors.New("slow request failed")
			}
			slow <- err
		}()
		synctest.Wait()

		cancel()
		synctest.Wait()

		code, err = h.status("/readyz")
		require.NoError(t, err, "the listener still accepts during the drain")
		assert.Equal(t, http.StatusServiceUnavailable, code)
		code, err = h.status("/work")
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, code)
		mu.Lock()
		assert.Equal(t, []string{"drain"}, order, "workers keep running during the drain")
		mu.Unlock()

		require.NoError(t, <-slow, "an in-flight request finishes")
		require.NoError(t, <-done)
		assert.Equal(t, []string{"drain", "worker stopped"}, order)
		_, err = h.status("/work")
		assert.Error(t, err, "the listener is closed after shutdown")
	})
}

func TestServe_FailingWorkerStillDrains(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t)
		fail := make(chan struct{})
		done := h.serve(t.Context(), nil, func(context.Context) error {
			<-fail
			return errors.New("queue lost")
		})
		synctest.Wait()

		close(fail)
		synctest.Wait()

		code, err := h.status("/work")
		require.NoError(t, err, "the listener still accepts during the drain")
		assert.Equal(t, http.StatusNoContent, code)
		code, err = h.status("/readyz")
		require.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, code)

		require.ErrorContains(t, <-done, "queue lost")
	})
}

func TestServe_DrainAndShutdownShareOneDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newHarness(t)
		release := make(chan struct{})
		h.router.Get("/stuck", func(http.ResponseWriter, *http.Request) { <-release })
		ctx, cancel := context.WithCancel(t.Context())
		done := h.serve(ctx, nil, func(context.Context) error {
			<-release
			return nil
		})
		go func() { _, _ = h.status("/stuck") }()
		synctest.Wait()

		cancel()
		time.Sleep(drainDelay + shutdownTimeout - time.Millisecond)
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("returned before the deadline: %v", err)
		default:
		}

		time.Sleep(time.Millisecond)
		synctest.Wait()
		select {
		case err := <-done:
			require.ErrorContains(t, err, "background workers did not stop in time")
		default:
			t.Fatal("still stopping after drain plus shutdown timeout")
		}
		close(release)
		synctest.Wait()
	})
}

func TestListen_UnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "keel")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "app.sock")

	var lc net.ListenConfig
	stale, err := lc.Listen(t.Context(), "unix", path)
	require.NoError(t, err)
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, stale.Close())
	require.FileExists(t, path)

	ln, err := server.Listen(t.Context(), "unix:"+path)
	require.NoError(t, err)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o660), info.Mode().Perm())
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "the private bind directory is removed")

	_, err = server.Listen(t.Context(), "unix:"+path)
	require.ErrorContains(t, err, "in use")

	require.NoError(t, os.Chmod(path, 0))
	_, err = server.Listen(t.Context(), "unix:"+path)
	require.Error(t, err, "a socket that cannot be dialled is never removed")
	require.NoError(t, os.Chmod(path, 0o660)) //nolint:gosec // restoring the socket's own mode
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "unix", path)
	require.NoError(t, err, "the live listener still answers")
	require.NoError(t, conn.Close())

	require.NoError(t, ln.Close())
	assert.NoFileExists(t, path)

	regular := filepath.Join(dir, "data.txt")
	require.NoError(t, os.WriteFile(regular, []byte("keep me"), 0o600))
	_, err = server.Listen(t.Context(), "unix:"+regular)
	require.ErrorContains(t, err, "not a socket")
	assert.FileExists(t, regular)
}

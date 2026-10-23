package health_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/health"
)

func get(ctx context.Context, h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil))
	return rec
}

func mount(h *health.Health) http.Handler {
	r := chi.NewRouter()
	h.Mount(r)
	return r
}

func started(h *health.Health) *health.Health {
	h.Ready()
	return h
}

func TestReadyz_FailsUntilStartedAndAtOnceWhenDraining(t *testing.T) {
	h := health.New()
	srv := mount(h)
	assert.Equal(t, http.StatusServiceUnavailable, get(t.Context(), srv, "/readyz").Code)
	assert.Equal(t, http.StatusOK, get(t.Context(), srv, "/livez").Code)

	h.Ready()
	require.Equal(t, http.StatusOK, get(t.Context(), srv, "/readyz").Code)

	h.Drain()

	assert.Equal(t, http.StatusServiceUnavailable, get(t.Context(), srv, "/readyz").Code)
	assert.Equal(t, http.StatusOK, get(t.Context(), srv, "/livez").Code)
}

func TestLivez_SaysOnlyOK(t *testing.T) {
	srv := mount(health.New())

	assert.JSONEq(t, `{"data":{"status":"ok"}}`, get(t.Context(), srv, "/livez").Body.String())
	for _, path := range []string{"/livez", "/readyz"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodHead, path, nil))
		assert.NotEqual(t, http.StatusMethodNotAllowed, rec.Code, path)
	}
}

func TestReadyz_ReportsFailingChecksWithoutTheirErrors(t *testing.T) {
	srv := mount(started(health.New(health.Check{Name: "database", Run: func(context.Context) error {
		return errors.New("dial tcp 10.1.2.3:5432: connection refused")
	}})))

	rec := get(t.Context(), srv, "/readyz")

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), `"database":"failing"`)
	assert.NotContains(t, rec.Body.String(), "10.1.2.3")
}

func TestReadyz_CachesResultsAndNeverRunsAChecksConcurrently(t *testing.T) {
	var runs, running, maxRunning atomic.Int32
	release := make(chan struct{})
	srv := mount(started(health.New(health.Check{Name: "slow", Run: func(context.Context) error {
		runs.Add(1)
		n := running.Add(1)
		maxRunning.Store(max(maxRunning.Load(), n))
		<-release
		running.Add(-1)
		return nil
	}})))
	start := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	ctx := clock.WithWall(t.Context(), clock.Fixed(start))

	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for range 8 {
		wg.Go(func() { codes <- get(ctx, srv, "/readyz").Code })
	}
	require.Eventually(t, func() bool { return runs.Load() == 1 }, time.Second, time.Millisecond)
	close(release)
	wg.Wait()
	close(codes)
	for code := range codes {
		assert.Equal(t, http.StatusOK, code)
	}

	get(ctx, srv, "/readyz")
	assert.Equal(t, int32(1), runs.Load(), "fresh result is reused")
	assert.Equal(t, int32(1), maxRunning.Load())

	later := clock.WithWall(t.Context(), clock.Fixed(start.Add(6*time.Second)))
	get(later, srv, "/readyz")
	assert.Equal(t, int32(2), runs.Load(), "stale result is refreshed")
}

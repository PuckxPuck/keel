package ratelimit_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

func TestMiddleware_RefusesWithRetryAfterAndPolicyHeaders(t *testing.T) {
	problem.Install()
	lim := ratelimit.New(ratelimit.NewMemory(100))
	lim.Define("tight", ratelimit.Rule{Key: ratelimit.ByAddress, Rate: ratelimit.Rate{Limit: 2, Period: time.Minute}})
	router := httpx.NewRouter()
	router.Use(httpx.ClientAddress(config.Proxy{}))
	api := httpx.NewAPI(router, httpx.Options{Title: "t", Version: "1"})
	api.UseMiddleware(lim.Middleware(api))
	httpx.Register(api, huma.Operation{OperationID: "op", Method: http.MethodGet, Path: "/op"},
		func(context.Context, *struct{}) (*httpx.NoContent, error) { return &httpx.NoContent{}, nil }, ratelimit.Class("tight"))
	require.NoError(t, lim.Check(api))

	call := func(addr string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/op", nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	first := call("203.0.113.7:1000")
	assert.Equal(t, http.StatusNoContent, first.Code)
	assert.Equal(t, `"tight";q=2;w=60`, first.Header().Get("RateLimit-Policy"))
	assert.Equal(t, `"tight";r=1;t=30`, first.Header().Get("RateLimit"))
	call("203.0.113.7:1001")

	refused := call("203.0.113.7:1002")
	assert.Equal(t, http.StatusTooManyRequests, refused.Code)
	assert.Equal(t, "30", refused.Header().Get("Retry-After"))
	assert.Contains(t, refused.Body.String(), `"code":"rate_limited"`)

	call("[2001:db8:1:2::9]:1")
	call("[2001:db8:1:2:aaaa::1]:1")
	assert.Equal(t, http.StatusTooManyRequests, call("[2001:db8:1:2::8]:1").Code, "one IPv6 /64 is one client")
	assert.Equal(t, http.StatusNoContent, call("[2001:db8:1:3::1]:1").Code, "another /64 has its own bucket")
}

// Concurrent hits through many pooled connections count against one window: exactly the limit
// gets through, as it would across replicas.
func TestDBStore_CountsOneWindowAcrossConnections(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		store := ratelimit.NewDBStore(e.DB().SQL(), e.Dialect())
		rate := ratelimit.Rate{Limit: 5, Period: time.Minute}
		key := "auth:" + ids.New().String()
		ctx := clock.WithWall(t.Context(), clock.Fixed(time.Date(2026, 10, 22, 12, 0, 30, 0, time.UTC)))

		var allowed atomic.Int32
		errs := make(chan error, 12)
		var wg sync.WaitGroup
		for range 12 {
			wg.Go(func() {
				d, err := store.Take(ctx, key, rate)
				errs <- err
				if d.Allowed {
					allowed.Add(1)
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
		assert.Equal(t, int32(5), allowed.Load())

		d, err := store.Take(ctx, key, rate)
		require.NoError(t, err)
		assert.False(t, d.Allowed)
		assert.Equal(t, 30*time.Second, d.RetryAfter, "until the window ends")

		late := clock.WithWall(t.Context(), clock.Fixed(time.Date(2026, 10, 22, 12, 0, 30, 600_000_000, time.UTC)))
		d, err = store.Take(late, key, rate)
		require.NoError(t, err)
		assert.Equal(t, 30*time.Second, d.RetryAfter, "29.4 s rounds up, never early")

		next := clock.WithWall(t.Context(), clock.Fixed(time.Date(2026, 10, 22, 12, 1, 0, 0, time.UTC)))
		d, err = store.Take(next, key, rate)
		require.NoError(t, err)
		assert.True(t, d.Allowed, "a new window starts from zero")
		assert.Equal(t, 4, d.Remaining)
	})
}

type brokenStore struct{}

func (brokenStore) Take(context.Context, string, ratelimit.Rate) (ratelimit.Decision, error) {
	return ratelimit.Decision{}, errors.New("database is down")
}

// A failing store refuses requests on every path unless the rule fails open.
func TestLimiter_FailingStoreFailsClosed(t *testing.T) {
	problem.Install()
	ok := func(context.Context, *struct{}) (*httpx.NoContent, error) { return &httpx.NoContent{}, nil }
	for _, failOpen := range []bool{false, true} {
		lim := ratelimit.New(ratelimit.NewMemory(10))
		lim.Define("down", ratelimit.Rule{Key: ratelimit.ByAddress, Rate: ratelimit.Rate{Limit: 5, Period: time.Minute}, Store: brokenStore{}, FailOpen: failOpen})
		lim.Define("fine", ratelimit.Rule{Key: ratelimit.ByAddress, Rate: ratelimit.Rate{Limit: 5, Period: time.Minute}})
		router := httpx.NewRouter()
		router.With(lim.HTTP("down")).Get("/plain", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
		preAuth := httpx.NewAPI(router, httpx.Options{Title: "t", Version: "1", BasePath: "/pre"})
		preAuth.UseMiddleware(lim.PreAuth(preAuth, "down"))
		httpx.Register(preAuth, huma.Operation{OperationID: "pre", Method: http.MethodGet, Path: "/op"}, ok, ratelimit.Class("fine"))
		byClass := httpx.NewAPI(router, httpx.Options{Title: "t", Version: "1", BasePath: "/class"})
		byClass.UseMiddleware(lim.Middleware(byClass))
		httpx.Register(byClass, huma.Operation{OperationID: "class", Method: http.MethodGet, Path: "/op"}, ok, ratelimit.Class("down"))

		want := http.StatusServiceUnavailable
		if failOpen {
			want = http.StatusNoContent
		}
		for _, path := range []string{"/plain", "/pre/op", "/class/op"} {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
			assert.Equal(t, want, rec.Code, "%s fail open %v", path, failOpen)
		}
	}
}

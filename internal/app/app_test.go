package app_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

// signingKeys is APP_SESSION_KEYS for tests: required outside local.
const signingKeys = "APP_SESSION_KEYS=a2VlbC10ZXN0LXNpZ25pbmcta2V5LW9mLTMyLWJ5dGVzIQ=="

func build(t *testing.T, env []string, extra ...func(huma.API)) app.Built {
	t.Helper()
	environ := append([]string{"APP_ENV=test", "APP_PUBLIC_URL=http://localhost:8080", signingKeys}, env...)
	cfg, err := app.LoadConfig(environ)
	require.NoError(t, err)
	built, err := app.Build(t.Context(), cfg, app.Deps{}, extra...)
	require.NoError(t, err)
	return built
}

func send(t *testing.T, h http.Handler, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := logx.WithLogger(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func serve(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	return send(t, h, method, target, "", nil)
}

type echoInput struct {
	Body struct {
		Name string `json:"name" minLength:"3"`
	}
}

type blobInput struct {
	Body struct {
		Blob string `json:"blob"`
	}
}

func blob(n int) string { return `{"blob":"` + strings.Repeat("a", n) + `"}` }

var publicWrite = []httpx.Option{rbac.Public(), ratelimit.Class(ratelimit.ClassAPIWrite)}

func testOperations(api huma.API) {
	httpx.Register(api, huma.Operation{OperationID: "testEcho", Method: http.MethodPost, Path: "/test/echo", Tags: []string{"test"}},
		func(_ context.Context, in *echoInput) (*httpx.One[map[string]string], error) {
			return httpx.OneOf(map[string]string{"name": in.Body.Name}), nil
		}, publicWrite...)
	httpx.Register(api, huma.Operation{OperationID: "testPanic", Method: http.MethodGet, Path: "/test/panic", Tags: []string{"test"}},
		func(context.Context, *struct{}) (*httpx.One[map[string]string], error) { panic("boom") }, publicWrite...)
	httpx.Register(api, huma.Operation{OperationID: "testBlob", Method: http.MethodPost, Path: "/test/blob", Tags: []string{"test"}},
		func(context.Context, *blobInput) (*httpx.NoContent, error) { return &httpx.NoContent{}, nil }, publicWrite...)
	httpx.Register(api, huma.Operation{OperationID: "testBigBlob", Method: http.MethodPost, Path: "/test/big-blob", MaxBodyBytes: 4 << 20, Tags: []string{"test"}},
		func(context.Context, *blobInput) (*httpx.NoContent, error) { return &httpx.NoContent{}, nil }, publicWrite...)
}

func TestBuild_Ping(t *testing.T) {
	rec := serve(t, build(t, nil).Handler, http.MethodGet, "/api/v1/ping")

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"data":{"message":"pong"}}`, rec.Body.String())
	assert.NotEmpty(t, rec.Header().Get("X-Request-Id"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Empty(t, rec.Header().Get("Strict-Transport-Security"))
}

func TestBuild_EveryErrorIsAProblemWithRequestIDAndSecurityHeaders(t *testing.T) {
	h := build(t, []string{"APP_HTTP_MAX_BODY_BYTES=1KiB"}, testOperations).Handler

	tests := []struct {
		name, method, target, body string
		wantStatus                 int
		wantCode                   string
	}{
		{"unknown route", http.MethodGet, "/api/v1/nothing", "", http.StatusNotFound, "not_found"},
		{"wrong method", http.MethodPost, "/api/v1/ping", "", http.StatusMethodNotAllowed, "method_not_allowed"},
		{"oversized body", http.MethodPost, "/api/v1/test/echo", `{"name":"` + strings.Repeat("a", 2048) + `"}`, http.StatusRequestEntityTooLarge, "too_large"},
		{"malformed json", http.MethodPost, "/api/v1/test/echo", `{"name":`, http.StatusBadRequest, "invalid_json"},
		{"validation", http.MethodPost, "/api/v1/test/echo", `{"name":"ab"}`, http.StatusUnprocessableEntity, "validation_failed"},
		{"panic", http.MethodGet, "/api/v1/test/panic", "", http.StatusInternalServerError, "internal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := send(t, h, tt.method, tt.target, tt.body, nil)

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
			var body map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
			assert.Equal(t, tt.wantCode, body["code"])
			assert.NotEmpty(t, body["requestId"])
			assert.Equal(t, rec.Header().Get("X-Request-Id"), body["requestId"])
			assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
			if tt.wantStatus == http.StatusMethodNotAllowed {
				assert.Equal(t, "GET", rec.Header().Get("Allow"))
			}
		})
	}
}

func TestBuild_CrossSitePostIsRefused(t *testing.T) {
	h := build(t, nil).Handler
	crossSite := map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}

	for _, target := range []string{"/api/v1/ping", "/livez"} {
		rec := send(t, h, http.MethodPost, target, "", crossSite)

		assert.Equal(t, http.StatusForbidden, rec.Code, target)
		assert.Contains(t, rec.Body.String(), `"code":"cross_origin_blocked"`, target)
		assert.Contains(t, rec.Body.String(), `"requestId":"`+rec.Header().Get("X-Request-Id")+`"`, target)
	}
}

func TestBuild_BodyCapIsTheOperationDefaultAndOperationsMayRaiseIt(t *testing.T) {
	h := build(t, []string{"APP_HTTP_MAX_BODY_BYTES=2MiB"}, testOperations).Handler

	assert.Equal(t, http.StatusNoContent, send(t, h, http.MethodPost, "/api/v1/test/blob", blob(3<<19), nil).Code, "above Huma's own 1 MiB default")
	atCap := 2<<20 - len(blob(0))
	assert.Equal(t, http.StatusNoContent, send(t, h, http.MethodPost, "/api/v1/test/blob", blob(atCap), nil).Code, "a body of exactly the cap")
	assert.Equal(t, http.StatusRequestEntityTooLarge, send(t, h, http.MethodPost, "/api/v1/test/blob", blob(atCap+1), nil).Code)
	assert.Equal(t, http.StatusNoContent, send(t, h, http.MethodPost, "/api/v1/test/big-blob", blob(3<<20), nil).Code, "the global cap does not apply to operations")
}

func TestBuild_HealthRoutesAreMountedBehindTheStartupGate(t *testing.T) {
	built := build(t, nil)

	assert.Equal(t, http.StatusOK, serve(t, built.Handler, http.MethodGet, "/livez").Code)
	assert.Equal(t, http.StatusServiceUnavailable, serve(t, built.Handler, http.MethodGet, "/readyz").Code)
	built.Ready()
	assert.Equal(t, http.StatusOK, serve(t, built.Handler, http.MethodGet, "/readyz").Code)
}

// Probes from this host, directly or through a trusted local proxy, are never rate limited; others are.
func TestBuild_HealthIsNotLimitedForLocalProbes(t *testing.T) {
	h := build(t, []string{"APP_RATE_HEALTH=1/1m", "APP_PROXY_TRUSTED=127.0.0.1/32"}).Handler
	probe := func(remote, forwarded string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/livez", nil)
		req.RemoteAddr = remote
		if forwarded != "" {
			req.Header.Set("X-Forwarded-For", forwarded)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for range 3 {
		assert.Equal(t, http.StatusOK, probe("127.0.0.1:5000", "").Code, "loopback")
		assert.Equal(t, http.StatusOK, probe("127.0.0.1:5000", "198.51.100.4").Code, "through a trusted local proxy")
	}
	assert.Equal(t, http.StatusOK, probe("203.0.113.9:5000", "").Code)
	refused := probe("203.0.113.9:5001", "")
	assert.Equal(t, http.StatusTooManyRequests, refused.Code)
	assert.NotEmpty(t, refused.Header().Get("Retry-After"))
}

func TestBuild_DocsOnlyWhenEnabled(t *testing.T) {
	assert.Equal(t, http.StatusNotFound, serve(t, build(t, nil).Handler, http.MethodGet, "/api/v1/openapi.json").Code)
	assert.Equal(t, http.StatusNotFound, serve(t, build(t, nil).Handler, http.MethodGet, "/api/v1/docs").Code)

	on := serve(t, build(t, []string{"APP_HTTP_DOCS=true"}).Handler, http.MethodGet, "/api/v1/openapi.json")
	require.Equal(t, http.StatusOK, on.Code)
	var spec struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	require.NoError(t, json.Unmarshal(on.Body.Bytes(), &spec))
	assert.Contains(t, spec.Paths, "/api/v1/ping")
}

func TestOperations_UseTheEnvelope(t *testing.T) {
	set, err := app.Operations()
	require.NoError(t, err)

	set.Each(func(_ realm.Realm, api huma.API) {
		require.NoError(t, httpx.CheckOutputs(api))
	})
}

// failedChecks runs doctor without a database in the local profile and lists the failed checks.
func failedChecks(t *testing.T, env ...string) []string { //nolint:unused // used by the mail, files and pdf parts' tests
	t.Helper()
	cfg, err := app.LoadConfig(append([]string{"APP_ENV=local", signingKeys}, env...))
	require.NoError(t, err)
	var failed []string
	for _, c := range app.Diagnose(t.Context(), cfg, app.Deps{}) {
		if c.Status == app.Fail {
			failed = append(failed, c.Name+": "+c.Detail)
		}
	}
	return failed
}

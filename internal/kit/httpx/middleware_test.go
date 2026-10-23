package httpx_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/logx"
)

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	assert.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body
}

func quietLogs(next http.Handler) http.Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(logx.WithLogger(r.Context(), logger)))
	})
}

func TestRecover_PanicBecomesProblemWithOnlyTheHeadersSetBeforeIt(t *testing.T) {
	h := quietLogs(httpx.RequestID(httpx.SecurityHeaders(false)(httpx.Recover(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc")
		w.Header().Set("Content-Length", "2")
		w.Header().Set("Content-Disposition", "attachment")
		panic("database password is hunter2")
	})))))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	body := decodeProblem(t, rec)
	assert.Equal(t, "internal", body["code"])
	assert.Equal(t, rec.Header().Get("X-Request-Id"), body["requestId"])
	assert.NotContains(t, rec.Body.String(), "hunter2")
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Empty(t, rec.Header().Get("Set-Cookie"))
	assert.Empty(t, rec.Header().Get("Content-Length"))
	assert.Empty(t, rec.Header().Get("Content-Disposition"))
}

func TestRecover_AbortHandlerPassesThrough(t *testing.T) {
	h := httpx.Recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))

	assert.PanicsWithValue(t, http.ErrAbortHandler, func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	})
}

func TestRecover_DoesNotWriteAfterHeadersWentOut(t *testing.T) {
	h := quietLogs(httpx.Recover(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("partial"))
		panic("boom")
	})))
	rec := httptest.NewRecorder()

	assert.PanicsWithValue(t, http.ErrAbortHandler, func() {
		h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	})
	assert.Equal(t, "partial", rec.Body.String())
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequestID_IncomingValueOnlyFromATrustedProxyAndStrictPattern(t *testing.T) {
	proxy := config.Proxy{Trusted: config.TrustedProxies{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}}
	tests := []struct {
		name     string
		remote   string
		incoming string
		keep     bool
	}{
		{"well formed from the proxy", "10.0.0.1:4000", "req-2026.10.22_abc", true},
		{"well formed from a client", "203.0.113.9:4000", "req-2026.10.22_abc", false},
		{"too short", "10.0.0.1:4000", "abc", false},
		{"log injection", "10.0.0.1:4000", "abcdefgh\nlevel=error", false},
		{"markup", "10.0.0.1:4000", "<script>alert(1)</script>", false},
		{"too long", "10.0.0.1:4000", strings.Repeat("a", 65), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remote
			req.Header["X-Request-Id"] = []string{tt.incoming}
			rec := httptest.NewRecorder()

			httpx.ClientAddress(proxy)(httpx.RequestID(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))).ServeHTTP(rec, req)

			got := rec.Header().Get("X-Request-Id")
			if tt.keep {
				assert.Equal(t, tt.incoming, got)
				return
			}
			assert.NotEqual(t, tt.incoming, got)
			assert.Len(t, got, 36)
		})
	}
}

func TestCrossOrigin(t *testing.T) {
	guard, err := httpx.CrossOrigin("https://app.example.com")
	require.NoError(t, err)
	h := guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	tests := []struct {
		name    string
		method  string
		headers map[string]string
		want    int
	}{
		{"cross-site post is refused", http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, http.StatusForbidden},
		{"foreign origin without fetch metadata is refused", http.MethodPost, map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"same-origin post passes", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusNoContent},
		{"trusted origin passes", http.MethodPost, map[string]string{"Origin": "https://app.example.com"}, http.StatusNoContent},
		{"non-browser client passes", http.MethodPost, nil, http.StatusNoContent},
		{"cross-site get passes", http.MethodGet, map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), tt.method, "http://api.example.com/things", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			assert.Equal(t, tt.want, rec.Code)
			if tt.want == http.StatusForbidden {
				assert.Equal(t, "cross_origin_blocked", decodeProblem(t, rec)["code"])
			}
		})
	}
}

func TestCORS_OnlyListedOriginsGetCredentials(t *testing.T) {
	h := httpx.CORS([]string{"https://app.example.com"})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	listed := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	h.ServeHTTP(listed, req)
	assert.Equal(t, http.StatusNoContent, listed.Code)
	assert.Equal(t, "https://app.example.com", listed.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", listed.Header().Get("Access-Control-Allow-Credentials"))

	for _, origin := range []string{"https://evil.example", "https://app.example.com.evil.example", "null", ""} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		h.ServeHTTP(rec, req)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"), origin)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"), origin)
	}
}

func TestSecurityHeaders_HSTSOnlyInProduction(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	prod, dev := httptest.NewRecorder(), httptest.NewRecorder()
	httpx.SecurityHeaders(true)(next).ServeHTTP(prod, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	httpx.SecurityHeaders(false)(next).ServeHTTP(dev, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	assert.NotEmpty(t, prod.Header().Get("Strict-Transport-Security"))
	assert.Empty(t, dev.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "nosniff", dev.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", dev.Header().Get("X-Frame-Options"))
}

func TestMaxBody_RefusesADeclaredOversizedBody(t *testing.T) {
	h := httpx.MaxBody(8)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	declared := httptest.NewRecorder()
	h.ServeHTTP(declared, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 64))))
	assert.Equal(t, http.StatusRequestEntityTooLarge, declared.Code)
	assert.Equal(t, "too_large", decodeProblem(t, declared)["code"])
}

package otelx_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/otelx"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

// kept survives the provider's shutdown, which would otherwise clear the recorded spans.
type kept struct{ *tracetest.InMemoryExporter }

func (kept) Shutdown(context.Context) error { return nil }

type recorded struct {
	spans   []sdktrace.ReadOnlySpan
	metrics metricdata.ResourceMetrics
	logs    string
}

// instrument serves each request through the middleware with sampling at sample, runs a failing job,
// and returns what was exported.
func instrument(t *testing.T, sample float64, requests ...*http.Request) recorded {
	t.Helper()
	spans, reader := tracetest.NewInMemoryExporter(), sdkmetric.NewManualReader()
	shutdown := otelx.Install(otelx.Resource{Service: "keel-test"}, sample, kept{spans}, reader)

	var logs bytes.Buffer
	logger := logx.New(config.Log{Format: config.LogText}, &logs, logx.ContextAttrs(otelx.LogAttrs))
	r := chi.NewRouter()
	r.Use(otelx.Middleware("api.keel.test"))
	r.Get("/things/{id}", func(w http.ResponseWriter, r *http.Request) {
		logger.InfoContext(r.Context(), "inside")
		w.WriteHeader(http.StatusNoContent)
	})
	r.Get("/livez", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	for _, req := range requests {
		r.ServeHTTP(httptest.NewRecorder(), req)
	}
	var out recorded
	require.NoError(t, reader.Collect(t.Context(), &out.metrics))

	trace, _ := otelx.Jobs()
	_, end := trace(t.Context(), jobs.Job{Kind: "mail.send", Attempt: 1})
	end(errors.New("smtp refused alice@example.com"))
	require.NoError(t, shutdown(t.Context()))
	out.spans, out.logs = spans.GetSpans().Snapshots(), logs.String()
	return out
}

func get(t *testing.T, target string, headers map[string]string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// A request's span and metrics carry its route pattern and the configured server name, a log line inside
// it carries its trace id, and a job run is a span named after its kind that records the failure by type.
// Nothing exported holds the client's address, the Host header or an error's text.
func TestInstrumentation(t *testing.T) {
	req := get(t, "/things/42", map[string]string{"X-Forwarded-For": "203.0.113.9"})
	req.Host, req.RemoteAddr = "attacker-chosen.example:31337", "198.51.100.7:4242"
	got := instrument(t, 1, req, get(t, "/livez", nil))

	require.Len(t, got.spans, 2, "the request and the job; health checks are not traced")
	request, job := got.spans[0], got.spans[1]
	assert.Equal(t, "GET /things/{id}", request.Name())
	assert.Contains(t, got.logs, "trace_id="+request.SpanContext().TraceID().String())
	assert.Equal(t, "job mail.send", job.Name())
	assert.Equal(t, codes.Error, job.Status().Code)
	assert.Empty(t, job.Events(), "no exception event carries the error's text")

	for _, s := range got.spans {
		for _, kv := range s.Attributes() {
			v := kv.Value.String()
			for _, leak := range []string{"203.0.113.9", "198.51.100.7", "attacker-chosen", "31337", "alice@example.com"} {
				assert.NotContains(t, v, leak, "%s on %s", kv.Key, s.Name())
			}
			assert.NotContains(t, []string{"client.address", "network.peer.address"}, string(kv.Key))
		}
	}
	errorType := false
	for _, kv := range job.Attributes() {
		errorType = errorType || (kv.Key == "error.type" && kv.Value.AsString() == "*errors.errorString")
	}
	assert.True(t, errorType, "the failure is recorded by type")

	routed := false
	for _, sm := range got.metrics.ScopeMetrics {
		for _, m := range sm.Metrics {
			if h, ok := m.Data.(metricdata.Histogram[float64]); ok && m.Name == "http.server.request.duration" {
				for _, p := range h.DataPoints {
					route, _ := p.Attributes.Value("http.route")
					server, _ := p.Attributes.Value("server.address")
					_, port := p.Attributes.Value("server.port")
					routed = routed || route.AsString() == "/things/{id}"
					assert.Equal(t, "api.keel.test", server.AsString(), "the Host header never labels a metric")
					assert.False(t, port, "nor its port")
				}
			}
		}
	}
	assert.True(t, routed, "request metrics are labelled with the route pattern")
}

// A client's traceparent cannot force sampling or plant its trace id: the request starts a new trace
// that links to the caller's, and an unsampled span puts no ids in the logs.
func TestMiddleware_IsAPublicEndpoint(t *testing.T) {
	const caller = "4bf92f3577b34da6a3ce929d0e0e4736"
	traceparent := map[string]string{"traceparent": "00-" + caller + "-00f067aa0ba902b7-01"}

	got := instrument(t, 0, get(t, "/things/42", traceparent))
	for _, s := range got.spans {
		assert.NotEqual(t, "GET /things/{id}", s.Name(), "a sampled traceparent does not override the rate")
	}
	assert.NotContains(t, got.logs, "trace_id=", "unsampled spans are never exported, so logs do not point at them")

	got = instrument(t, 1, get(t, "/things/42", traceparent))
	request := got.spans[0]
	assert.NotEqual(t, caller, request.SpanContext().TraceID().String())
	assert.False(t, request.Parent().IsValid(), "a new root")
	require.Len(t, request.Links(), 1)
	assert.Equal(t, caller, request.Links()[0].SpanContext.TraceID().String())
}

// Tracing wraps the pool's connector but keeps the session reset that clears the tenant setting on
// every checkout (D30). The reset leaves the setting empty where a connection that never ran it has
// none at all; the setting is never written here (only kit/db and kit/tenancy may).
func TestOpenDB_KeepsTheTenantReset(t *testing.T) {
	url := config.Secret(testdb.Tenancy(t).AdminURL(t))
	setting := func(opts ...db.OpenOption) sql.NullString {
		cfg := db.Defaults()
		cfg.URL, cfg.MaxOpen, cfg.MaxIdle = url, 1, 1
		d, _, err := db.Open(t.Context(), cfg, append(opts, db.Connector(otelx.OpenDB))...)
		require.NoError(t, err)
		defer func() { _ = d.Close() }()
		var value sql.NullString
		require.NoError(t, d.SQL().QueryRowContext(t.Context(), "SELECT current_setting('app.tenant_id', true)").Scan(&value))
		return value
	}
	assert.Equal(t, sql.NullString{Valid: true}, setting(db.ResetTenant()), "the reset ran when the connection was handed out again")
	assert.False(t, setting().Valid, "without the reset the setting does not exist")
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name string
		cfg  otelx.Config
		ok   bool
	}{
		{"off", otelx.Config{}, true},
		{"collector", otelx.Config{Endpoint: "http://collector:4318", Sample: 0.1, Headers: "x-key=abc"}, true},
		{"not a URL", otelx.Config{Endpoint: "collector:4318"}, false},
		{"credentials in the URL", otelx.Config{Endpoint: "https://collector@c.example"}, false},
		{"sample above one", otelx.Config{Endpoint: "https://c.example", Sample: 2}, false},
		{"headers without values", otelx.Config{Endpoint: "https://c.example", Headers: "x-key"}, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.ok, tt.cfg.Validate(true) == nil, tt.name)
	}
}

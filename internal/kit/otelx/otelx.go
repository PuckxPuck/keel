// Package otelx sends traces and metrics to an OTLP collector over HTTP when one is configured. Without
// an endpoint nothing is installed and the instrumentation helpers are not wired, so it costs nothing.
package otelx

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/XSAM/otelsql"
	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/health"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/logx"
)

const scope = "github.com/PuckxPuck/keel/internal/kit/otelx"

// Config is OTEL_*: Endpoint is the collector's OTLP/HTTP base URL; traces go to /v1/traces and
// metrics to /v1/metrics under it. Headers are sent with every export (key=value, comma separated).
type Config struct {
	Endpoint string        `env:"ENDPOINT"`
	Headers  config.Secret `env:"HEADERS"`
	Sample   float64       `env:"SAMPLE" envDefault:"0.1"`
	Service  string        `env:"SERVICE"`
}

func (c Config) Enabled() bool { return c.Endpoint != "" }

func (c Config) Validate(bool) error {
	if !c.Enabled() {
		return nil
	}
	var errs []error
	if u, err := url.Parse(c.Endpoint); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" {
		errs = append(errs, errors.New("OpenTelemetry endpoint must be an http or https URL without a query"))
	} else if u.User != nil {
		errs = append(errs, errors.New("OpenTelemetry endpoint must not carry credentials (it is printed); send them in the headers setting"))
	}
	if c.Sample < 0 || c.Sample > 1 {
		errs = append(errs, errors.New("OpenTelemetry sample must be between 0 and 1"))
	}
	if _, err := c.headers(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (c Config) headers() (map[string]string, error) {
	out := map[string]string{}
	raw := strings.TrimSpace(c.Headers.Reveal())
	if raw == "" {
		return out, nil
	}
	for pair := range strings.SplitSeq(raw, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if k = strings.TrimSpace(k); !ok || k == "" {
			return nil, errors.New("OpenTelemetry headers must be key=value pairs separated by commas")
		}
		out[k] = strings.TrimSpace(v)
	}
	return out, nil
}

// Resource names the process in every span and metric.
type Resource struct {
	Service, Version, Environment string
}

// Start installs the global tracer and meter providers exporting to cfg.Endpoint. shutdown flushes and
// stops them; without an endpoint Start installs nothing and shutdown does nothing.
func Start(ctx context.Context, cfg Config, res Resource) (shutdown func(context.Context) error, err error) {
	if !cfg.Enabled() {
		return func(context.Context) error { return nil }, nil
	}
	headers, err := cfg.headers()
	if err != nil {
		return nil, err
	}
	base := strings.TrimSuffix(cfg.Endpoint, "/")
	spans, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(base+"/v1/traces"), otlptracehttp.WithHeaders(headers))
	if err != nil {
		return nil, fmt.Errorf("otel traces: %w", err)
	}
	metrics, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpointURL(base+"/v1/metrics"), otlpmetrichttp.WithHeaders(headers))
	if err != nil {
		return nil, fmt.Errorf("otel metrics: %w", err)
	}
	return Install(res, cfg.Sample, spans, sdkmetric.NewPeriodicReader(metrics)), nil
}

// Install sets the global providers over the given exporter and reader (Start's, or a test's).
func Install(res Resource, sample float64, spans sdktrace.SpanExporter, metrics sdkmetric.Reader) func(context.Context) error {
	r := resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName(res.Service), semconv.ServiceVersion(res.Version), semconv.DeploymentEnvironmentNameKey.String(res.Environment))
	tp := sdktrace.NewTracerProvider(sdktrace.WithResource(r), sdktrace.WithBatcher(withoutClients{spans}),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sample))))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(r), sdkmetric.WithReader(metrics))
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return func(ctx context.Context) error {
		return errors.Join(tp.Shutdown(ctx), mp.Shutdown(ctx))
	}
}

// Middleware gives each request a server span and the request metrics, named after its route pattern.
// Every request is from the public: a caller's trace context becomes a link on a new trace, so no client
// decides sampling or plants a trace id. server is the fixed server.address (the Host header would let
// clients pick metric labels). Health checks are not traced.
func Middleware(server string) func(http.Handler) http.Handler {
	public := func(*http.Request) bool { return true }
	untraced := func(r *http.Request) bool { return r.URL.Path != health.LivePath && r.URL.Path != health.ReadyPath }
	// A port of 0 keeps the Host header's port out of the attributes as well.
	name := net.JoinHostPort(server, "0")
	return func(next http.Handler) http.Handler {
		return otelhttp.NewHandler(routed(next), "http.server", otelhttp.WithSpanNameFormatter(spanName),
			otelhttp.WithPublicEndpointFn(public), otelhttp.WithServerName(name), otelhttp.WithFilter(untraced))
	}
}

// clientKeys are the attributes that would export a client's address; no span carries them.
var clientKeys = []attribute.Key{semconv.ClientAddressKey, semconv.ClientPortKey, semconv.NetworkPeerAddressKey, semconv.NetworkPeerPortKey}

// withoutClients exports spans without clientKeys, whichever instrumentation set them.
type withoutClients struct{ sdktrace.SpanExporter }

func (e withoutClients) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	out := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, s := range spans {
		out[i] = anonymous{s}
	}
	return e.SpanExporter.ExportSpans(ctx, out)
}

type anonymous struct{ sdktrace.ReadOnlySpan }

func (s anonymous) Attributes() []attribute.KeyValue {
	return slices.DeleteFunc(slices.Clone(s.ReadOnlySpan.Attributes()), func(kv attribute.KeyValue) bool {
		return slices.Contains(clientKeys, kv.Key)
	})
}

// spanName is the method until routing, then the method and the route pattern.
func spanName(_ string, r *http.Request) string {
	if route := routeOf(r); route != "" {
		return r.Method + " " + route
	}
	return r.Method
}

func routeOf(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		return rc.RoutePattern()
	}
	return ""
}

func routed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		span := trace.SpanFromContext(r.Context())
		route := routeOf(r)
		if route == "" {
			return
		}
		span.SetName(r.Method + " " + route)
		span.SetAttributes(semconv.HTTPRoute(route))
		if l, ok := otelhttp.LabelerFromContext(r.Context()); ok {
			l.Add(semconv.HTTPRoute(route))
		}
	})
}

// OpenDB opens a pool whose queries are spans; give it to db.Connector. It keeps the driver's session
// reset and validity check. A failed query records its error's type, not its text, which can hold values.
func OpenDB(c driver.Connector) *sql.DB {
	return otelsql.OpenDB(c,
		otelsql.WithSpanOptions(otelsql.SpanOptions{OmitConnResetSession: true, OmitRows: true, DisableErrSkip: true, RecordError: func(error) bool { return false }}),
		otelsql.WithSpanErrorAttributesGetter(func(err error) []attribute.KeyValue { return []attribute.KeyValue{semconv.ErrorType(err)} }))
}

// Jobs are the queue's hooks: a span per run named after the job's kind, and wait and run times by kind.
func Jobs() (trace func(ctx context.Context, job jobs.Job) (context.Context, func(error)), metrics jobs.Metrics) {
	tracer := otel.Tracer(scope)
	meter := otel.Meter(scope)
	waited, _ := meter.Float64Histogram("jobs.wait.duration", metric.WithUnit("s"), metric.WithDescription("How long a job waited to be claimed"))
	took, _ := meter.Float64Histogram("jobs.run.duration", metric.WithUnit("s"), metric.WithDescription("How long a run took, by outcome"))
	trace = func(ctx context.Context, job jobs.Job) (context.Context, func(error)) {
		ctx, span := tracer.Start(ctx, "job "+job.Kind, oteltrace(job))
		return ctx, func(err error) {
			if err != nil {
				// The error's text can hold addresses or a vendor's reply; its type is enough to group failures.
				span.SetAttributes(semconv.ErrorType(err))
				span.SetStatus(codes.Error, "job failed")
			}
			span.End()
		}
	}
	metrics = jobs.Metrics{
		Claimed: func(ctx context.Context, kind, lane string, wait time.Duration) {
			waited.Record(ctx, wait.Seconds(), metric.WithAttributes(attribute.String("job.kind", kind), attribute.String("job.lane", lane)))
		},
		Finished: func(ctx context.Context, kind, lane string, outcome jobs.Outcome, d time.Duration) {
			took.Record(ctx, d.Seconds(), metric.WithAttributes(
				attribute.String("job.kind", kind), attribute.String("job.lane", lane), attribute.String("job.outcome", string(outcome))))
		},
	}
	return trace, metrics
}

func oteltrace(job jobs.Job) trace.SpanStartOption {
	return trace.WithAttributes(attribute.String("job.kind", job.Kind), attribute.Int("job.attempt", job.Attempt))
}

// LogAttrs are the trace and span ids of the sampled span in ctx (an unsampled one is never exported);
// give it to logx.ContextAttrs.
func LogAttrs(ctx context.Context) []slog.Attr {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() || !sc.IsSampled() {
		return nil
	}
	return []slog.Attr{slog.String(logx.KeyTraceID, sc.TraceID().String()), slog.String(logx.KeySpanID, sc.SpanID().String())}
}

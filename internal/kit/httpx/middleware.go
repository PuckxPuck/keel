package httpx

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/logx"
)

const headerRequestID = "X-Request-Id"

// Incoming ids are echoed into logs and responses, so only a conservative alphabet is accepted.
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$`)

// RequestID keeps a well-formed X-Request-Id set by a trusted proxy and otherwise makes one.
// It runs after ClientAddress, which decides whether the request came through a proxy.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(headerRequestID)
		if !Proxied(r.Context()) || !requestIDPattern.MatchString(id) {
			id = ids.New().String()
		}
		w.Header().Set(headerRequestID, id)
		ctx := problem.WithRequestID(r.Context(), id)
		ctx = logx.With(ctx, slog.String(logx.KeyRequestID, id))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AccessLog logs one line per request with the route pattern; quiet patterns log at debug.
func AccessLog(quiet ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := record(w)
			defer logRequest(r, rec, clock.Wall(r.Context()).Now(), quiet)
			next.ServeHTTP(rec, r)
		})
	}
}

func logRequest(r *http.Request, rec *recorder, start time.Time, quiet []string) {
	ctx := r.Context()
	route := "unmatched"
	if rc := chi.RouteContext(ctx); rc != nil && rc.RoutePattern() != "" {
		route = rc.RoutePattern()
	}
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	level := slog.LevelInfo
	switch {
	case slices.Contains(quiet, route):
		level = slog.LevelDebug
	case status >= http.StatusInternalServerError:
		level = slog.LevelError
	}
	logx.From(ctx).Log(ctx, level, "request",
		"method", r.Method, "route", route, "status", status,
		"bytes", rec.bytes, "duration_ms", clock.Wall(ctx).Now().Sub(start).Milliseconds())
}

// Recover answers a panic with a problem 500 and logs the stack. http.ErrAbortHandler passes through,
// and so does a panic after the response started: aborting the connection tells the client it was cut short.
// The 500 carries only the headers set before Recover ran, so nothing the handler set (cookies, lengths) leaks.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := record(w)
		defer recoverPanic(rec, r, w.Header().Clone())
		next.ServeHTTP(rec, r)
	})
}

// recoverPanic must be the deferred function itself for recover to work.
func recoverPanic(rec *recorder, r *http.Request, before http.Header) {
	v := recover()
	if v == nil {
		return
	}
	if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
		panic(v)
	}
	logx.From(r.Context()).Error("panic recovered", "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
	if rec.written() {
		panic(http.ErrAbortHandler)
	}
	h := rec.Header()
	clear(h)
	maps.Copy(h, before)
	h.Del("Content-Length")
	problem.Write(rec, r, problem.Internal())
}

// MaxBody caps request bodies; a declared length over the cap is refused before any handler runs.
func MaxBody(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				problem.Write(w, r, problem.New(http.StatusRequestEntityTooLarge, problem.CodeTooLarge, "request body is too large"))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders sets the API response headers from docs/security.md; hsts is for production only.
func SecurityHeaders(hsts bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Frame-Options", "DENY")
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=31536000")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CrossOrigin refuses cross-site unsafe requests (Sec-Fetch-Site, then Origin against Host) unless the origin is trusted.
func CrossOrigin(trusted ...string) (func(http.Handler) http.Handler, error) {
	cop := http.NewCrossOriginProtection()
	for _, origin := range trusted {
		if err := cop.AddTrustedOrigin(origin); err != nil {
			return nil, fmt.Errorf("trusted origin %q: %w", origin, err)
		}
	}
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		problem.Write(w, r, problem.New(http.StatusForbidden, "cross_origin_blocked", "cross-origin request refused"))
	}))
	return cop.Handler, nil
}

const corsMaxAge = 10 * time.Minute

// CORS allows exactly the listed origins, with credentials; there is no wildcard.
func CORS(origins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		allowed[o] = struct{}{}
	}
	maxAge := strconv.Itoa(int(corsMaxAge.Seconds()))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Add("Vary", "Origin")
			origin := r.Header.Get("Origin")
			if _, ok := allowed[origin]; !ok || origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Expose-Headers", headerRequestID)
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h.Add("Vary", "Access-Control-Request-Method")
				h.Set("Access-Control-Allow-Methods", strings.Join([]string{
					http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
				}, ", "))
				h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Idempotency-Key")
				h.Set("Access-Control-Max-Age", maxAge)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

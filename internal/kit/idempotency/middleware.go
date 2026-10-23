package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

const (
	Header         = "Idempotency-Key"
	ReplayedHeader = "Idempotent-Replayed"
	maxKey         = 255

	CodeKeyRequired       = "idempotency_key_required"
	CodeKeyInvalid        = "idempotency_key_invalid"
	CodeMismatch          = "idempotency_mismatch"
	CodeInProgress        = "idempotency_in_progress"
	CodeOutcomeUnknown    = "idempotency_outcome_unknown"
	CodeResponseNotStored = "idempotency_response_not_stored"
)

// Config is APP_IDEMPOTENCY_*. Lease is how long a claim counts as running; after it, and until TTL,
// a repeat is told the outcome is unknown, because the first request may have committed.
type Config struct {
	TTL            time.Duration   `env:"TTL" envDefault:"24h"`
	Lease          time.Duration   `env:"LEASE" envDefault:"2m"`
	MaxStoredBytes config.ByteSize `env:"MAX_STORED_BYTES" envDefault:"256KiB"`
}

func (c Config) Validate(bool) error {
	var errs []error
	if c.Lease < time.Second || c.TTL < c.Lease {
		errs = append(errs, errors.New("idempotency lease must be at least 1s and the TTL at least the lease"))
	}
	if c.MaxStoredBytes < 1 || c.MaxStoredBytes > 16<<20 {
		errs = append(errs, errors.New("idempotency max stored bytes must be 1B to 16MiB"))
	}
	return errors.Join(errs...)
}

// replayedHeaders are the response headers stored and replayed with the body.
var replayedHeaders = []string{"Content-Type", "Content-Location", "Location", "ETag", "Last-Modified"}

const metaRequired = "keel:idempotency"

type requiredOption struct{}

func (requiredOption) Apply(op *huma.Operation) { httpx.SetMeta(op, metaRequired, true) }

// Required marks an operation that needs an Idempotency-Key; an httpx.Register option. The operation
// must not be public and must have a body limit (Check).
func Required() httpx.Option { return requiredOption{} }

func IsRequired(op *huma.Operation) bool {
	v, _ := op.Metadata[metaRequired].(bool)
	return v
}

// Check reports every operation marked Required that is public or has no body limit: keys are scoped
// to a signed-in principal, and the body is buffered to hash it.
func Check(api huma.API) error {
	var errs []error
	for _, op := range httpx.Operations(api) {
		if !IsRequired(op) {
			continue
		}
		if need, ok := rbac.NeedOf(op); !ok || need.IsPublic() {
			errs = append(errs, fmt.Errorf("%s %s (%s) needs an Idempotency-Key but is public", op.Method, op.Path, op.OperationID))
		}
		if httpx.BodyLimit(op) <= 0 {
			errs = append(errs, fmt.Errorf("%s %s (%s) needs an Idempotency-Key but has no body limit", op.Method, op.Path, op.OperationID))
		}
	}
	return errors.Join(errs...)
}

// Middleware makes marked operations at most once per key for a signed-in principal in its realm. The
// first answer below 500 is stored before it is sent and replayed for cfg.TTL; a 5xx, a failed save or
// a claim past its lease leaves the outcome unknown (409) until the key expires, so a retry never runs
// the change twice. Without a store, marked operations answer 503 rather than run unprotected.
func Middleware(api huma.API, store *Store, cfg Config, principals rbac.Principals) func(huma.Context, func(huma.Context)) {
	return guard{api: api, store: store, cfg: cfg, principals: principals}.handle
}

type guard struct {
	api        huma.API
	store      *Store
	cfg        Config
	principals rbac.Principals
}

func (g guard) handle(ctx huma.Context, next func(huma.Context)) {
	op := ctx.Operation()
	if !IsRequired(op) {
		next(ctx)
		return
	}
	if g.store == nil {
		fail(g.api, ctx, problem.New(http.StatusServiceUnavailable, problem.CodeUnavailable, "try again shortly"))
		return
	}
	p, ok := g.principals.Principal(ctx.Context())
	if !ok || p.IsSystem() || p.Realm != httpx.RealmOf(op) {
		fail(g.api, ctx, problem.New(http.StatusUnauthorized, "unauthenticated", "sign in to continue"))
		return
	}
	key := ctx.Header(Header)
	if key == "" {
		fail(g.api, ctx, problem.New(http.StatusBadRequest, CodeKeyRequired, "this operation needs an Idempotency-Key header"))
		return
	}
	if !validKey(key) {
		fail(g.api, ctx, problem.New(http.StatusBadRequest, CodeKeyInvalid, "the Idempotency-Key must be 1 to 255 printable ASCII characters"))
		return
	}
	limit := httpx.BodyLimit(op)
	if limit <= 0 {
		fail(g.api, ctx, problem.New(http.StatusInternalServerError, problem.CodeInternal, "internal error"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(ctx.BodyReader(), limit+1))
	if err != nil {
		fail(g.api, ctx, problem.New(http.StatusBadRequest, "bad_request", "the request body could not be read"))
		return
	}
	if int64(len(body)) > limit {
		fail(g.api, ctx, problem.New(http.StatusRequestEntityTooLarge, problem.CodeTooLarge, "request body is too large"))
		return
	}
	s := scope{realm: p.Realm, principal: p.Key(), key: key}
	g.run(ctx, next, s, requestHash(ctx, op, body), body)
}

func (g guard) run(ctx huma.Context, next func(huma.Context), s scope, hash, body []byte) {
	c := ctx.Context()
	now := clock.Wall(c).Now().UTC()
	rec, claimed, err := g.store.claim(c, s, hash, now, g.cfg)
	if err != nil {
		logx.From(c).Error("idempotency store failed", "error", err)
		fail(g.api, ctx, problem.New(http.StatusServiceUnavailable, problem.CodeUnavailable, "try again shortly"))
		return
	}
	if !claimed {
		g.answerRepeat(ctx, rec, hash, now)
		return
	}
	st := &captured{
		body: bytes.NewReader(body), headers: map[string]string{}, limit: int(g.cfg.MaxStoredBytes),
		inner: ctx, save: func(status int, headers map[string]string, out []byte, stored bool) {
			saveOutcome(context.WithoutCancel(c), g.store, rec.id, status, headers, out, stored)
		},
	}
	next(&capture{inner: ctx, state: st})
	st.send(true)
}

// saveOutcome records the answer, or marks it unknown for a 5xx. A failure leaves the claim in progress,
// which becomes unknown after its lease: never released, so a retry cannot run the change again.
func saveOutcome(ctx context.Context, store *Store, id idemID, status int, headers map[string]string, body []byte, stored bool) {
	var err error
	if status >= http.StatusOK && status < http.StatusInternalServerError {
		err = store.finish(ctx, id, status, headers, body, stored)
	} else {
		err = store.markUnknown(ctx, id)
	}
	if err != nil {
		logx.From(ctx).Error("idempotency store failed to record an outcome", "error", err)
	}
}

func (g guard) answerRepeat(ctx huma.Context, rec record, hash []byte, now time.Time) {
	switch {
	case !bytes.Equal(rec.requestHash, hash):
		fail(g.api, ctx, problem.New(http.StatusUnprocessableEntity, CodeMismatch, "this Idempotency-Key was used with a different request"))
	case rec.status == statusInProgress && now.Before(rec.leaseUntil):
		ctx.SetHeader("Retry-After", "1")
		fail(g.api, ctx, problem.New(http.StatusConflict, CodeInProgress, "a request with this Idempotency-Key is still running"))
	case rec.status != statusDone:
		fail(g.api, ctx, problem.New(http.StatusConflict, CodeOutcomeUnknown,
			"the outcome of the request with this Idempotency-Key is unknown; check the resource before trying again with a new key"))
	case !rec.bodyStored:
		ctx.SetHeader(ReplayedHeader, "true")
		p := problem.New(http.StatusConflict, CodeResponseNotStored, "the request with this Idempotency-Key succeeded but its response was too large to keep")
		p.Extensions = map[string]any{"originalStatus": rec.respStatus}
		fail(g.api, ctx, p)
	default:
		for k, v := range rec.headers {
			ctx.SetHeader(k, v)
		}
		ctx.SetHeader(ReplayedHeader, "true")
		ctx.SetStatus(rec.respStatus)
		_, _ = ctx.BodyWriter().Write(rec.body) // a failed write means the client is gone
	}
}

func fail(api huma.API, ctx huma.Context, p *problem.Problem) {
	_ = huma.WriteErr(api, ctx, p.Status, "", p)
}

func validKey(k string) bool {
	if len(k) > maxKey {
		return false
	}
	for i := range len(k) {
		if k[i] < 0x21 || k[i] > 0x7e {
			return false
		}
	}
	return true
}

// requestHash covers everything that can change what a request does: method, route, path, query
// (canonicalised), content type and body. Each part is length-prefixed so parts cannot run together.
func requestHash(ctx huma.Context, op *huma.Operation, body []byte) []byte {
	u := ctx.URL()
	query := u.RawQuery
	if values, err := url.ParseQuery(query); err == nil {
		query = values.Encode()
	}
	h := sha256.New()
	for _, part := range []string{ctx.Method(), op.Path, u.Path, query, strings.ToLower(strings.TrimSpace(ctx.Header("Content-Type"))), string(body)} {
		_ = binary.Write(h, binary.BigEndian, uint64(len(part))) // hash writes never fail
		h.Write([]byte(part))
	}
	return h.Sum(nil)
}

// captured buffers the response so its record is saved before anything is sent. A body over limit is
// not kept: the record is saved without it, then the response streams through.
type captured struct {
	body    io.Reader
	status  int
	headers map[string]string
	out     bytes.Buffer
	limit   int
	inner   huma.Context
	sent    bool
	save    func(status int, headers map[string]string, body []byte, stored bool)
}

func (st *captured) send(stored bool) {
	if st.sent {
		return
	}
	st.sent = true
	if st.status == 0 {
		st.status = http.StatusOK
	}
	var kept []byte
	if stored {
		kept = st.out.Bytes()
	}
	st.save(st.status, st.headers, kept, stored)
	st.inner.SetStatus(st.status)
	if st.out.Len() > 0 {
		_, _ = st.inner.BodyWriter().Write(st.out.Bytes()) // a failed write means the client is gone
	}
}

func (st *captured) Write(p []byte) (int, error) {
	if !st.sent && st.out.Len()+len(p) > st.limit {
		st.send(false)
	}
	if st.sent {
		return st.inner.BodyWriter().Write(p)
	}
	return st.out.Write(p)
}

type inner huma.Context

// capture hands the buffered request body to the handler and holds back what it writes.
type capture struct {
	inner
	state *captured
}

func (c *capture) BodyReader() io.Reader { return c.state.body }

func (c *capture) SetStatus(code int) { c.state.status = code }

func (c *capture) Status() int { return c.state.status }

func (c *capture) SetHeader(name, value string) {
	if kept(name) {
		c.state.headers[http.CanonicalHeaderKey(name)] = value
	}
	c.inner.SetHeader(name, value)
}

func (c *capture) BodyWriter() io.Writer { return c.state }

func (c *capture) WithContext(ctx context.Context) huma.Context {
	return &capture{inner: huma.WithContext(c.inner, ctx), state: c.state}
}

func kept(name string) bool {
	canonical := http.CanonicalHeaderKey(name)
	for _, h := range replayedHeaders {
		if h == canonical {
			return true
		}
	}
	return false
}

package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

const CodeRateLimited = "rate_limited"

// Rule is one class: how requests are keyed and how many are allowed. Store overrides the limiter's
// store (DBStore for security counters). A failing store refuses requests with 503 on every path unless
// FailOpen, which lets them through and logs. Skip exempts requests from the class (local health probes).
type Rule struct {
	Key      KeyFunc
	Rate     Rate
	Store    Store
	FailOpen bool
	Skip     func(ctx context.Context) bool
}

type Limiter struct {
	store   Store
	classes map[string]Rule
}

func New(store Store) *Limiter { return &Limiter{store: store, classes: map[string]Rule{}} }

var classPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Define registers a class; it panics on a bad or repeated definition, which only happens at startup.
func (l *Limiter) Define(class string, r Rule) {
	switch {
	case !classPattern.MatchString(class):
		panic(fmt.Sprintf("ratelimit: class name %q must be lower case letters, digits and -", class))
	case r.Key == nil || !r.Rate.valid():
		panic(fmt.Sprintf("ratelimit: class %s needs a key and a rate", class))
	}
	if _, dup := l.classes[class]; dup {
		panic(fmt.Sprintf("ratelimit: class %s is defined twice", class))
	}
	l.classes[class] = r
}

// Defaults are the default classes with the configured rates; the auth and webhook classes key by
// address because their callers are not signed in yet.
func Defaults(cfg Config, principals rbac.Principals) map[string]Rule {
	byPrincipal := ByPrincipal(principals)
	return map[string]Rule{
		ClassPreAuth:   {Key: ByAddress, Rate: cfg.PreAuth},
		ClassAuth:      {Key: ByAddress, Rate: cfg.Auth},
		ClassAPIRead:   {Key: byPrincipal, Rate: cfg.APIRead},
		ClassAPIWrite:  {Key: byPrincipal, Rate: cfg.APIWrite},
		ClassHeavy:     {Key: byPrincipal, Rate: cfg.Heavy},
		ClassWebhook:   {Key: ByAddress, Rate: cfg.Webhook},
		ClassHealth:    {Key: ByAddress, Rate: cfg.Health, Skip: httpx.LocalProbe},
		ClassAPIKey:    {Key: byPrincipal, Rate: cfg.APIKey},
		ClassAPITenant: {Key: ByTenant, Rate: cfg.APITenant},
	}
}

// ByTenant keys by the request's tenant (db.WithTenant); without tenancy the app is its only tenant, so
// every request shares one bucket.
func ByTenant(ctx context.Context, _ Headers) string {
	if id, ok := db.TenantOf(ctx); ok {
		return "tenant:" + id.String()
	}
	return "tenant"
}

const metaClass = "keel:rateClass"

type classOption string

func (c classOption) Apply(op *huma.Operation) { httpx.SetMeta(op, metaClass, string(c)) }

// Class names the operation's rate-limit class; an httpx.Register option.
func Class(name string) httpx.Option { return classOption(name) }

func ClassOf(op *huma.Operation) (string, bool) {
	c, ok := op.Metadata[metaClass].(string)
	return c, ok && c != ""
}

// Check reports every operation on api without a class or with a class that is not defined.
func (l *Limiter) Check(api huma.API) error {
	var errs []error
	for _, op := range httpx.Operations(api) {
		class, ok := ClassOf(op)
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("%s %s (%s) declares no rate-limit class", op.Method, op.Path, op.OperationID))
		case !l.defined(class):
			errs = append(errs, fmt.Errorf("%s %s (%s) uses the undefined rate-limit class %q", op.Method, op.Path, op.OperationID, class))
		}
	}
	return errors.Join(errs...)
}

// Defined is true for a class Define registered.
func (l *Limiter) Defined(class string) bool { return l.defined(class) }

func (l *Limiter) defined(class string) bool {
	_, ok := l.classes[class]
	return ok
}

// Middleware limits each request by its operation's class and adds its RateLimit headers.
func (l *Limiter) Middleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return byClass{l: l, api: api}.handle
}

type byClass struct {
	l   *Limiter
	api huma.API
}

func (b byClass) handle(ctx huma.Context, next func(huma.Context)) {
	class, _ := ClassOf(ctx.Operation())
	d, ok := b.l.take(ctx.Context(), ctx, class)
	if !ok {
		_ = huma.WriteErr(b.api, ctx, http.StatusServiceUnavailable, "", unavailable())
		return
	}
	setPolicy(ctx.AppendHeader, class, d)
	if !d.Allowed {
		refuse(b.api, ctx, d)
		return
	}
	next(ctx)
}

// PreAuth limits every request by class before anything else runs, setting headers only when it refuses.
func (l *Limiter) PreAuth(api huma.API, class string) func(huma.Context, func(huma.Context)) {
	return preAuth{l: l, api: api, class: class}.handle
}

type preAuth struct {
	l     *Limiter
	api   huma.API
	class string
}

func (p preAuth) handle(ctx huma.Context, next func(huma.Context)) {
	d, ok := p.l.take(ctx.Context(), ctx, p.class)
	switch {
	case !ok:
		_ = huma.WriteErr(p.api, ctx, http.StatusServiceUnavailable, "", unavailable())
	case !d.Allowed:
		setPolicy(ctx.SetHeader, p.class, d)
		refuse(p.api, ctx, d)
	default:
		next(ctx)
	}
}

// Classes limits every request by each class pick returns, in order, before the operation's own class,
// adding each class's RateLimit headers so a client sees every budget that can stop it; the first
// refusal answers.
func (l *Limiter) Classes(api huma.API, pick func(ctx context.Context) []string) func(huma.Context, func(huma.Context)) {
	return classes{l: l, api: api, pick: pick}.handle
}

type classes struct {
	l    *Limiter
	api  huma.API
	pick func(ctx context.Context) []string
}

func (c classes) handle(ctx huma.Context, next func(huma.Context)) {
	for _, class := range c.pick(ctx.Context()) {
		d, ok := c.l.take(ctx.Context(), ctx, class)
		if !ok {
			_ = huma.WriteErr(c.api, ctx, http.StatusServiceUnavailable, "", unavailable())
			return
		}
		setPolicy(ctx.AppendHeader, class, d)
		if !d.Allowed {
			refuse(c.api, ctx, d)
			return
		}
	}
	next(ctx)
}

// HTTP limits plain routes (health) by class.
func (l *Limiter) HTTP(class string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d, ok := l.take(r.Context(), httpHeaders(r.Header), class)
			switch {
			case !ok:
				problem.Write(w, r, unavailable())
			case !d.Allowed:
				setPolicy(w.Header().Set, class, d)
				w.Header().Set("Retry-After", ceilSeconds(d.RetryAfter))
				problem.Write(w, r, limited())
			default:
				next.ServeHTTP(w, r)
			}
		})
	}
}

// take counts the request; ok is false when the class is undefined (the startup check prevents that)
// or the store failed and the class does not fail open.
func (l *Limiter) take(ctx context.Context, h Headers, class string) (Decision, bool) {
	rule, defined := l.classes[class]
	if !defined {
		logx.From(ctx).Error("rate limit class is not defined", "class", class)
		return Decision{}, false
	}
	if rule.Skip != nil && rule.Skip(ctx) {
		return Decision{Allowed: true}, true
	}
	store := rule.Store
	if store == nil {
		store = l.store
	}
	d, err := store.Take(ctx, class+":"+bucketKey(rule.Key(ctx, h)), rule.Rate)
	if err != nil {
		logx.From(ctx).Error("rate limit store failed", "class", class, "error", err)
		return Decision{Allowed: true}, rule.FailOpen
	}
	return d, true
}

// bucketKey keeps keys within rate_counters' 191 characters, whatever a custom KeyFunc returns.
func bucketKey(k string) string {
	if len(k) <= 128 {
		return k
	}
	return "h:" + digest(k)
}

func setPolicy(set func(name, value string), class string, d Decision) {
	if d.Limit == 0 {
		return
	}
	set("RateLimit-Policy", fmt.Sprintf("%q;q=%d;w=%d", class, d.Limit, int(d.Window.Seconds())))
	set("RateLimit", fmt.Sprintf("%q;r=%d;t=%s", class, d.Remaining, ceilSeconds(d.Reset)))
}

func refuse(api huma.API, ctx huma.Context, d Decision) {
	ctx.SetHeader("Retry-After", ceilSeconds(d.RetryAfter))
	_ = huma.WriteErr(api, ctx, http.StatusTooManyRequests, "", limited())
}

func ceilSeconds(d time.Duration) string {
	return strconv.FormatInt(int64((d+time.Second-1)/time.Second), 10)
}

func unavailable() *problem.Problem {
	return problem.New(http.StatusServiceUnavailable, problem.CodeUnavailable, "try again shortly")
}

func limited() *problem.Problem {
	return problem.New(http.StatusTooManyRequests, CodeRateLimited, "too many requests; retry after the time in Retry-After")
}

type httpHeaders http.Header

func (h httpHeaders) Header(name string) string { return http.Header(h).Get(name) }

package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"sync"

	"github.com/danielgtaylor/huma/v2"

	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/auth/devices"
	"github.com/PuckxPuck/keel/internal/kit/auth/password"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/auth/tokens"
	"github.com/PuckxPuck/keel/internal/kit/auth/totp"
	"github.com/PuckxPuck/keel/internal/kit/buildinfo"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/health"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/idempotency"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/occ"
	"github.com/PuckxPuck/keel/internal/kit/paging"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
	"github.com/PuckxPuck/keel/internal/kit/webhook"
)

const BasePath = "/api/v1"

// Built is the wired HTTP side of the app. Ready opens the readiness gate once startup has
// succeeded; Drain closes it again ahead of shutdown.
type Built struct {
	Handler http.Handler
	Ready   func()
	Drain   func()
	Realms  *realm.Set
	// Queue has every job kind and schedule registered (the kit's, maintenance and the modules'); nil
	// without a database. serve runs it when APP_JOBS_IN_SERVE, app worker otherwise.
	Queue *jobs.Queue
	// Modules are the module instances mounted, the same ones whose jobs are on Queue.
	Modules []Module
}

// Deps are the opened resources Build wires in. A nil DB leaves the database out of readiness (tests)
// and makes idempotent operations answer 503. A nil Principals reads the principal from the context.
type Deps struct {
	DB *db.DB
	// Operator opens operator transactions; pass it only to operator-realm wiring (D29).
	Operator   *db.OperatorAccess
	Principals rbac.Principals
	// Notifier enqueues reset, verification and invite links in the issuing transaction. Required outside
	// APP_ENV=local, where nil means the log notifier.
	Notifier tokens.Notifier
	// AdminNotifier tells key and access managers about security events: a leaked or expiring API key, a
	// disabled webhook endpoint. With the mail part it defaults to mail; without it, production needs one
	// when API keys or outbound webhooks are on.
	AdminNotifier AdminNotifier
	// Tenancy runs the tenancy part (OpenDatabase sets it when the migrations carry it); it needs Operator.
	Tenancy bool
	// Mailer replaces the one APP_MAIL_DRIVER names (tests).
	Mailer Mailer
}

var (
	installKitMappers sync.Once
	// moduleMappers holds the module types whose mapper is installed; the mapper list is process-wide.
	moduleMappers sync.Map
)

// installProblems replaces Huma's errors with problem+json and maps every kit part's errors, then each
// module type's the first time it is mounted. It runs before any operation is registered, so the OpenAPI
// documents describe Problem.
func installProblems(list []Module) {
	installKitMappers.Do(func() {
		problem.Install(occ.Mapper, rbac.Mapper, users.Mapper, webhook.Mapper,
			auth.Mapper, password.Mapper, tokens.Mapper, totp.Mapper, devices.Mapper,
			oidcMapper, passkeyMapper, apiKeysMapper, filesMapper, paging.Mapper, tenancyMapper)
	})
	for _, m := range list {
		if _, done := moduleMappers.LoadOrStore(reflect.TypeOf(m), true); !done {
			problem.Install(m.Mapper)
		}
	}
}

// Build wires the router, middleware, health, operations and the job queue without listening or
// running workers. extra registers further operations on the tenant realm after the app's own; tests
// use it.
func Build(ctx context.Context, cfg Config, deps Deps, extra ...func(huma.API)) (Built, error) {
	crossOrigin, err := httpx.CrossOrigin(trustedOrigins(cfg)...)
	if err != nil {
		return Built{}, fmt.Errorf("csrf protection: %w", err)
	}
	maxBody := int64(cfg.HTTP.MaxBodyBytes)
	principals := deps.Principals
	if principals == nil {
		principals = rbac.FromContext{}
	}
	limiter := newLimiter(cfg.Rate, principals)
	w, err := assemble(ctx, cfg, deps)
	if err != nil {
		return Built{}, err
	}
	set, err := newRealmSet(append(configuredRealms(cfg), apiRealms(cfg)...), cfg.HTTP.Docs, maxBody)
	if err != nil {
		return Built{}, err
	}

	router := httpx.NewRouter()
	router.Use(httpx.ClientAddress(cfg.Proxy))
	router.Use(otelMiddleware(cfg)...)
	router.Use(
		httpx.RequestID,
		httpx.SecurityHeaders(cfg.Env.IsProd()),
		httpx.AccessLog(health.LivePath, health.ReadyPath),
	)
	// The api realm takes bearer keys only, so it has no ambient credentials to protect and no CORS.
	if len(cfg.HTTP.CORSOrigins) > 0 {
		router.Use(unlessRealm(set, RealmAPI, httpx.CORS(cfg.HTTP.CORSOrigins)))
	}
	router.Use(httpx.Recover, unlessRealm(set, RealmAPI, crossOrigin))

	var probes []health.Check
	if deps.DB != nil {
		probes = append(probes, db.HealthCheck(deps.DB))
	}
	checks := health.New(probes...)
	// Operations enforce their own body caps (httpx.Register); MaxBody covers routes outside the API.
	checks.Mount(router.With(httpx.MaxBody(maxBody), limiter.HTTP(ratelimit.ClassHealth)))

	var idem *idempotency.Store
	if deps.DB != nil {
		idem = idempotency.NewStore(deps.DB)
	}
	set.Each(func(r realm.Realm, api huma.API) {
		if r.Name == RealmAPI {
			api.UseMiddleware(w.apiMiddleware(api, limiter, principals, idem)...)
			return
		}
		// Order matters (docs/architecture.md section 5).
		api.UseMiddleware(
			limiter.PreAuth(api, ratelimit.ClassPreAuth),
			w.resolveTenant(r.Name, api),
			w.sessions.Resolve(),
			limiter.Middleware(api),
			w.sessions.Require(api, principals),
			w.guardTenant(r.Name, api, principals),
			rbac.Enforce(api, principals),
			w.sessions.Restrict(api),
			idempotency.Middleware(api, idem, cfg.Idempotency, principals),
		)
	})
	registerOperations(set, w, extra...)
	if err := CheckOperations(ctx, set, limiter); err != nil {
		return Built{}, fmt.Errorf("operations:\n%w", err)
	}
	router.Mount("/", set)

	return Built{Handler: router, Ready: checks.Ready, Drain: checks.Drain, Realms: set, Queue: w.queue, Modules: w.modules}, nil
}

// assemble is the wiring with every service Build and the commands share: auth, the queue with each
// kind registered (the kit's, maintenance, the modules'), mail, files and the integrations.
func assemble(ctx context.Context, cfg Config, deps Deps) (*wiring, error) {
	w, err := newWiring(cfg, deps)
	if err != nil {
		return nil, fmt.Errorf("wiring: %w", err)
	}
	if deps.DB != nil {
		if w.notifier == nil {
			return nil, errNoNotifier
		}
		if w.admins == nil && cfg.Env.IsProd() && (len(apiKeyParts(cfg)) > 0 || len(webhookParts(cfg)) > 0) {
			return nil, errNoAdminNotifier
		}
		if err := w.openFiles(ctx, cfg, deps); err != nil {
			return nil, fmt.Errorf("files: %w", err)
		}
		w.mountModules()
		w.registerMaintenance()
	}
	installProblems(w.modules)
	return w, nil
}

// unlessRealm applies mw to every request except those routed to the named realm.
func unlessRealm(set *realm.Set, name string, mw func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		wrapped := mw(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if set.For(r.Host) == name {
				next.ServeHTTP(w, r)
				return
			}
			wrapped.ServeHTTP(w, r)
		})
	}
}

func newLimiter(cfg ratelimit.Config, principals rbac.Principals) *ratelimit.Limiter {
	lim := ratelimit.New(ratelimit.NewMemory(cfg.MaxKeys))
	for class, rule := range ratelimit.Defaults(cfg, principals) {
		lim.Define(class, rule)
	}
	return lim
}

func newRealmSet(list []realm.Realm, docs bool, maxBody int64) (*realm.Set, error) {
	return realm.New(httpx.Options{
		Title:        "keel",
		Version:      buildinfo.Get().Version,
		DocsEnabled:  docs,
		MaxBodyBytes: maxBody,
	}, list...)
}

func registerOperations(set *realm.Set, w *wiring, extra ...func(huma.API)) {
	registerAPIRealm(set)
	ops := operations(w)
	set.Each(func(r realm.Realm, api huma.API) {
		for _, register := range ops[r.Name] {
			register(api)
		}
	})
	for _, register := range extra {
		register(set.API(RealmTenant))
	}
}

// Operations builds every realm with its operations and no middleware, for route:list, openapi and walk
// tests. The api realm stands on a placeholder host.
func Operations() (*realm.Set, error) {
	set, err := newRealmSet(append(append(realms(), listedAPIRealms()...), operatorRealms()...), false, 0)
	if err != nil {
		return nil, err
	}
	w := &wiring{}
	w.modules = mounted(w)
	installProblems(w.modules)
	registerOperations(set, w)
	return set, nil
}

// CheckOperations is the startup check over every operation, hidden ones included: an id, tags, a
// realm, a Need from its realm's catalogue, a defined rate-limit class, and idempotency only where a
// principal and a body limit exist.
func CheckOperations(ctx context.Context, set *realm.Set, limiter *ratelimit.Limiter) error {
	var errs []error
	set.Each(func(r realm.Realm, api huma.API) {
		for _, op := range httpx.Operations(api) {
			if op.OperationID == "" || len(op.Tags) == 0 {
				errs = append(errs, fmt.Errorf("%s %s needs an OperationID and tags", op.Method, op.Path))
			}
			if httpx.RealmOf(op) != r.Name {
				errs = append(errs, fmt.Errorf("%s %s (%s) is not recorded on realm %s", op.Method, op.Path, op.OperationID, r.Name))
			}
		}
		errs = append(errs, rbac.Check(api, r.Catalogue), idempotency.Check(api))
		if r.Name == RealmTenant {
			errs = append(errs, checkUploadNeeds(r.Catalogue))
		}
		if r.Name == RealmAPI {
			errs = append(errs, checkAPIRealm(ctx, api))
		}
		if limiter != nil {
			errs = append(errs, limiter.Check(api))
		}
	})
	return errors.Join(errs...)
}

func trustedOrigins(cfg Config) []string {
	origins := append([]string(nil), cfg.HTTP.CORSOrigins...)
	if u, err := url.Parse(cfg.App.PublicURL); err == nil && u.Host != "" {
		origins = append(origins, u.Scheme+"://"+u.Host)
	}
	return origins
}

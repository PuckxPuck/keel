package httpx

import (
	"context"
	"maps"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"

	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
)

type Options struct {
	Title    string
	Version  string
	BasePath string
	// DocsEnabled serves the OpenAPI document, the docs page and the schemas under BasePath.
	DocsEnabled bool
	// MaxBodyBytes is the body cap of every operation registered with Register that does not set its own.
	MaxBodyBytes int64
	// Realm is recorded on every operation registered on this API.
	Realm string
	// SpecPath serves the OpenAPI document alone at SpecPath.json and SpecPath.yaml, whatever
	// DocsEnabled says (the public api realm's document).
	SpecPath string
}

// bodyLimits, realms, registries and mirrors hold each API's settings, keyed by its OpenAPI document,
// which its groups share.
var bodyLimits, realms, registries, mirrors sync.Map

// registry lists every operation as the router sees it, hidden ones included (Huma leaves those out
// of the OpenAPI document, so startup checks would miss them).
type registry struct {
	mu  sync.Mutex
	ops map[string]*huma.Operation
}

func (r *registry) add(op *huma.Operation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops[op.Method+" "+op.Path] = op
}

// Option adds metadata to an operation at registration: rbac.Need, ratelimit.Class, idempotency.Required.
type Option interface {
	Apply(op *huma.Operation)
}

// SetMeta sets one metadata key on op.
func SetMeta(op *huma.Operation, key string, value any) {
	if op.Metadata == nil {
		op.Metadata = map[string]any{}
	}
	op.Metadata[key] = value
}

const metaRealm = "keel:realm"

// RealmOf is the realm Register recorded on op, or "" for an API without one.
func RealmOf(op *huma.Operation) string {
	name, _ := op.Metadata[metaRealm].(string)
	return name
}

type realmKey struct{}

// WithRealm records the realm a request was routed to; the realm router sets it.
func WithRealm(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, realmKey{}, name)
}

// Realm is the realm the request was routed to, or "" outside a realm (CLI, jobs).
func Realm(ctx context.Context) string {
	name, _ := ctx.Value(realmKey{}).(string)
	return name
}

var probedMethods = []string{
	http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
	http.MethodPatch, http.MethodDelete, http.MethodOptions,
}

// NewRouter answers unknown routes and wrong methods with problem+json.
func NewRouter() chi.Router {
	mux := chi.NewRouter()
	mux.NotFound(func(w http.ResponseWriter, r *http.Request) {
		problem.Write(w, r, problem.New(http.StatusNotFound, problem.CodeNotFound, "no such route"))
	})
	mux.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		var allowed []string
		for _, m := range probedMethods {
			if mux.Match(chi.NewRouteContext(), m, r.URL.Path) {
				allowed = append(allowed, m)
			}
		}
		if len(allowed) > 0 {
			w.Header().Set("Allow", strings.Join(allowed, ", "))
		}
		problem.Write(w, r, problem.New(http.StatusMethodNotAllowed, problem.CodeMethodNotAllowed, "method not allowed"))
	})
	return mux
}

// NewAPI mounts a Huma API on router with its operations under opts.BasePath.
// Call problem.Install before registering operations.
func NewAPI(router chi.Router, opts Options) huma.API {
	cfg := huma.DefaultConfig(opts.Title, opts.Version)
	cfg.CreateHooks = nil
	cfg.Transformers = append(cfg.Transformers, problem.Transformer)
	if opts.DocsEnabled {
		cfg.OpenAPIPath = opts.BasePath + "/openapi"
		cfg.DocsPath = opts.BasePath + "/docs"
		cfg.SchemasPath = opts.BasePath + "/schemas"
	} else {
		cfg.OpenAPIPath, cfg.DocsPath, cfg.SchemasPath = "", "", ""
	}
	if opts.SpecPath != "" {
		cfg.OpenAPIPath = opts.SpecPath
	}

	api := humachi.New(router, cfg)
	if opts.MaxBodyBytes > 0 {
		bodyLimits.Store(api.OpenAPI(), opts.MaxBodyBytes)
	}
	if opts.Realm != "" {
		realms.Store(api.OpenAPI(), opts.Realm)
	}
	reg := &registry{ops: map[string]*huma.Operation{}}
	registries.Store(api.OpenAPI(), reg)
	var group *huma.Group
	if opts.BasePath == "" {
		group = huma.NewGroup(api)
	} else {
		group = huma.NewGroup(api, opts.BasePath)
	}
	// Runs after the prefix modifier, for the documented copy and then the routed one; the routed one
	// is what middleware sees as ctx.Operation(), and it replaces the documented one.
	group.UseModifier(func(op *huma.Operation, next func(*huma.Operation)) {
		next(op)
		reg.add(op)
	})
	return group
}

// Register is huma.Register, applying opts, recording the API's realm, and giving the operation the API's
// default body cap unless it sets MaxBodyBytes (Huma would otherwise apply its own 1 MiB default).
func Register[I, O any](api huma.API, op huma.Operation, handler func(context.Context, *I) (*O, error), opts ...Option) {
	for _, o := range opts {
		o.Apply(&op)
	}
	if name, ok := realms.Load(api.OpenAPI()); ok {
		SetMeta(&op, metaRealm, name)
	}
	if op.MaxBodyBytes == 0 {
		if limit, ok := bodyLimits.Load(api.OpenAPI()); ok {
			op.MaxBodyBytes, _ = limit.(int64)
		}
	}
	if op.MaxBodyBytes > 0 {
		// Huma refuses a body of exactly MaxBodyBytes; one more lets a body at the cap through.
		op.MaxBodyBytes++
	}
	if _, ok := any(new(O)).(answersExisting); ok {
		body, _ := reflect.TypeFor[O]().FieldByName("Body")
		documentExisting(api, &op, body.Type)
	}
	huma.Register(api, op, handler)
	if v, ok := mirrors.Load(api.OpenAPI()); ok {
		list, _ := v.([]mirror)
		for _, m := range list {
			if m.accept(&op) {
				huma.Register(m.to, m.copyOf(op), handler)
			}
		}
	}
}

type mirror struct {
	to     huma.API
	realm  string
	accept func(*huma.Operation) bool
	adjust func(*huma.Operation)
}

// copyOf gives the copy its own metadata, recorded on the mirror's realm.
func (m mirror) copyOf(op huma.Operation) huma.Operation {
	op.Metadata = maps.Clone(op.Metadata)
	if m.realm != "" {
		op.Metadata[metaRealm] = m.realm
	}
	if m.adjust != nil {
		m.adjust(&op)
	}
	return op
}

// Mirror registers every operation later registered on from that accept takes on to as well, with the
// same handler and options, recorded on to's realm; adjust may change the copy (its document entry).
// The public api realm exposes marked operations of the tenant realm this way.
func Mirror(from, to huma.API, accept func(*huma.Operation) bool, adjust func(*huma.Operation)) {
	m := mirror{to: to, accept: accept, adjust: adjust}
	if name, ok := realms.Load(to.OpenAPI()); ok {
		m.realm, _ = name.(string)
	}
	var list []mirror
	if v, ok := mirrors.Load(from.OpenAPI()); ok {
		list, _ = v.([]mirror)
	}
	mirrors.Store(from.OpenAPI(), append(slices.Clone(list), m))
}

// BodyLimit is the largest body op accepts, or 0 when it has no limit.
func BodyLimit(op *huma.Operation) int64 { return max(0, op.MaxBodyBytes-1) }

// Operations lists every operation registered on api through Register, hidden ones included, sorted by
// path then method.
func Operations(api huma.API) []*huma.Operation {
	v, ok := registries.Load(api.OpenAPI())
	if !ok {
		return nil
	}
	reg, _ := v.(*registry)
	reg.mu.Lock()
	out := make([]*huma.Operation, 0, len(reg.ops))
	for _, op := range reg.ops {
		out = append(out, op)
	}
	reg.mu.Unlock()
	slices.SortFunc(out, func(a, b *huma.Operation) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return slices.Index(probedMethods, a.Method) - slices.Index(probedMethods, b.Method)
	})
	return out
}

const metaServed = "keel:served"

var pathParam = regexp.MustCompile(`\{([^}]+)\}`)

type served struct{ h http.Handler }

// Serve hands the request to h once the API's and the operation's middleware have passed, in place of
// the operation's handler, for bodies Huma should not read or write: an upload streamed to storage, a
// file download. Huma never reads the body, so h enforces its own size cap. Path parameters reach h as
// r.PathValue. A 2xx answer that is not JSON (a download) is exempt from the envelope check.
func Serve(h http.Handler) Option { return served{h: h} }

func (s served) Apply(op *huma.Operation) {
	SetMeta(op, metaServed, true)
	var names []string
	for _, m := range pathParam.FindAllStringSubmatch(op.Path, -1) {
		names = append(names, m[1])
	}
	op.Middlewares = append(op.Middlewares, func(ctx huma.Context, _ func(huma.Context)) {
		r, w := humachi.Unwrap(ctx)
		r = r.WithContext(ctx.Context())
		for _, n := range names {
			r.SetPathValue(n, ctx.Param(n))
		}
		s.h.ServeHTTP(w, r)
	})
}

func isServed(op *huma.Operation) bool {
	v, _ := op.Metadata[metaServed].(bool)
	return v
}

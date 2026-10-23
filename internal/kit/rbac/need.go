package rbac

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/logx"
)

type needKind int

const (
	needPublic needKind = iota + 1
	needSignedIn
	needAll
	needAny
	needIn
)

// Need is what an operation asks of the caller; every operation declares one.
type Need struct {
	kind      needKind
	perms     []Code
	scopeFrom ScopeFunc
}

// ScopeFunc reads the target's scope from the request; false when the request names none.
type ScopeFunc func(ctx huma.Context) (Scope, bool)

func Public() Need   { return Need{kind: needPublic} }
func SignedIn() Need { return Need{kind: needSignedIn} }

// Requires asks for every one of perms, each granted everywhere: a scoped grant does not count.
func Requires(perms ...Code) Need {
	if len(perms) == 0 {
		panic("rbac: Requires needs at least one permission")
	}
	return Need{kind: needAll, perms: slices.Clone(perms)}
}

// RequiresAny asks for at least one of perms, granted everywhere.
func RequiresAny(perms ...Code) Need {
	if len(perms) == 0 {
		panic("rbac: RequiresAny needs at least one permission")
	}
	return Need{kind: needAny, perms: slices.Clone(perms)}
}

// RequiresIn asks for perm everywhere or within the scope scopeFrom reads from the request.
func RequiresIn(perm Code, scopeFrom ScopeFunc) Need {
	if perm == "" || scopeFrom == nil {
		panic("rbac: RequiresIn needs a permission and a scope reader")
	}
	return Need{kind: needIn, perms: []Code{perm}, scopeFrom: scopeFrom}
}

// PathScope reads a scope of scopeType from the uuid in path parameter param.
func PathScope(scopeType, param string) ScopeFunc {
	return func(ctx huma.Context) (Scope, bool) {
		id, err := uuid.Parse(ctx.Param(param))
		if err != nil {
			return Scope{}, false
		}
		return Scope{Type: scopeType, ID: id}, true
	}
}

const metaNeed = "keel:need"

// Apply makes a Need an httpx.Register option.
func (n Need) Apply(op *huma.Operation) { httpx.SetMeta(op, metaNeed, n) }

func NeedOf(op *huma.Operation) (Need, bool) {
	n, ok := op.Metadata[metaNeed].(Need)
	return n, ok && n.kind != 0
}

func (n Need) Perms() []Code { return slices.Clone(n.perms) }

func (n Need) IsPublic() bool { return n.kind == needPublic }

// IsAny is true for RequiresAny, where one of Perms is enough.
func (n Need) IsAny() bool { return n.kind == needAny }

func (n Need) String() string {
	names := make([]string, len(n.perms))
	for i, p := range n.perms {
		names[i] = string(p)
	}
	switch n.kind {
	case needPublic:
		return "public"
	case needSignedIn:
		return "signed-in"
	case needAll:
		return strings.Join(names, " and ")
	case needAny:
		return "any of " + strings.Join(names, ", ")
	case needIn:
		return names[0] + " in scope"
	}
	return "none"
}

// verdict is the status Enforce answers with: 0 lets the request through.
func (n Need) verdict(ctx huma.Context, p Principal, signedIn bool) int {
	switch n.kind {
	case needPublic:
		return 0
	case needSignedIn, needAll, needAny, needIn:
		if !signedIn {
			return http.StatusUnauthorized
		}
	default:
		return http.StatusForbidden
	}
	switch n.kind {
	case needAll:
		if len(p.Missing(n.perms...)) > 0 {
			return http.StatusForbidden
		}
	case needAny:
		if !slices.ContainsFunc(n.perms, p.Can) {
			return http.StatusForbidden
		}
	case needIn:
		if p.Can(n.perms[0]) {
			return 0
		}
		if scope, ok := n.scopeFrom(ctx); !ok || !p.CanIn(n.perms[0], scope) {
			return http.StatusForbidden
		}
	case needPublic, needSignedIn:
	}
	return 0
}

// Enforce refuses a request whose operation's Need the caller does not meet, before the handler runs.
// A principal of another realm counts as nobody.
func Enforce(api huma.API, principals Principals) func(huma.Context, func(huma.Context)) {
	return enforcer{api: api, principals: principals}.handle
}

type enforcer struct {
	api        huma.API
	principals Principals
}

func (e enforcer) handle(ctx huma.Context, next func(huma.Context)) {
	op := ctx.Operation()
	need, ok := NeedOf(op)
	if !ok {
		logx.From(ctx.Context()).Error("operation has no Need", "operation", op.OperationID)
	}
	p, signedIn := e.principals.Principal(ctx.Context())
	if signedIn && (p.system || p.Realm != httpx.RealmOf(op)) {
		signedIn = false
	}
	switch need.verdict(ctx, p, signedIn) {
	case 0:
		next(ctx)
	case http.StatusUnauthorized:
		_ = huma.WriteErr(e.api, ctx, http.StatusUnauthorized, "", problem.New(http.StatusUnauthorized, "unauthenticated", "sign in to continue"))
	default:
		_ = huma.WriteErr(e.api, ctx, http.StatusForbidden, "", problem.New(http.StatusForbidden, problem.CodeForbidden, "you do not have permission to do this"))
	}
}

// Check reports every operation on api, hidden ones included, without a Need or asking for a
// permission cat does not hold.
func Check(api huma.API, cat *Catalogue) error {
	var errs []error
	for _, op := range httpx.Operations(api) {
		need, ok := NeedOf(op)
		if !ok {
			errs = append(errs, fmt.Errorf("%s %s (%s) declares no Need", op.Method, op.Path, op.OperationID))
			continue
		}
		if unknown := cat.Unknown(need.perms...); len(unknown) > 0 {
			errs = append(errs, fmt.Errorf("%s %s (%s) needs permissions missing from the catalogue: %v", op.Method, op.Path, op.OperationID, unknown))
		}
	}
	return errors.Join(errs...)
}

var _ httpx.Option = Need{}

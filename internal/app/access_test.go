package app_test

import (
	"context"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/idempotency"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

type idInput struct {
	ID   string `path:"id" format:"uuid"`
	Body struct {
		Name string `json:"name" minLength:"1"`
	}
}

// guardedOperations are one write per kind of Need, one of them hidden from the document.
func guardedOperations(api huma.API) {
	write := ratelimit.Class(ratelimit.ClassAPIWrite)
	ok := func(context.Context, *idInput) (*httpx.NoContent, error) { return &httpx.NoContent{}, nil }
	tags := []string{"test"}
	httpx.Register(api, huma.Operation{OperationID: "updateThing", Method: http.MethodPatch, Path: "/things/{id}", Tags: tags},
		ok, rbac.Requires(app.PermUsersManage), write)
	httpx.Register(api, huma.Operation{OperationID: "deleteThing", Method: http.MethodDelete, Path: "/things/{id}", Tags: tags},
		ok, rbac.Requires(app.PermUsersManage, app.PermAccessManage), write)
	httpx.Register(api, huma.Operation{OperationID: "approveThing", Method: http.MethodPost, Path: "/things/{id}/approve", Tags: tags},
		ok, rbac.RequiresAny(app.PermAccessManage, app.PermUsersManage), write)
	httpx.Register(api, huma.Operation{OperationID: "starThing", Method: http.MethodPost, Path: "/things/{id}/star", Tags: tags},
		ok, rbac.SignedIn(), write)
	httpx.Register(api, huma.Operation{OperationID: "purgeThing", Method: http.MethodPost, Path: "/things/{id}/purge", Tags: tags, Hidden: true},
		ok, rbac.Requires(app.PermAccessManage), write)
}

const guardedWrites = 5

// publicWrites are the unsafe operations anyone may call; every other write needs a principal.
var publicWrites = []string{
	"signIn", "devLogin", "requestPasswordReset", "resetPassword", "verifyEmail", "acceptInvite", "pairDevice",
	"beginPasskeySignIn", "finishPasskeySignIn", "reportLeakedApiKeys",
}

func as(h http.Handler, p rbac.Principal) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(rbac.WithPrincipal(r.Context(), p)))
	})
}

var pathParam = regexp.MustCompile(`\{[^}]+\}`)

// Every write operation, hidden ones included, refuses the anonymous (401), a principal of another
// realm (401) and a principal short of its Need (403), and lets one that meets it through. Dropping
// one permission at a time proves each Need asks for exactly what it says.
func TestPermissionWalk(t *testing.T) {
	built := build(t, nil, guardedOperations)
	user := users.ID(ids.New())
	walked := 0
	built.Realms.Each(func(r realm.Realm, api huma.API) {
		var all []rbac.Code
		for _, p := range r.Catalogue.All() {
			all = append(all, p.Code)
		}
		holding := func(perms ...rbac.Code) http.Handler {
			var grants []rbac.Grant
			for _, p := range perms {
				grants = append(grants, rbac.Grant{Perm: p})
			}
			return as(built.Handler, rbac.NewPrincipal(user, r.Name, grants...))
		}
		for _, op := range httpx.Operations(api) {
			if slices.Contains([]string{http.MethodGet, http.MethodHead, http.MethodOptions}, op.Method) {
				continue
			}
			walked++
			need, ok := rbac.NeedOf(op)
			require.True(t, ok, op.OperationID)
			call := func(h http.Handler) int {
				return send(t, h, op.Method, pathParam.ReplaceAllString(op.Path, ids.New().String()), `{"name":"x"}`, nil).Code
			}
			passes := func(h http.Handler) bool {
				return !slices.Contains([]int{http.StatusUnauthorized, http.StatusForbidden}, call(h))
			}
			if need.IsPublic() {
				assert.Contains(t, publicWrites, op.OperationID, "%s is a public write that is not on the allowlist", op.OperationID)
				continue
			}
			assert.Equal(t, http.StatusUnauthorized, call(built.Handler), "%s anonymous", op.OperationID)
			other := as(built.Handler, rbac.NewPrincipal(user, "elsewhere", rbac.Grant{Perm: app.PermAccessManage}, rbac.Grant{Perm: app.PermUsersManage}))
			assert.Equal(t, http.StatusUnauthorized, call(other), "%s from another realm", op.OperationID)
			assert.True(t, passes(holding(all...)), "%s with every permission", op.OperationID)

			perms := need.Perms()
			switch {
			case len(perms) == 0:
				assert.True(t, passes(holding()), "%s signed in", op.OperationID)
			case need.IsAny():
				for _, p := range perms {
					assert.True(t, passes(holding(p)), "%s with only %s", op.OperationID, p)
				}
				assert.Equal(t, http.StatusForbidden, call(holding(without(all, perms...)...)), "%s with none of %s", op.OperationID, need)
			default:
				for _, p := range perms {
					assert.Equal(t, http.StatusForbidden, call(holding(without(all, p)...)), "%s without %s", op.OperationID, p)
				}
			}
		}
	})
	assert.GreaterOrEqual(t, walked, guardedWrites)
}

func without(all []rbac.Code, drop ...rbac.Code) []rbac.Code {
	return slices.DeleteFunc(slices.Clone(all), func(c rbac.Code) bool { return slices.Contains(drop, c) })
}

func TestBuild_RefusesOperationsMissingTheirDeclarations(t *testing.T) {
	cfg, err := app.LoadConfig([]string{"APP_ENV=test", signingKeys})
	require.NoError(t, err)
	noop := func(context.Context, *struct{}) (*httpx.NoContent, error) { return &httpx.NoContent{}, nil }
	read := ratelimit.Class(ratelimit.ClassAPIRead)
	tests := []struct {
		name string
		op   huma.Operation
		opts []httpx.Option
		want string
	}{
		{"no need", huma.Operation{OperationID: "a", Tags: []string{"t"}}, []httpx.Option{read}, "declares no Need"},
		{"no class", huma.Operation{OperationID: "b", Tags: []string{"t"}}, []httpx.Option{rbac.Public()}, "declares no rate-limit class"},
		{"undefined class", huma.Operation{OperationID: "c", Tags: []string{"t"}}, []httpx.Option{rbac.Public(), ratelimit.Class("nope")}, "undefined rate-limit class"},
		{"unknown permission", huma.Operation{OperationID: "d", Tags: []string{"t"}}, []httpx.Option{rbac.Requires("zz_unknown.read"), read}, "missing from the catalogue"},
		{"no tags", huma.Operation{OperationID: "e"}, []httpx.Option{rbac.Public(), read}, "needs an OperationID and tags"},
		{"hidden and no need", huma.Operation{OperationID: "f", Tags: []string{"t"}, Hidden: true}, []httpx.Option{read}, "declares no Need"},
		{"hidden and no class", huma.Operation{OperationID: "g", Tags: []string{"t"}, Hidden: true}, []httpx.Option{rbac.SignedIn()}, "declares no rate-limit class"},
		{"idempotent and public", huma.Operation{OperationID: "h", Tags: []string{"t"}}, []httpx.Option{rbac.Public(), read, idempotency.Required()}, "is public"},
		{"idempotent without a body limit", huma.Operation{OperationID: "i", Tags: []string{"t"}, MaxBodyBytes: -1}, []httpx.Option{rbac.SignedIn(), read, idempotency.Required()}, "no body limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := tt.op
			op.Method, op.Path = http.MethodPost, "/x/"+strings.ReplaceAll(tt.name, " ", "-")
			_, err := app.Build(t.Context(), cfg, app.Deps{}, func(api huma.API) { httpx.Register(api, op, noop, tt.opts...) })
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestBuild_IdempotentOperationsFailClosedWithoutAStore(t *testing.T) {
	h := build(t, nil, func(api huma.API) {
		httpx.Register(api, huma.Operation{OperationID: "pay", Method: http.MethodPost, Path: "/pay", Tags: []string{"test"}},
			func(context.Context, *struct{}) (*httpx.NoContent, error) { return &httpx.NoContent{}, nil },
			rbac.SignedIn(), ratelimit.Class(ratelimit.ClassAPIWrite), idempotency.Required())
	}).Handler

	signedIn := as(h, rbac.NewPrincipal(users.ID(ids.New()), app.RealmTenant))
	rec := send(t, signedIn, http.MethodPost, "/api/v1/pay", "", map[string]string{idempotency.Header: "k-1"})
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// user:grant is break-glass: the system grants what nobody holds yet, audited as the system, but only
// roles of the realm it names.
func TestGrantRole_GrantsAsTheSystemWithinTheRealm(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		ctx := t.Context()
		rec := audit.New(audit.Options{})
		_, err := app.Setup(ctx, app.Deps{DB: e.DB()}, rec)
		require.NoError(t, err)
		email := ids.New().String() + "@example.test"
		var u users.User
		require.NoError(t, db.InTx(ctx, e.DB(), func(ctx context.Context, tx db.Tx[db.Plain]) error {
			u, err = users.NewService(rec, app.NewAccess(rec)).Create(ctx, tx, users.NewUser{Email: email})
			return err
		}))

		require.NoError(t, app.GrantRole(ctx, app.Deps{DB: e.DB()}, rec, app.RealmTenant, "admin", strings.ToUpper(email), ""))
		require.ErrorIs(t, app.GrantRole(ctx, app.Deps{DB: e.DB()}, rec, app.RealmTenant, "admin", email, ""), rbac.ErrAlreadyGranted)
		require.Error(t, app.GrantRole(ctx, app.Deps{DB: e.DB()}, rec, "nowhere", "admin", email, ""), "no such realm")

		var actorType string
		require.NoError(t, e.DB().SQL().QueryRowContext(ctx, db.Rebind(e.Dialect(),
			"SELECT actor_type FROM audit_log WHERE action = 'user_role.granted' AND entity_id = ?"), u.ID.String()).Scan(&actorType))
		assert.Equal(t, string(audit.ActorSystem), actorType)
	})
}

// A built-in role whose definition changed after a database was set up catches up on the next setup: the
// permission it gained is added, one it dropped is removed, and the change is recorded once.
func TestSetup_SyncsExistingBuiltinRoles(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		d := e.Isolated(t)
		ctx := t.Context()
		rec := audit.New(audit.Options{})
		_, err := app.Setup(ctx, app.Deps{DB: d}, rec)
		require.NoError(t, err)
		_, err = d.SQL().ExecContext(ctx, db.Rebind(d.Dialect(), "DELETE FROM role_permissions WHERE permission = ?"), string(app.PermDevicesManage))
		require.NoError(t, err, "the database predates the permission")
		_, err = d.SQL().ExecContext(ctx, "INSERT INTO role_permissions (role_id, permission) SELECT id, 'zz_retired.read' FROM roles WHERE code = 'admin'")
		require.NoError(t, err, "the definition has since dropped a permission")

		res, err := app.Setup(ctx, app.Deps{DB: d}, rec)
		require.NoError(t, err)
		require.Len(t, res.Synced, 1)
		assert.Empty(t, res.Created)
		assert.Equal(t, "admin", res.Synced[0].Code)
		assert.Contains(t, res.Synced[0].Permissions, app.PermDevicesManage)
		assert.NotContains(t, res.Synced[0].Permissions, rbac.Code("zz_retired.read"))
		var synced int
		require.NoError(t, d.SQL().QueryRowContext(ctx, "SELECT count(*) FROM audit_log WHERE action = 'role.permissions_synced'").Scan(&synced))
		assert.Equal(t, 1, synced)

		again, err := app.Setup(ctx, app.Deps{DB: d}, rec)
		require.NoError(t, err)
		assert.Empty(t, again.Synced, "nothing left to change")
	})
}

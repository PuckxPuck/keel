package rbac_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"

	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

type fixed struct {
	p  rbac.Principal
	ok bool
}

func (f fixed) Principal(context.Context) (rbac.Principal, bool) { return f.p, f.ok }

func TestEnforce(t *testing.T) {
	user := users.ID(ids.New())
	tests := []struct {
		name   string
		need   rbac.Need
		caller fixed
		want   int
	}{
		{"public lets anyone in", rbac.Public(), fixed{}, http.StatusNoContent},
		{"signed in refuses nobody", rbac.SignedIn(), fixed{}, http.StatusUnauthorized},
		{"signed in lets a principal in", rbac.SignedIn(), fixed{rbac.NewPrincipal(user, "tenant"), true}, http.StatusNoContent},
		{
			"requires refuses a principal missing one", rbac.Requires(read, write),
			fixed{rbac.NewPrincipal(user, "tenant", rbac.Grant{Perm: read}), true},
			http.StatusForbidden,
		},
		{
			"requires lets a holder of all in", rbac.Requires(read, write),
			fixed{rbac.NewPrincipal(user, "tenant", rbac.Grant{Perm: read}, rbac.Grant{Perm: write}), true},
			http.StatusNoContent,
		},
		{
			"requires refuses a holder only within a scope", rbac.Requires(write),
			fixed{rbac.NewPrincipal(user, "tenant", rbac.Grant{Perm: write, Scope: &branch}), true},
			http.StatusForbidden,
		},
		{
			"requires in lets a holder within the request's scope in", rbac.RequiresIn(write, rbac.PathScope("branch", "id")),
			fixed{rbac.NewPrincipal(user, "tenant", rbac.Grant{Perm: write, Scope: &branch}), true},
			http.StatusNoContent,
		},
		{
			"requires in refuses a holder within another scope", rbac.RequiresIn(write, rbac.PathScope("branch", "id")),
			fixed{rbac.NewPrincipal(user, "tenant", rbac.Grant{Perm: write, Scope: &other}), true},
			http.StatusForbidden,
		},
		{
			"requires in lets a holder everywhere in", rbac.RequiresIn(write, rbac.PathScope("branch", "id")),
			fixed{rbac.NewPrincipal(user, "tenant", rbac.Grant{Perm: write}), true},
			http.StatusNoContent,
		},
		{
			"requires any refuses a holder only within a scope", rbac.RequiresAny(read, write),
			fixed{rbac.NewPrincipal(user, "tenant", rbac.Grant{Perm: write, Scope: &branch}), true},
			http.StatusForbidden,
		},
		{
			"requires any lets a holder of one in", rbac.RequiresAny(read, write),
			fixed{rbac.NewPrincipal(user, "tenant", rbac.Grant{Perm: write}), true},
			http.StatusNoContent,
		},
		{
			"requires any refuses a holder of none", rbac.RequiresAny(read, write),
			fixed{rbac.NewPrincipal(user, "tenant", rbac.Grant{Perm: manage}), true},
			http.StatusForbidden,
		},
		{
			"a principal of another realm counts as nobody", rbac.Requires(read),
			fixed{rbac.NewPrincipal(user, "operator", rbac.Grant{Perm: read}), true},
			http.StatusUnauthorized,
		},
		{"no Need refuses everyone", rbac.Need{}, fixed{rbac.NewPrincipal(user, "tenant", rbac.Grant{Perm: read}), true}, http.StatusForbidden},
		{"the system is never a caller", rbac.SignedIn(), fixed{rbac.System("tenant"), true}, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := httpx.NewRouter()
			api := httpx.NewAPI(router, httpx.Options{Title: "t", Version: "1", Realm: "tenant"})
			api.UseMiddleware(rbac.Enforce(api, tt.caller))
			httpx.Register(api, huma.Operation{OperationID: "op", Method: http.MethodPost, Path: "/branches/{id}/op"},
				func(context.Context, *struct {
					ID string `path:"id"`
				},
				) (*httpx.NoContent, error) {
					return &httpx.NoContent{}, nil
				}, tt.need)

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/branches/"+branch.ID.String()+"/op", nil))

			assert.Equal(t, tt.want, rec.Code)
		})
	}
}

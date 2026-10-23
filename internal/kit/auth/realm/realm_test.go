package realm_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
)

var cat = rbac.NewCatalogue()

type whoami struct {
	Realm string `json:"realm"`
}

func register(api huma.API, id, path string) {
	httpx.Register(api, huma.Operation{OperationID: id, Method: http.MethodGet, Path: path},
		func(ctx context.Context, _ *struct{}) (*httpx.One[whoami], error) {
			return httpx.OneOf(whoami{Realm: httpx.Realm(ctx)}), nil
		})
}

func get(t *testing.T, h http.Handler, host, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Every operation answers on its own realm's hosts and on no other realm's.
func TestRealmWalk(t *testing.T) {
	set, err := realm.New(httpx.Options{Title: "t", Version: "1"},
		realm.Realm{Name: "tenant", BasePath: "/api/v1", Catalogue: cat},
		realm.Realm{Name: "operator", Hosts: []string{"ops.example.test", "Admin.Example.Test"}, BasePath: "/api/v1", Catalogue: cat},
	)
	require.NoError(t, err)
	register(set.API("tenant"), "tenantOnly", "/tenant-only")
	register(set.API("operator"), "operatorOnly", "/operator-only")
	hosts := map[string][]string{
		"tenant":   {"app.example.test", "acme.example.test:8443", "127.0.0.1:8080"},
		"operator": {"ops.example.test", "OPS.example.test:443", "admin.example.test.", "ops.example.test:8080"},
	}

	set.Each(func(owner realm.Realm, api huma.API) {
		for _, op := range httpx.Operations(api) {
			assert.Equal(t, owner.Name, httpx.RealmOf(op))
			for name, list := range hosts {
				for _, host := range list {
					rec := get(t, set, host, op.Path)
					if name != owner.Name {
						assert.Equal(t, http.StatusNotFound, rec.Code, "%s on %s", op.OperationID, host)
						continue
					}
					require.Equal(t, http.StatusOK, rec.Code, "%s on %s", op.OperationID, host)
					var body httpx.OneBody[whoami]
					require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
					assert.Equal(t, owner.Name, body.Data.Realm)
				}
			}
		}
	})
}

func TestUnknownHostWithoutFallbackIsNotFound(t *testing.T) {
	set, err := realm.New(httpx.Options{Title: "t", Version: "1"},
		realm.Realm{Name: "operator", Hosts: []string{"ops.example.test"}, Catalogue: cat})
	require.NoError(t, err)

	rec := get(t, set, "evil.example.test", "/anything")

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), `"code":"not_found"`)
}

func TestNew_RefusesAmbiguousRealms(t *testing.T) {
	tests := []struct {
		name   string
		realms []realm.Realm
	}{
		{"two fallbacks", []realm.Realm{{Name: "a", Catalogue: cat}, {Name: "b", Catalogue: cat}}},
		{"one host claimed twice", []realm.Realm{
			{Name: "a", Hosts: []string{"x.example.test"}, Catalogue: cat},
			{Name: "b", Hosts: []string{"X.example.test:443"}, Catalogue: cat},
		}},
		{"a name used twice", []realm.Realm{{Name: "a", Catalogue: cat}, {Name: "a", Hosts: []string{"y.example.test"}, Catalogue: cat}}},
		{"no catalogue", []realm.Realm{{Name: "a"}}},
		{"a malformed host", []realm.Realm{{Name: "a", Hosts: []string{"[a.example.test]"}, Catalogue: cat}}},
		{"an invalid internationalised host", []realm.Realm{{Name: "a", Hosts: []string{"a_bü.example"}, Catalogue: cat}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := realm.New(httpx.Options{Title: "t", Version: "1"}, tt.realms...)
			assert.Error(t, err)
		})
	}
}

// Hosts are parsed strictly: brackets only around an IPv6 literal, a numeric port, one trailing dot,
// and internationalised names in punycode.
func TestServeHTTP_ParsesTheHostStrictly(t *testing.T) {
	set, err := realm.New(httpx.Options{Title: "t", Version: "1"},
		realm.Realm{Name: "tenant", Catalogue: cat},
		realm.Realm{Name: "operator", Hosts: []string{"ops.example.test", "bücher.example", "[2001:db8::1]"}, Catalogue: cat},
	)
	require.NoError(t, err)
	register(set.API("tenant"), "tenantWho", "/who")
	register(set.API("operator"), "operatorWho", "/who")

	tests := []struct {
		host      string
		wantRealm string
		wantCode  int
	}{
		{"ops.example.test", "operator", http.StatusOK},
		{"OPS.Example.Test.:8443", "operator", http.StatusOK},
		{"xn--bcher-kva.example", "operator", http.StatusOK},
		{"BÜCHER.example", "operator", http.StatusOK},
		{"[2001:DB8:0::1]:443", "operator", http.StatusOK},
		{"ops.example.test..", "tenant", http.StatusOK},
		{"other.example.test", "tenant", http.StatusOK},
		{"[ops.example.test]", "", http.StatusBadRequest},
		{"[ops.example.test]:443", "", http.StatusBadRequest},
		{"[[ops.example.test]]", "", http.StatusBadRequest},
		{"ops.example.test]", "", http.StatusBadRequest},
		{"ops.example.test:https", "", http.StatusBadRequest},
		{"ops.example.test:99999", "", http.StatusBadRequest},
		{"2001:db8::1", "", http.StatusBadRequest},
		{"[fe80::1%25en0]", "", http.StatusBadRequest},
	}
	for _, tt := range tests {
		rec := get(t, set, tt.host, "/who")
		require.Equal(t, tt.wantCode, rec.Code, tt.host)
		if tt.wantCode != http.StatusOK {
			continue
		}
		var body httpx.OneBody[whoami]
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, tt.wantRealm, body.Data.Realm, tt.host)
	}
}

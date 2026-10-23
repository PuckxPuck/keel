//go:build !notenancy && !nofiles && !nonotes

package app_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/files"
	"github.com/PuckxPuck/keel/internal/kit/files/inspect"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/tenancy"
	"github.com/PuckxPuck/keel/internal/modules/notes"
)

const publicKind = "test-public"

func (a *tenancyApp) upload(host, kind string, cookie *http.Cookie) *httptest.ResponseRecorder {
	a.t.Helper()
	ctx := logx.WithLogger(a.t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/files/"+kind, strings.NewReader("shift notes"))
	r.Host = host
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("Content-Disposition", `attachment; filename="notes.txt"`)
	r.AddCookie(cookie)
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, r)
	return rec
}

// publicLink signs a link the way the files service does, as path and query.
func (a *tenancyApp) publicLink(fileID string, tenant tenancy.Tenant) string {
	a.t.Helper()
	signer, err := files.NewURLSigner(a.cfg.App.PublicURL+app.BasePath+"/public-files", a.cfg.SigningKeys()...)
	require.NoError(a.t, err)
	id, err := files.ParseID(fileID)
	require.NoError(a.t, err)
	link, err := signer.URL(id, tenant.ID.UUID(), clock.Wall(a.t.Context()).Now(), time.Hour)
	require.NoError(a.t, err)
	u, err := url.Parse(link)
	require.NoError(a.t, err)
	return u.RequestURI()
}

// File routes run inside the tenant realm: only the uploader reads a file no owner type lets others
// read, another tenant's file does not exist, an upload needs its kind's permission and a writable
// tenant, and a public link serves only on its own tenant's or the shared host while the tenant is not
// suspended.
func TestFiles_RoutesKeepTenantsAndPermissions(t *testing.T) {
	t.Cleanup(app.MountTestFileKind(publicKind, files.Policy{
		MaxBytes: 1 << 10, Types: []string{inspect.TypeText}, Inspect: true, Visibility: files.Public,
	}, notes.PermWrite))
	a := newTenancyApp(t, "APP_FILES_DRIVER=local", "APP_FILES_ROOT="+t.TempDir())
	ann, bob, carol := a.person("ann"), a.person("bob"), a.person("carol")
	acme, initech, umbrella := a.tenant("acme", ann), a.tenant("initech", ann), a.tenant("umbrella", ann)
	a.tenant("globex", bob)
	rec := audit.New(audit.Options{})
	err := db.InTx(db.WithTenant(t.Context(), acme.ID.UUID()), a.d.DB, func(ctx context.Context, tx db.Tx[db.Tenant]) error {
		_, err := app.NewAccess(rec).CreateRole(ctx, tx, rbac.System(app.RealmTenant),
			rbac.NewRole{Code: "reader", Name: "Reader", Permissions: []rbac.Code{notes.PermRead}})
		return err
	})
	require.NoError(t, err)
	require.NoError(t, app.GrantRole(t.Context(), a.deps, rec, app.RealmTenant, "reader", carol, "acme"))
	_, annIn := a.signIn("acme.tenants.example.test", ann)
	_, carolIn := a.signIn(acmeHost, carol)
	_, bobIn := a.signIn(globexHost, bob)
	_, annUmbrella := a.signIn("umbrella.tenants.example.test", ann)
	_, annInitech := a.signIn("initech.tenants.example.test", ann)
	require.NotNil(t, annIn)
	require.NotNil(t, carolIn)
	require.NotNil(t, bobIn)
	require.NotNil(t, annUmbrella)
	require.NotNil(t, annInitech)

	staged := a.upload(acmeHost, notes.AttachmentKind, annIn)
	require.Equal(t, http.StatusCreated, staged.Code, staged.Body.String())
	stagedPath := "/api/v1/files/" + data(t, staged)["id"].(string)
	public := a.upload(acmeHost, publicKind, annIn)
	require.Equal(t, http.StatusCreated, public.Code, public.Body.String())
	acmeLink := a.publicLink(data(t, public)["id"].(string), acme)
	suspended := a.upload("umbrella.tenants.example.test", publicKind, annUmbrella)
	require.Equal(t, http.StatusCreated, suspended.Code, suspended.Body.String())
	umbrellaLink := a.publicLink(data(t, suspended)["id"].(string), umbrella)
	_, err = app.SetTenantState(t.Context(), a.cfg, a.deps, umbrella.Slug, tenancy.Suspended, "")
	require.NoError(t, err)
	_, err = app.SetTenantState(t.Context(), a.cfg, a.deps, initech.Slug, tenancy.ReadOnly, "")
	require.NoError(t, err)

	tests := []struct {
		name   string
		status int
		do     func() *httptest.ResponseRecorder
	}{
		{"the uploader reads their file", http.StatusOK, func() *httptest.ResponseRecorder {
			return a.call(http.MethodGet, acmeHost, stagedPath, "", annIn)
		}},
		{"another member cannot: no reader for the file's owner", http.StatusNotFound, func() *httptest.ResponseRecorder {
			return a.call(http.MethodGet, acmeHost, stagedPath, "", carolIn)
		}},
		{"another tenant's owner cannot", http.StatusNotFound, func() *httptest.ResponseRecorder {
			return a.call(http.MethodGet, globexHost, stagedPath, "", bobIn)
		}},
		{"an upload needs its kind's permission", http.StatusForbidden, func() *httptest.ResponseRecorder {
			return a.upload(acmeHost, notes.AttachmentKind, carolIn)
		}},
		{"a read-only tenant takes no uploads", http.StatusForbidden, func() *httptest.ResponseRecorder {
			return a.upload("initech.tenants.example.test", notes.AttachmentKind, annInitech)
		}},
		{"a public link serves on the shared host", http.StatusOK, func() *httptest.ResponseRecorder {
			return a.call(http.MethodGet, sharedHost, acmeLink, "", nil)
		}},
		{"a public link serves on its tenant's host", http.StatusOK, func() *httptest.ResponseRecorder {
			return a.call(http.MethodGet, acmeHost, acmeLink, "", nil)
		}},
		{"a public link is bound to its tenant", http.StatusNotFound, func() *httptest.ResponseRecorder {
			return a.call(http.MethodGet, globexHost, acmeLink, "", nil)
		}},
		{"a suspended tenant's public link is gone", http.StatusNotFound, func() *httptest.ResponseRecorder {
			return a.call(http.MethodGet, sharedHost, umbrellaLink, "", nil)
		}},
	}
	for _, tt := range tests {
		got := tt.do()
		assert.Equal(t, tt.status, got.Code, "%s: %s", tt.name, got.Body.String())
	}
}

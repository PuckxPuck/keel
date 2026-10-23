//go:build !notenancy

package app_test

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/cli"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/jobs"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/tenancy"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

const (
	sharedHost = "app.example.test"
	acmeHost   = "acme.tenants.example.test"
	globexHost = "globex.tenants.example.test"
)

type tenancyApp struct {
	t     *testing.T
	d     *testdb.TenancyDB
	cfg   app.Config
	deps  app.Deps
	h     http.Handler
	q     *jobs.Queue
	links *links
}

const opsHost = "ops.example.test"

func newTenancyApp(t *testing.T, env ...string) *tenancyApp {
	t.Helper()
	d := testdb.Tenancy(t)
	environ := append([]string{
		"APP_ENV=test", "APP_PUBLIC_URL=http://localhost:8080", "APP_PASSWORD_ARGON2=m=64,t=1,p=1", signingKeys,
		"APP_TENANCY_HOST_SUFFIX=.tenants.example.test", "APP_REALM_OPERATOR_HOSTS=" + opsHost, "APP_MFA_KEYS=tenancy-test-key",
	}, env...)
	cfg, err := app.LoadConfig(environ)
	require.NoError(t, err)
	a := &tenancyApp{t: t, d: d, cfg: cfg, links: &links{}}
	a.deps = app.Deps{DB: d.DB, Operator: d.Operator, Tenancy: true, Notifier: a.links}
	require.NoError(t, app.CheckTenancy(t.Context(), a.deps))
	built, err := app.Build(t.Context(), cfg, a.deps)
	require.NoError(t, err)
	a.h, a.q = built.Handler, built.Queue
	_, err = app.Setup(t.Context(), a.deps, audit.New(audit.Options{}))
	require.NoError(t, err)
	return a
}

func (a *tenancyApp) call(method, host, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	a.t.Helper()
	ctx := logx.WithLogger(a.t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequestWithContext(ctx, method, path, strings.NewReader(body))
	r.Host = host
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, r)
	return rec
}

// person creates a user with a password; they belong to no tenant yet.
func (a *tenancyApp) person(name string) string {
	a.t.Helper()
	email := name + "@example.test"
	_, invite, err := app.CreateUser(a.t.Context(), a.cfg, a.deps, email, name, true)
	require.NoError(a.t, err)
	rec := a.call(http.MethodPost, sharedHost, "/api/v1/auth/invites/accept", `{"token":"`+invite+`","password":"`+goodPassword+`"}`, nil)
	require.Equal(a.t, http.StatusNoContent, rec.Code, rec.Body.String())
	return email
}

func (a *tenancyApp) tenant(slug, owner string) tenancy.Tenant {
	a.t.Helper()
	t, err := app.CreateTenant(a.t.Context(), a.cfg, a.deps, tenancy.NewTenant{Slug: slug, Name: slug}, owner)
	require.NoError(a.t, err)
	return t
}

func (a *tenancyApp) signIn(host, email string) (*httptest.ResponseRecorder, *http.Cookie) {
	a.t.Helper()
	rec := a.call(http.MethodPost, host, "/api/v1/auth/sign-in", `{"email":"`+email+`","password":"`+goodPassword+`"}`, nil)
	for _, c := range rec.Result().Cookies() {
		if (c.Name == "session" || c.Name == "operator_session") && c.Value != "" {
			return rec, c
		}
	}
	return rec, nil
}

// owned is what one tenant's owner made: a paired device.
type owned struct {
	cookie   *http.Cookie
	deviceID string
}

func (a *tenancyApp) own(host, email string) owned {
	a.t.Helper()
	rec, cookie := a.signIn(host, email)
	require.NotNil(a.t, cookie, rec.Body.String())
	o := owned{cookie: cookie}
	code := a.call(http.MethodPost, host, "/api/v1/devices/pairing-codes", `{"name":"till"}`, cookie)
	require.Equal(a.t, http.StatusOK, code.Code, code.Body.String())
	paired := a.call(http.MethodPost, host, "/api/v1/devices/pair", `{"code":"`+data(a.t, code)["code"].(string)+`"}`, nil)
	require.Equal(a.t, http.StatusOK, paired.Code, paired.Body.String())
	o.deviceID = data(a.t, paired)["device"].(map[string]any)["id"].(string)
	return o
}

func listed(t *testing.T, rec *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body.Data
}

// Two tenants with the same data: every operation acme's owner calls with globex's ids is 404 and
// changes nothing, and lists show only the caller's tenant.
func TestTenancy_IsolationWalk(t *testing.T) {
	a := newTenancyApp(t)
	ann, bob := a.person("ann"), a.person("bob")
	a.tenant("acme", ann)
	a.tenant("globex", bob)
	acme, globex := a.own(acmeHost, ann), a.own(globexHost, bob)

	walk := []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/devices/" + globex.deviceID + "/rotate", "{}"},
		{http.MethodDelete, "/api/v1/devices/" + globex.deviceID, ""},
	}
	for _, step := range walk {
		rec := a.call(step.method, acmeHost, step.path, step.body, acme.cookie)
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s %s: %s", step.method, step.path, rec.Body.String())
	}

	assert.Len(t, listed(t, a.call(http.MethodGet, globexHost, "/api/v1/devices", "", globex.cookie)), 1, "globex's device is still there")
	own := listed(t, a.call(http.MethodGet, acmeHost, "/api/v1/devices", "", acme.cookie))
	require.Len(t, own, 1)
	assert.Equal(t, acme.deviceID, own[0]["id"])
}

func TestTenancy_MembershipAndAccessState(t *testing.T) {
	a := newTenancyApp(t)
	ann, bob := a.person("ann"), a.person("bob")
	a.tenant("acme", ann)
	a.tenant("globex", bob)
	_, annCookie := a.signIn(acmeHost, ann)
	require.NotNil(t, annCookie)
	pairing := a.call(http.MethodPost, acmeHost, "/api/v1/devices/pairing-codes", `{"name":"till"}`, annCookie)
	require.Equal(t, http.StatusOK, pairing.Code, pairing.Body.String())

	refused, cookie := a.signIn(acmeHost, bob)
	assert.Nil(t, cookie)
	assert.Equal(t, "invalid_credentials", data(t, refused)["code"], "a non-member signs in like a wrong password")
	_, bobCookie := a.signIn(globexHost, bob)
	require.NotNil(t, bobCookie)
	foreign := a.call(http.MethodGet, acmeHost, "/api/v1/me", "", bobCookie)
	assert.Equal(t, http.StatusForbidden, foreign.Code)
	assert.Equal(t, tenancy.CodeNotAMember, data(t, foreign)["code"])
	assert.Equal(t, http.StatusNotFound, a.call(http.MethodGet, "nobody.tenants.example.test", "/api/v1/ping", "", nil).Code)

	_, err := app.SetTenantState(t.Context(), a.cfg, a.deps, "acme", tenancy.ReadOnly, "payment failed")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, a.call(http.MethodGet, acmeHost, "/api/v1/devices", "", annCookie).Code, "reads still work")
	write := a.call(http.MethodPost, acmeHost, "/api/v1/devices/pairing-codes", `{"name":"late"}`, annCookie)
	assert.Equal(t, http.StatusForbidden, write.Code)
	assert.Equal(t, tenancy.CodeReadOnly, data(t, write)["code"])
	paired := a.call(http.MethodPost, acmeHost, "/api/v1/devices/pair", `{"code":"`+data(t, pairing)["code"].(string)+`"}`, nil)
	assert.Equal(t, tenancy.CodeReadOnly, data(t, paired)["code"], "a public write into tenant tables is refused too")
	_, again := a.signIn(acmeHost, ann)
	assert.NotNil(t, again, "signing in still works")

	_, err = app.SetTenantState(t.Context(), a.cfg, a.deps, "acme", tenancy.Suspended, "")
	require.NoError(t, err)
	for _, cookie := range []*http.Cookie{annCookie, nil} {
		rec := a.call(http.MethodGet, acmeHost, "/api/v1/ping", "", cookie)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Equal(t, tenancy.CodeSuspended, data(t, rec)["code"])
	}
	assert.Equal(t, http.StatusUnauthorized, a.call(http.MethodGet, sharedHost, "/api/v1/me", "", annCookie).Code, "the tenant's sessions were cleared")
	assert.Equal(t, http.StatusOK, a.call(http.MethodGet, globexHost, "/api/v1/me", "", bobCookie).Code, "other tenants carry on")
}

func TestTenancy_SwitchRotatesTheSession(t *testing.T) {
	a := newTenancyApp(t)
	ann, bob, carol := a.person("ann"), a.person("bob"), a.person("carol")
	a.tenant("acme", ann)
	globex := a.tenant("globex", bob)
	rec := audit.New(audit.Options{})
	require.NoError(t, app.GrantRole(t.Context(), a.deps, rec, app.RealmTenant, "admin", carol, "acme"))
	require.NoError(t, app.GrantRole(t.Context(), a.deps, rec, app.RealmTenant, "admin", carol, "globex"))
	bobs := a.own(globexHost, bob)

	first := a.cookie(sharedHost, carol)
	require.Len(t, listed(t, a.call(http.MethodGet, sharedHost, "/api/v1/me/tenants", "", first)), 2)
	assert.Empty(t, listed(t, a.call(http.MethodGet, sharedHost, "/api/v1/devices", "", first)), "carol lands in acme, her first tenant")

	switched := a.call(http.MethodPost, sharedHost, "/api/v1/auth/tenant", `{"tenantId":"`+globex.ID.String()+`"}`, first)
	require.Equal(t, http.StatusOK, switched.Code, switched.Body.String())
	var next *http.Cookie
	for _, c := range switched.Result().Cookies() {
		if c.Name == "session" && c.Value != "" {
			next = c
		}
	}
	require.NotNil(t, next)
	assert.NotEqual(t, first.Value, next.Value)
	assert.Equal(t, http.StatusUnauthorized, a.call(http.MethodGet, sharedHost, "/api/v1/me", "", first).Code, "the old token stopped working")
	devices := listed(t, a.call(http.MethodGet, sharedHost, "/api/v1/devices", "", next))
	require.Len(t, devices, 1)
	assert.Equal(t, bobs.deviceID, devices[0]["id"])

	notMine := a.call(http.MethodPost, sharedHost, "/api/v1/auth/tenant", `{"tenantId":"`+globex.ID.String()+`"}`, a.cookie(acmeHost, ann))
	assert.Equal(t, http.StatusForbidden, notMine.Code)
}

func (a *tenancyApp) cookie(host, email string) *http.Cookie {
	a.t.Helper()
	rec, c := a.signIn(host, email)
	require.NotNil(a.t, c, rec.Body.String())
	return c
}

// Every migration, the kit's and every module's, makes a schema the catalogue check passes with the app's
// exceptions: CI catches here what migrate:validate cannot see in the SQL.
func TestTenancy_EveryMigrationPassesTheCatalogue(t *testing.T) {
	require.NoError(t, app.CheckSchema(t.Context(), testdb.Tenancy(t).DB))
}

// An app table whose migration marks it -- keel:global passes the allowlist check of migrate:validate and
// the catalogue check once appGlobalTables lists it, and fails both until then.
func TestTenancy_AppGlobalTablesAreAllowlisted(t *testing.T) {
	fsys, err := migrations.For(db.Postgres)
	require.NoError(t, err)
	require.NoError(t, app.CheckGlobalTables(fsys), "the kit's and the app's own migrations")

	withLedger := fstest.MapFS{"29990101000000_shop_ledger.sql": {Data: []byte(
		"-- keel:global entries every tenant reads\n-- +goose Up\ncreate table shop_ledger (id uuid primary key);\n\n-- +goose Down\ndrop table shop_ledger;\n",
	)}}
	names, err := fs.Glob(fsys, "*.sql")
	require.NoError(t, err)
	for _, name := range names {
		raw, err := fs.ReadFile(fsys, name)
		require.NoError(t, err)
		withLedger[name] = &fstest.MapFile{Data: raw}
	}
	d := testdb.Tenancy(t)
	d.Admin(t, "create table public.shop_ledger (id uuid primary key)")
	require.ErrorContains(t, app.CheckGlobalTables(withLedger), "table shop_ledger is marked -- keel:global but is not in appGlobalTables")
	require.ErrorContains(t, app.CheckSchema(t.Context(), d.DB), "shop_ledger: has no tenant_id")

	defer app.WithAppGlobalTables(tenancy.Exception{Table: "shop_ledger", Reason: "entries every tenant reads"})()
	require.NoError(t, app.CheckGlobalTables(withLedger))
	require.NoError(t, app.CheckSchema(t.Context(), d.DB))
}

func TestTenancy_StartupRefusesAnAppRoleThatBypassesRowLevelSecurity(t *testing.T) {
	d := testdb.Tenancy(t)
	err := app.CheckTenancy(t.Context(), app.Deps{DB: d.As(t, "operator"), Operator: d.Operator, Tenancy: true})
	require.ErrorContains(t, err, "bypasses row-level security")
}

// The operator realm reaches every tenant through the operator pool; the tenant realm has none of its routes.
func TestTenancy_OperatorRealm(t *testing.T) {
	a := newTenancyApp(t, "APP_REALM_OPERATOR_MFA=off")
	ann, olga := a.person("ann"), a.person("olga")
	acme := a.tenant("acme", ann)
	a.tenant("globex", ann)
	require.NoError(t, app.GrantRole(t.Context(), a.deps, audit.New(audit.Options{}), app.RealmOperator, "operator", olga, ""))
	ops := a.cookie(opsHost, olga)

	assert.Equal(t, http.StatusNotFound, a.call(http.MethodGet, acmeHost, "/api/v1/tenants", "", a.cookie(acmeHost, ann)).Code)
	refused, _ := a.signIn(opsHost, ann)
	assert.Equal(t, http.StatusUnauthorized, refused.Code, "a tenant user holds no operator role")

	assert.Len(t, listed(t, a.call(http.MethodGet, opsHost, "/api/v1/tenants", "", ops)), 2)
	suspended := a.call(http.MethodPost, opsHost, "/api/v1/tenants/"+acme.ID.String()+"/suspend", `{"reason":"abuse"}`, ops)
	require.Equal(t, http.StatusOK, suspended.Code, suspended.Body.String())
	assert.Equal(t, "suspended", data(t, suspended)["status"])
	trail := listed(t, a.call(http.MethodGet, opsHost, "/api/v1/tenants/"+acme.ID.String()+"/audit", "", ops))
	require.Len(t, trail, 3, "created, ann's sign-in in acme, suspended")
	assert.Equal(t, "tenant.state_changed", trail[0]["action"])
	assert.Equal(t, "operator", trail[0]["realm"])
	assert.Equal(t, "tenant.created", trail[2]["action"])
}

// operatorEnv is the operator pool production needs under tenancy.
var operatorEnv = []string{"APP_DATABASE_OPERATOR_URL=postgres://operator@db.example.test/app?sslmode=verify-full"}

// migrate checks the schema against the tenancy rules once it has applied the files, and fails on a
// finding, so a deploy stops before the new release serves it.
func TestMigrate_RefusesASchemaThatBreaksTheTenancyRules(t *testing.T) {
	d := testdb.Tenancy(t)
	environ := []string{"APP_ENV=test", "APP_DATABASE_MIGRATE_URL=" + d.AdminURL(t)}
	code, _, stderr := runCommand(t, environ, "migrate")
	require.Equal(t, cli.ExitOK, code, stderr)

	d.Admin(t, "create table public.shared_by_accident (id int primary key)")
	code, _, stderr = runCommand(t, environ, "migrate")
	assert.Equal(t, cli.ExitError, code)
	assert.Contains(t, stderr, "shared_by_accident: has no tenant_id")
}

func TestLoadConfig_TenancyRules(t *testing.T) {
	pg := "APP_DATABASE_URL=postgres://keel_app@db.example/keel?sslmode=verify-full"
	prod := []string{"APP_ENV=production", "APP_PUBLIC_URL=https://app.example.com", signingKeys, pg}
	tests := []struct {
		name string
		env  []string
		want string
	}{
		{"tenancy settings with MySQL", []string{"APP_ENV=test", signingKeys, "APP_DATABASE_URL=mysql://app@127.0.0.1:3306/keel", "APP_TENANCY_HOST_SUFFIX=.example.app"}, "tenancy needs Postgres"},
		{"operator pool as the app's user", []string{"APP_ENV=test", signingKeys, pg, "APP_DATABASE_OPERATOR_URL=postgres://keel_app@db.example/keel"}, "operator URL must connect as another role"},
		{"production without the operator pool", prod, "tenancy needs APP_DATABASE_OPERATOR_URL"},
		{"operator realm without MFA in production", append(prod, "APP_REALM_OPERATOR_HOSTS=ops.example.com", "APP_REALM_OPERATOR_MFA=off"), "operator realm's MFA must be required"},
		{"an operator pool the workers would drain", []string{"APP_ENV=test", signingKeys, pg, "APP_DATABASE_OPERATOR_URL=postgres://keel_operator@db.example/keel", "APP_DATABASE_OPERATOR_MAX_OPEN=4"}, "needs at least the 5 workers plus 2"},
	}
	for _, tt := range tests {
		_, err := app.LoadConfig(tt.env)
		require.ErrorContains(t, err, tt.want, tt.name)
	}
}

// rotated is the session cookie a response set, else the one the request sent.
func rotated(rec *httptest.ResponseRecorder, cookie *http.Cookie) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookie.Name && c.Value != "" {
			return c
		}
	}
	return cookie
}

// A member removed from a tenant can still sign out there; a session working in it leaves it, so the
// person carries on in their other tenants instead of meeting 403 on every request.
func TestTenancy_RemovedMember(t *testing.T) {
	a := newTenancyApp(t)
	ann, bob, carol := a.person("ann"), a.person("bob"), a.person("carol")
	acme := a.tenant("acme", ann)
	globex := a.tenant("globex", bob)
	rec := audit.New(audit.Options{})
	require.NoError(t, app.GrantRole(t.Context(), a.deps, rec, app.RealmTenant, "admin", carol, "acme"))
	require.NoError(t, app.GrantRole(t.Context(), a.deps, rec, app.RealmTenant, "admin", carol, "globex"))
	shared := a.cookie(sharedHost, carol)
	inAcme := a.cookie(acmeHost, carol)
	operator := func(query string, args ...any) {
		t.Helper()
		require.NoError(t, db.InOperatorTx(t.Context(), a.deps.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
			u, err := users.ByEmail(ctx, tx, carol)
			if err != nil {
				return err
			}
			if query == "" {
				return tenancy.RemoveMember(ctx, tx, acme.ID, u.ID)
			}
			_, err = tx.Q().ExecContext(ctx, query, append([]any{u.ID}, args...)...)
			return err
		}))
	}
	operator("")

	me := a.call(http.MethodGet, sharedHost, "/api/v1/me", "", shared)
	require.Equal(t, http.StatusOK, me.Code, me.Body.String())
	shared = rotated(me, shared)
	assert.Len(t, listed(t, a.call(http.MethodGet, sharedHost, "/api/v1/me/tenants", "", shared)), 1)
	refused := a.call(http.MethodGet, acmeHost, "/api/v1/me", "", inAcme)
	assert.Equal(t, tenancy.CodeNotAMember, data(t, refused)["code"])
	inAcme = rotated(refused, inAcme)
	assert.Equal(t, http.StatusNoContent, a.call(http.MethodPost, acmeHost, "/api/v1/auth/sign-out", "", inAcme).Code, "sign-out always works")

	switched := a.call(http.MethodPost, sharedHost, "/api/v1/auth/tenant", `{"tenantId":"`+globex.ID.String()+`"}`, shared)
	require.Equal(t, http.StatusOK, switched.Code, switched.Body.String())
	shared = rotated(switched, shared)
	operator("UPDATE memberships SET status = 'disabled' WHERE user_id = $1 AND tenant_id = $2", globex.ID)
	for range 2 {
		me := a.call(http.MethodGet, sharedHost, "/api/v1/me", "", shared)
		assert.Equal(t, http.StatusOK, me.Code, "a session whose tenant went away leaves it: %s", me.Body.String())
	}
}

func (a *tenancyApp) trail(tn tenancy.Tenant) []string {
	a.t.Helper()
	var out []string
	require.NoError(a.t, db.InOperatorTx(tenancy.WithTenant(context.Background(), tn), a.deps.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		entries, err := audit.List(ctx, tx, 0, 100)
		for _, e := range entries {
			out = append(out, e.Action)
		}
		return err
	}))
	return out
}

// A shared-host sign-in is the global trail's and entering a tenant is the tenant's; a tenant's trail
// names only its own people.
func TestTenancy_AuditLandsOnTheRightTrail(t *testing.T) {
	a := newTenancyApp(t)
	ann, bob := a.person("ann"), a.person("bob")
	acme := a.tenant("acme", ann)
	globex := a.tenant("globex", bob)

	a.cookie(sharedHost, ann)
	assert.Contains(t, a.trail(acme), "session.entered")
	assert.NotContains(t, a.trail(acme), "session.start", "the shared-host sign-in is on the global trail")

	for _, email := range []string{ann, "nobody@example.test", bob} {
		rec := a.call(http.MethodPost, globexHost, "/api/v1/auth/password/reset-request", `{"email":"`+email+`"}`, nil)
		require.Equal(t, http.StatusNoContent, rec.Code)
	}
	resets := 0
	for _, action := range a.trail(globex) {
		if action == "password.reset_requested" {
			resets++
		}
	}
	assert.Equal(t, 1, resets, "bob's only: ann has no account as far as globex can tell")
}

// A custom domain cannot take a host the app or another tenant serves.
func TestTenancy_CustomDomainsAreChecked(t *testing.T) {
	a := newTenancyApp(t, "APP_TENANCY_CUSTOM_DOMAINS=true", "APP_PUBLIC_URL=https://app.example.test")
	ann := a.person("ann")
	_, err := app.CreateTenant(t.Context(), a.cfg, a.deps, tenancy.NewTenant{Slug: "acme", Name: "acme", Domains: []string{"shop.acme.test"}}, ann)
	require.NoError(t, err)
	for i, domain := range []string{sharedHost, "evil.tenants.example.test", "tenants.example.test", opsHost, "shop.acme.test"} {
		_, err := app.CreateTenant(t.Context(), a.cfg, a.deps, tenancy.NewTenant{Slug: "t" + strconv.Itoa(i), Name: "t", Domains: []string{domain}}, ann)
		require.ErrorIs(t, err, tenancy.ErrInvalid, domain)
	}
}

// Maintenance is global: under tenancy it runs on the operator pool, so one prune reaches every tenant's
// rows, which a tenant transaction or the plain app pool could not see.
func TestMaintenance_RunsOnTheOperatorPoolUnderTenancy(t *testing.T) {
	a := newTenancyApp(t, "APP_JOBS_POLL=50ms", "APP_JOBS_SHUTDOWN_GRACE=0s")
	owner := a.person("Owner")
	for _, tn := range []tenancy.Tenant{a.tenant("maint-a", owner), a.tenant("maint-b", owner)} {
		a.d.Admin(t, "INSERT INTO idempotency_keys (id, tenant_id, realm, principal, idem_key, request_hash, status, created_at, lease_until, expires_at) "+
			"VALUES ('"+ids.New().String()+"', '"+tn.ID.String()+"', 'tenant', 'maintenance-test', 'k', '\\x00', 'done', now() - interval '2 days', now() - interval '2 days', now() - interval '1 day')")
	}
	operator := a.d.As(t, "operator")
	left := func() int {
		var n int
		require.NoError(t, operator.SQL().QueryRowContext(t.Context(), "SELECT count(*) FROM idempotency_keys WHERE principal = 'maintenance-test'").Scan(&n))
		return n
	}
	require.Equal(t, 2, left())

	runMaintenance(t, a.q, "idempotency.prune", func() bool { return left() == 0 })
}

package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/auth"
	"github.com/PuckxPuck/keel/internal/kit/auth/devices"
	"github.com/PuckxPuck/keel/internal/kit/auth/password"
	"github.com/PuckxPuck/keel/internal/kit/auth/realm"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

func TestMain(m *testing.M) {
	problem.Install(auth.Mapper)
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

const (
	read    rbac.Code = "notes.read"
	manage  rbac.Code = "access.manage"
	opsHost           = "ops.example.test"
)

var catalogue = rbac.NewCatalogue(rbac.Perm{Code: read}, rbac.Perm{Code: manage})

var start = time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)

type wallClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *wallClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *wallClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type startInput struct {
	Body struct {
		User   string `json:"user"`
		Bearer bool   `json:"bearer,omitempty"`
	}
}

type startOutput struct {
	Token string `json:"token"`
}

type who struct {
	User string `json:"user"`
}

// harness has two realms: tenant on every host (cookie "session", no MFA) and ops on ops.example.test
// (cookie "ops", MFA required), each with test operations behind the session middleware.
type harness struct {
	db       *db.DB
	sessions *auth.Sessions
	access   *rbac.Access
	users    *users.Service
	devices  *devices.Service
	clock    *wallClock
	handler  http.Handler
	// member is a role without permissions in each realm, so new users may sign in there.
	member map[string]rbac.RoleID
}

type allow struct{}

func (allow) CheckStatus(context.Context, db.Transaction, users.Actor, users.ID, users.Status) error {
	return nil
}

func newHarness(t *testing.T, e *testdb.Engine) *harness { return newHarnessWith(t, e, false) }

func newHarnessWith(t *testing.T, e *testdb.Engine, secure bool) *harness {
	t.Helper()
	rec := audit.New(audit.Options{})
	h := &harness{db: e.DB(), clock: &wallClock{t: start}, users: users.NewService(rec, allow{}), member: map[string]rbac.RoleID{}}
	list := []realm.Realm{
		{
			Name: "tenant", BasePath: "/api", Catalogue: catalogue, Cookie: "session", Idle: 2 * time.Hour, Absolute: 12 * time.Hour,
			MFA: realm.MFAOff, Loader: rbac.NewLoader("tenant", catalogue),
		},
		{
			Name: "ops", Hosts: []string{opsHost}, BasePath: "/api", Catalogue: catalogue, Cookie: "ops", Idle: 30 * time.Minute, Absolute: 8 * time.Hour,
			MFA: realm.MFARequired, Loader: rbac.NewLoader("ops", catalogue),
		},
	}
	var err error
	h.devices = devices.New(rec, func(string, string) []rbac.Grant { return []rbac.Grant{{Perm: read}} })
	h.sessions, err = auth.NewSessions(auth.Options{DB: e.DB(), Audit: rec, Realms: list, CacheTTL: time.Hour, Devices: h.devices, Secure: secure})
	require.NoError(t, err)
	h.access = rbac.NewAccess(rec, rbac.Policy{AccessManage: manage}, map[string]*rbac.Catalogue{"tenant": catalogue, "ops": catalogue}, rbac.WithHook(h.sessions))
	require.NoError(t, db.InTx(t.Context(), h.db, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		for _, name := range []string{"tenant", "ops"} {
			if _, err := h.access.Setup(ctx, tx, name, []rbac.Builtin{{Code: "member", Name: "Member"}}); err != nil {
				return err
			}
			role, err := rbac.RoleByCode(ctx, tx, name, "member")
			h.member[name] = role.ID
			if err != nil {
				return err
			}
		}
		return nil
	}))
	set, err := realm.New(httpx.Options{Title: "t", Version: "1"}, list...)
	require.NoError(t, err)
	set.Each(func(_ realm.Realm, api huma.API) {
		principals := rbac.FromContext{}
		api.UseMiddleware(h.sessions.Resolve(), h.sessions.Require(api, principals), rbac.Enforce(api, principals), h.sessions.Restrict(api))
		h.register(api)
	})
	h.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		set.ServeHTTP(w, r.WithContext(clock.WithWall(r.Context(), h.clock)))
	})
	return h
}

func (h *harness) register(api huma.API) {
	tags := []string{"test"}
	httpx.Register(api, huma.Operation{OperationID: "start", Method: http.MethodPost, Path: "/start", Tags: tags},
		func(ctx context.Context, in *startInput) (*httpx.One[startOutput], error) {
			uid, err := uuid.Parse(in.Body.User)
			if err != nil {
				return nil, err
			}
			kind := auth.KindBrowser
			if in.Body.Bearer {
				kind = auth.KindAPI
			}
			var out startOutput
			err = db.InTx(ctx, h.db, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				s, err := h.sessions.Start(ctx, tx, users.ID(uid), auth.Meta{Kind: kind, Provider: "test"})
				out.Token = s.Token
				return err
			})
			if err != nil {
				return nil, err
			}
			return httpx.OneOf(out), nil
		}, rbac.Public())
	whoami := func(ctx context.Context, _ *struct{}) (*httpx.One[who], error) {
		p, _ := auth.PrincipalFrom(ctx)
		return httpx.OneOf(who{User: p.UserID.String()}), nil
	}
	httpx.Register(api, huma.Operation{OperationID: "who", Method: http.MethodGet, Path: "/who", Tags: tags}, whoami, rbac.SignedIn())
	httpx.Register(api, huma.Operation{OperationID: "read", Method: http.MethodGet, Path: "/read", Tags: tags}, whoami, rbac.Requires(read))
	httpx.Register(api, huma.Operation{OperationID: "pending", Method: http.MethodGet, Path: "/pending", Tags: tags}, whoami,
		rbac.SignedIn(), auth.AllowWhileRestricted())
	httpx.Register(api, huma.Operation{OperationID: "pendingRead", Method: http.MethodGet, Path: "/pending-read", Tags: tags}, whoami,
		rbac.Requires(read), auth.AllowWhileRestricted())
	httpx.Register(api, huma.Operation{OperationID: "sensitive", Method: http.MethodGet, Path: "/sensitive", Tags: tags}, whoami,
		rbac.SignedIn(), auth.RecentMFA(5*time.Minute))
	httpx.Register(api, huma.Operation{OperationID: "pass", Method: http.MethodPost, Path: "/pass", Tags: tags},
		func(ctx context.Context, _ *struct{}) (*httpx.One[startOutput], error) {
			var out startOutput
			err := db.InTx(ctx, h.db, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				s, err := h.sessions.PassMFA(ctx, tx, "test")
				out.Token = s.Token
				return err
			})
			if err != nil {
				return nil, err
			}
			return httpx.OneOf(out), nil
		}, rbac.SignedIn(), auth.AllowWhileRestricted())
	httpx.Register(api, huma.Operation{OperationID: "end", Method: http.MethodPost, Path: "/end", Tags: tags},
		func(ctx context.Context, _ *struct{}) (*httpx.NoContent, error) {
			return &httpx.NoContent{}, db.InTx(ctx, h.db, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				return h.sessions.End(ctx, tx)
			})
		}, rbac.SignedIn(), auth.AllowWhileRestricted())
}

// newUser makes a user holding the member role in both realms.
func (h *harness) newUser(t *testing.T) users.User {
	t.Helper()
	var u users.User
	require.NoError(t, db.InTx(t.Context(), h.db, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		if u, err = h.users.Create(ctx, tx, users.NewUser{Email: ids.New().String() + "@example.test"}); err != nil {
			return err
		}
		for name, role := range h.member {
			if err := h.access.Grant(ctx, tx, rbac.System(name), rbac.UserRole{UserID: u.ID, RoleID: role}); err != nil {
				return err
			}
		}
		return nil
	}))
	return u
}

// readerRole is a role of tenant carrying read, made once per test.
func (h *harness) readerRole(t *testing.T) rbac.Role {
	t.Helper()
	var role rbac.Role
	require.NoError(t, db.InTx(t.Context(), h.db, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		role, err = h.access.CreateRole(ctx, tx, rbac.System("tenant"), rbac.NewRole{Code: "reader" + ids.New().String()[24:], Name: "Reader", Permissions: []rbac.Code{read}})
		return err
	}))
	return role
}

func (h *harness) change(t *testing.T, fn func(ctx context.Context, tx db.Tx[db.Plain]) error) {
	t.Helper()
	require.NoError(t, db.InTx(t.Context(), h.db, fn))
}

type req struct {
	method, host, path string
	cookie             *http.Cookie
	bearer             string
	body               string
}

func (h *harness) do(t *testing.T, r req) *httptest.ResponseRecorder {
	t.Helper()
	if r.method == "" {
		r.method = http.MethodGet
	}
	hr := httptest.NewRequestWithContext(t.Context(), r.method, r.path, strings.NewReader(r.body))
	if r.host != "" {
		hr.Host = r.host
	}
	if r.body != "" {
		hr.Header.Set("Content-Type", "application/json")
	}
	if r.cookie != nil {
		hr.AddCookie(r.cookie)
	}
	if r.bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, hr)
	return rec
}

// signIn starts a browser session for u on host and returns its cookie.
func (h *harness) signIn(t *testing.T, host string, u users.User, prior *http.Cookie) *http.Cookie {
	t.Helper()
	rec := h.do(t, req{method: http.MethodPost, host: host, path: "/api/start", body: `{"user":"` + u.ID.String() + `"}`, cookie: prior})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	for _, c := range rec.Result().Cookies() {
		if c.Value != "" {
			return c
		}
	}
	t.Fatal("no session cookie set")
	return nil
}

func (h *harness) bearer(t *testing.T, host string, u users.User) string {
	t.Helper()
	rec := h.do(t, req{method: http.MethodPost, host: host, path: "/api/start", body: `{"user":"` + u.ID.String() + `","bearer":true}`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var out httpx.OneBody[startOutput]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	return out.Data.Token
}

func code(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	return p.Code
}

func TestStart_RotatesThePresentedSessionAndAudits(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		h := newHarness(t, e)
		u := h.newUser(t)
		first := h.signIn(t, "", u, nil)
		require.Equal(t, http.StatusOK, h.do(t, req{path: "/api/who", cookie: first}).Code)

		second := h.signIn(t, "", u, first)

		assert.NotEqual(t, first.Value, second.Value)
		assert.Equal(t, http.StatusUnauthorized, h.do(t, req{path: "/api/who", cookie: first}).Code, "the presented session is gone")
		assert.Equal(t, http.StatusOK, h.do(t, req{path: "/api/who", cookie: second}).Code)
		assert.True(t, second.HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, second.SameSite)
		assert.Equal(t, "/", second.Path)
		assert.Empty(t, second.Domain)
		var starts int
		require.NoError(t, e.DB().SQL().QueryRowContext(t.Context(), db.Rebind(e.Dialect(),
			"SELECT count(*) FROM audit_log WHERE action = 'session.start' AND actor_id = ?"), u.ID).Scan(&starts))
		assert.Equal(t, 2, starts)
	})
}

func TestResolve_IdleAndAbsoluteExpiry(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		h := newHarness(t, e)
		cookie := h.signIn(t, "", h.newUser(t), nil)
		for i := range 6 {
			h.clock.advance(110 * time.Minute)
			assert.Equal(t, http.StatusOK, h.do(t, req{path: "/api/who", cookie: cookie}).Code,
				"each request within the idle window extends it (%d)", i)
		}
		h.clock.advance(110 * time.Minute)
		rec := h.do(t, req{path: "/api/who", cookie: cookie})
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "past the absolute expiry however active")
		assert.Equal(t, auth.CodeSessionExpired, code(t, rec))

		idle := h.signIn(t, "", h.newUser(t), nil)
		h.clock.advance(2*time.Hour + time.Second)
		rec = h.do(t, req{path: "/api/who", cookie: idle})
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "idle past two hours")
		assert.Equal(t, auth.CodeSessionExpired, code(t, rec))
		assert.Contains(t, rec.Header().Get("Set-Cookie"), "Max-Age=0", "the stale cookie is cleared")
	})
}

// A session belongs to one realm: its cookie is not read on another realm's host, and its token is
// refused there under that realm's cookie name or as a bearer. Tokens travel only where their kind does.
func TestCredentials_StayInTheirRealmAndTransport(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		h := newHarness(t, e)
		u := h.newUser(t)
		tenant := h.signIn(t, "", u, nil)
		bearer := h.bearer(t, "", u)
		tests := []struct {
			name string
			r    req
			want int
		}{
			{"tenant cookie on tenant", req{cookie: tenant}, http.StatusOK},
			{"tenant cookie on the ops host", req{host: opsHost, cookie: tenant}, http.StatusUnauthorized},
			{"tenant token under the ops cookie name", req{host: opsHost, cookie: &http.Cookie{Name: "ops", Value: tenant.Value, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}}, http.StatusUnauthorized},
			{"tenant bearer on the ops host", req{host: opsHost, bearer: bearer}, http.StatusUnauthorized},
			{"bearer token as a bearer", req{bearer: bearer}, http.StatusOK},
			{"bearer token in a cookie", req{cookie: &http.Cookie{Name: "session", Value: bearer, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}}, http.StatusUnauthorized},
			{"browser token as a bearer", req{bearer: tenant.Value}, http.StatusUnauthorized},
			{"token in the query string", req{path: "/api/who?access_token=" + bearer}, http.StatusUnauthorized},
			{"malformed bearer", req{bearer: "not-a-token"}, http.StatusUnauthorized},
		}
		for _, tt := range tests {
			r := tt.r
			if r.path == "" {
				r.path = "/api/who"
			}
			assert.Equal(t, tt.want, h.do(t, r).Code, tt.name)
		}
	})
}

func TestRevokeUser_EndsEverySessionAtOnce(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		h := newHarness(t, e)
		u, other := h.newUser(t), h.newUser(t)
		a, b, kept := h.signIn(t, "", u, nil), h.bearer(t, "", u), h.signIn(t, "", other, nil)
		require.Equal(t, http.StatusOK, h.do(t, req{path: "/api/who", cookie: a}).Code, "cached principal")

		require.NoError(t, db.InTx(t.Context(), h.db, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			return h.sessions.RevokeUser(ctx, tx, u.ID)
		}))

		rec := h.do(t, req{path: "/api/who", cookie: a})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, auth.CodeSessionExpired, code(t, rec))
		assert.Equal(t, http.StatusUnauthorized, h.do(t, req{path: "/api/who", bearer: b}).Code)
		assert.Equal(t, http.StatusOK, h.do(t, req{path: "/api/who", cookie: kept}).Code)
	})
}

// In a realm that requires MFA a new session is restricted: it reaches only operations marked
// AllowWhileRestricted until it passes, and passing rotates it.
func TestRestrictedSession_OnlyReachesAllowedOperationsUntilMFAPasses(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		h := newHarness(t, e)
		u := h.newUser(t)
		h.change(t, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			role, err := h.access.Setup(ctx, tx, "ops", []rbac.Builtin{{Code: "reader" + ids.New().String()[24:], Name: "Reader", Permissions: []rbac.Code{read}}})
			if err != nil {
				return err
			}
			return h.access.Grant(ctx, tx, rbac.System("ops"), rbac.UserRole{UserID: u.ID, RoleID: role[0].ID})
		})
		pending := h.signIn(t, opsHost, u, nil)

		rec := h.do(t, req{host: opsHost, path: "/api/who", cookie: pending})
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Equal(t, auth.CodeMFARequired, code(t, rec))
		assert.Equal(t, http.StatusOK, h.do(t, req{host: opsHost, path: "/api/pending", cookie: pending}).Code)
		assert.Equal(t, http.StatusForbidden, h.do(t, req{host: opsHost, path: "/api/pending-read", cookie: pending}).Code,
			"a pending session carries no grants, even where it is let through")

		expiring := h.signIn(t, opsHost, u, nil)
		h.clock.advance(auth.PendingFor + time.Second)
		assert.Equal(t, http.StatusUnauthorized, h.do(t, req{host: opsHost, path: "/api/pending", cookie: expiring}).Code, "a pending session lives ten minutes")
		pending = h.signIn(t, opsHost, u, nil)

		pass := h.do(t, req{method: http.MethodPost, host: opsHost, path: "/api/pass", cookie: pending})
		require.Equal(t, http.StatusOK, pass.Code, pass.Body.String())
		passed := pass.Result().Cookies()[0]

		assert.NotEqual(t, pending.Value, passed.Value)
		assert.Equal(t, http.StatusUnauthorized, h.do(t, req{host: opsHost, path: "/api/pending", cookie: pending}).Code, "the restricted session is gone")
		assert.Equal(t, http.StatusOK, h.do(t, req{host: opsHost, path: "/api/who", cookie: passed}).Code)
		assert.Equal(t, http.StatusOK, h.do(t, req{host: opsHost, path: "/api/pending-read", cookie: passed}).Code, "passing restores the grants")
		assert.Equal(t, http.StatusOK, h.do(t, req{host: opsHost, path: "/api/sensitive", cookie: passed}).Code)

		h.clock.advance(6 * time.Minute)
		rec = h.do(t, req{host: opsHost, path: "/api/sensitive", cookie: passed})
		assert.Equal(t, http.StatusForbidden, rec.Code, "the step-up is older than the operation allows")
		assert.Equal(t, auth.CodeStepUpRequired, code(t, rec))
	})
}

// An access change moves the user's access version in its transaction. The next request on any
// replica sees it with the session row: a browser session rotates (new cookie, the old one stops
// working) and the principal is reloaded whatever is cached; a bearer keeps its token. Taking the last
// role ends the user's sessions in that realm.
func TestAccessChanges_RotateAndReloadAtOnceOnEveryReplica(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		h, other := newHarness(t, e), newHarness(t, e)
		u := h.newUser(t)
		cookie, bearer := h.signIn(t, "", u, nil), h.bearer(t, "", u)
		require.Equal(t, http.StatusForbidden, h.do(t, req{path: "/api/read", cookie: cookie}).Code)
		require.Equal(t, http.StatusForbidden, other.do(t, req{path: "/api/read", bearer: bearer}).Code, "cached on the other replica")
		grant := rbac.UserRole{UserID: u.ID, RoleID: h.readerRole(t).ID}

		h.change(t, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			return h.access.Grant(ctx, tx, rbac.System("tenant"), grant)
		})

		rec := h.do(t, req{path: "/api/read", cookie: cookie})
		assert.Equal(t, http.StatusOK, rec.Code, "the grant applies on the next request")
		rotated := rec.Result().Cookies()
		require.Len(t, rotated, 1, "the session rotated")
		assert.NotEqual(t, cookie.Value, rotated[0].Value)
		assert.Equal(t, http.StatusUnauthorized, h.do(t, req{path: "/api/who", cookie: cookie}).Code, "the old token is dead")
		cookie = rotated[0]
		assert.Equal(t, http.StatusOK, other.do(t, req{path: "/api/read", bearer: bearer}).Code, "the other replica's cache is bypassed")

		h.change(t, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			return h.access.Revoke(ctx, tx, rbac.System("tenant"), grant)
		})
		assert.Equal(t, http.StatusForbidden, other.do(t, req{path: "/api/read", bearer: bearer}).Code, "revocation reaches every replica at once")
		rec = h.do(t, req{path: "/api/read", cookie: cookie})
		assert.Equal(t, http.StatusForbidden, rec.Code)

		cookie = rec.Result().Cookies()[0]
		h.change(t, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			return h.access.Revoke(ctx, tx, rbac.System("tenant"), rbac.UserRole{UserID: u.ID, RoleID: h.member["tenant"]})
		})
		assert.Equal(t, http.StatusUnauthorized, h.do(t, req{path: "/api/who", cookie: cookie}).Code, "the last role taken ends the session")
		assert.Equal(t, http.StatusUnauthorized, other.do(t, req{path: "/api/who", bearer: bearer}).Code)
	})
}

// Only a user holding a role in the realm can start a session there.
func TestStart_RefusesAUserWithoutARoleInTheRealm(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		h := newHarness(t, e)
		var stranger users.User
		h.change(t, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			var err error
			stranger, err = h.users.Create(ctx, tx, users.NewUser{Email: ids.New().String() + "@example.test"})
			return err
		})
		rec := h.do(t, req{method: http.MethodPost, path: "/api/start", body: `{"user":"` + stranger.ID.String() + `"}`})
		assert.Equal(t, http.StatusInternalServerError, rec.Code, "the harness maps nothing; apps answer ErrNoAccess like bad credentials")
		assert.Empty(t, rec.Result().Cookies())
	})
}

// A device token resolves through the bearer path to the device's principal, in its own realm only,
// and never from a cookie.
func TestResolve_DeviceTokens(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		h := newHarness(t, e)
		var token string
		require.NoError(t, db.InTx(t.Context(), h.db, func(ctx context.Context, tx db.Tx[db.Plain]) error {
			code, err := h.devices.NewPairingCode(ctx, tx, rbac.System("tenant"), "tenant", "Till 1", "till")
			if err != nil {
				return err
			}
			token, _, err = h.devices.Pair(ctx, tx, "tenant", code)
			return err
		}))

		assert.Equal(t, http.StatusOK, h.do(t, req{path: "/api/read", bearer: token}).Code)
		assert.Equal(t, http.StatusUnauthorized, h.do(t, req{host: opsHost, path: "/api/read", bearer: token}).Code)
		assert.Equal(t, http.StatusUnauthorized, h.do(t, req{path: "/api/read", cookie: &http.Cookie{Name: "session", Value: token, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}}).Code)
		rec := h.do(t, req{path: "/api/sensitive", bearer: token})
		assert.Equal(t, auth.CodeStepUpRequired, code(t, rec), "a device has no second factor to step up with")
	})
}

func TestEnd_DeletesTheSessionAndClearsTheCookie(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		h := newHarness(t, e)
		cookie := h.signIn(t, "", h.newUser(t), nil)

		rec := h.do(t, req{method: http.MethodPost, path: "/api/end", cookie: cookie})

		require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Header().Get("Set-Cookie"), "Max-Age=0")
		assert.Equal(t, http.StatusUnauthorized, h.do(t, req{path: "/api/who", cookie: cookie}).Code)
	})
}

// In production a sign-in sets a __Host- cookie that is Secure, HttpOnly, Lax, on / and without a Domain.
func TestStart_ProductionCookieHeader(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		h := newHarnessWith(t, e, true)
		u := h.newUser(t)
		rec := h.do(t, req{method: http.MethodPost, path: "/api/start", body: `{"user":"` + u.ID.String() + `"}`})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		header := rec.Header().Get("Set-Cookie")
		for _, want := range []string{"__Host-session=", "; Path=/", "; HttpOnly", "; Secure", "; SameSite=Lax"} {
			assert.Contains(t, header, want)
		}
		assert.NotContains(t, header, "Domain=")
	})
}

func FuzzHashSecret(f *testing.F) {
	raw, _ := auth.NewSecret()
	for _, seed := range []string{raw, "", "a", strings.Repeat("A", auth.SecretLen), raw[:auth.SecretLen-1] + "=", raw + "x", "Bearer " + raw} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		hash, err := auth.HashSecret(s)
		if err != nil {
			return
		}
		assert.Len(t, hash, 32)
		assert.Len(t, s, auth.SecretLen)
	})
}

// Every change to what a user may do moves their access version in the change's transaction.
func TestAccessVersion_MovesOnEveryAccessChange(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		h := newHarness(t, e)
		u := h.newUser(t)
		role := h.readerRole(t)
		hasher, err := password.NewHasher(password.Params{Memory: 64, Time: 1, Threads: 1}, 1)
		require.NoError(t, err)
		rec := audit.New(audit.Options{})
		passwords := password.NewService(hasher, auth.NewFailures(ratelimit.DBStoreOf(e.DB())), password.DefaultThrottle, rec)
		system := rbac.System("tenant")
		changes := []struct {
			name string
			fn   func(ctx context.Context, tx db.Transaction) error
		}{
			{"grant", func(ctx context.Context, tx db.Transaction) error {
				return h.access.Grant(ctx, tx, system, rbac.UserRole{UserID: u.ID, RoleID: role.ID})
			}},
			{"role permissions", func(ctx context.Context, tx db.Transaction) error {
				_, err := h.access.SetRolePermissions(ctx, tx, system, role.ID, role.Version, nil)
				return err
			}},
			{"role deleted", func(ctx context.Context, tx db.Transaction) error {
				return h.access.DeleteRole(ctx, tx, system, role.ID, role.Version+1)
			}},
			{"status", func(ctx context.Context, tx db.Transaction) error {
				_, err := h.users.SetStatus(ctx, tx, system, u.ID, u.Version, users.Disabled)
				return err
			}},
			{"password", func(ctx context.Context, tx db.Transaction) error {
				hashed, err := passwords.Prepare(ctx, "violet-otter-harbour", password.Policy{})
				if err != nil {
					return err
				}
				return passwords.Set(ctx, tx, u.ID, hashed)
			}},
		}
		for _, c := range changes {
			var before, after int64
			h.change(t, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				before, err = users.AccessVersion(ctx, tx, u.ID)
				return err
			})
			h.change(t, func(ctx context.Context, tx db.Tx[db.Plain]) error { return c.fn(ctx, tx) })
			h.change(t, func(ctx context.Context, tx db.Tx[db.Plain]) error {
				after, err = users.AccessVersion(ctx, tx, u.ID)
				return err
			})
			assert.Greater(t, after, before, c.name)
		}
	})
}

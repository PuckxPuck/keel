//go:build !noapikeys

package app_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/apikeys"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/ratelimit"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/webhook"
)

const apiHost = "api.example.test"

var leakSecret = "whsec_" + base64.StdEncoding.EncodeToString([]byte("keel-test-leak-report-key-32-byte"))

// publicManaged is public on the api realm but needs a permission no key may hold.
func publicManaged(api huma.API) {
	httpx.Register(api, huma.Operation{OperationID: "testManaged", Method: http.MethodGet, Path: "/test/managed", Tags: []string{"test"}},
		func(context.Context, *struct{}) (*httpx.One[map[string]string], error) {
			return httpx.OneOf(map[string]string{"ok": "yes"}), nil
		}, rbac.Requires(app.PermAPIKeysManage), ratelimit.Class(ratelimit.ClassAPIRead), httpx.Public("2026-10-22"))
}

// request sends to host; send cannot, since a Host header does not set the request's host.
func request(t *testing.T, h http.Handler, method, host, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	r.Host = host
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestAPIRealm_ServesOnlyPublicOperationsToKeys(t *testing.T) {
	h := build(t, []string{"APP_REALM_API_HOSTS=" + apiHost}, publicManaged).Handler
	get := func(host, path string, headers map[string]string) *httptest.ResponseRecorder {
		return request(t, h, http.MethodGet, host, path, "", headers)
	}

	assert.Equal(t, http.StatusOK, get(apiHost, "/v1/ping", nil).Code)
	assert.Equal(t, http.StatusNotFound, get(apiHost, "/v1/devices", nil).Code, "not marked public")
	assert.Equal(t, http.StatusNotFound, get(apiHost, "/api/v1/ping", nil).Code, "the tenant realm's paths stay on its hosts")
	assert.Equal(t, http.StatusOK, get("app.example.test", "/api/v1/ping", nil).Code)
	assert.Equal(t, http.StatusUnauthorized, get(apiHost, "/v1/me", map[string]string{"Cookie": "session=" + ids.New().String()}).Code, "cookies are not credentials here")
	bad := get(apiHost, "/v1/me", map[string]string{"Authorization": "Bearer app_test_nonsense"})
	assert.Equal(t, http.StatusUnauthorized, bad.Code)
	assert.Contains(t, bad.Body.String(), `"code":"invalid_api_key"`)

	crossSite := request(t, h, http.MethodPost, apiHost, "/v1/ping", "", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"})
	assert.Equal(t, http.StatusMethodNotAllowed, crossSite.Code, "no CSRF check without ambient credentials")

	spec := get(apiHost, "/openapi.json", nil)
	require.Equal(t, http.StatusOK, spec.Code)
	var doc struct {
		Paths map[string]map[string]struct {
			Security []map[string][]string `json:"security"`
		} `json:"paths"`
		Components struct {
			SecuritySchemes map[string]struct {
				Type   string `json:"type"`
				Scheme string `json:"scheme"`
			} `json:"securitySchemes"`
		} `json:"components"`
	}
	require.NoError(t, json.Unmarshal(spec.Body.Bytes(), &doc))
	paths := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		paths = append(paths, p)
	}
	assert.Subset(t, paths, []string{"/v1/ping", "/v1/me", "/v1/test/managed"}, "modules add their own public operations")
	assert.NotContains(t, paths, "/v1/devices")
	assert.Equal(t, "bearer", doc.Components.SecuritySchemes[apikeys.SecurityScheme].Scheme)
	assert.Empty(t, doc.Paths["/v1/ping"]["get"].Security, "public")
	assert.Equal(t, []map[string][]string{{apikeys.SecurityScheme: {}}}, doc.Paths["/v1/me"]["get"].Security)
}

func TestAPIRealm_RefusesADeprecationThatHasNotStarted(t *testing.T) {
	cfg, err := app.LoadConfig([]string{"APP_ENV=test", signingKeys, "APP_REALM_API_HOSTS=" + apiHost})
	require.NoError(t, err)
	from := clock.Wall(t.Context()).Now().AddDate(0, 1, 0)
	_, err = app.Build(t.Context(), cfg, app.Deps{}, func(api huma.API) {
		httpx.Register(api, huma.Operation{OperationID: "testOld", Method: http.MethodGet, Path: "/test/old", Tags: []string{"test"}},
			func(context.Context, *struct{}) (*httpx.NoContent, error) { return &httpx.NoContent{}, nil },
			rbac.Public(), ratelimit.Class(ratelimit.ClassAPIRead), httpx.Public("2026-10-22", httpx.Sunset(from, from.AddDate(1, 0, 0))))
	})
	require.ErrorContains(t, err, "has not come")
}

func TestAPIRealm_KeysLimitsRevocationAndLeaks(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		environ := []string{
			"APP_ENV=test", "APP_PUBLIC_URL=http://localhost:8080", signingKeys,
			"APP_REALM_API_HOSTS=" + apiHost, "APP_RATE_API_KEY=3/1m", "APP_APIKEY_LEAK_SECRETS=" + leakSecret,
		}
		cfg, err := app.LoadConfig(environ)
		require.NoError(t, err)
		built, err := app.Build(t.Context(), cfg, app.Deps{DB: e.DB(), Notifier: &links{}}, publicManaged)
		require.NoError(t, err)
		_, err = app.Setup(t.Context(), app.Deps{DB: e.DB()}, audit.New(audit.Options{}))
		require.NoError(t, err)
		h := built.Handler
		create := func() (string, apikeys.Key) {
			plain, k, err := app.CreateAPIKey(t.Context(), cfg, app.Deps{DB: e.DB()}, "", apikeys.NewKey{Name: "Plugin"})
			require.NoError(t, err)
			return plain, k
		}
		call := func(path, key string) *httptest.ResponseRecorder {
			return request(t, h, http.MethodGet, apiHost, path, "", map[string]string{"Authorization": "Bearer " + key})
		}

		key, _ := create()
		me := call("/v1/me", key)
		require.Equal(t, http.StatusOK, me.Code, me.Body.String())
		assert.Equal(t, "apikey", data(t, me)["kind"])
		assert.Equal(t, http.StatusForbidden, call("/v1/test/managed", key).Code, "a key without the permission")

		allowed := call("/v1/ping", key)
		assert.Equal(t, http.StatusOK, allowed.Code)
		assert.Contains(t, strings.Join(allowed.Header().Values("RateLimit-Policy"), ","), `"api-key";q=3`, "every budget that can stop the key, on success too")
		limited := call("/v1/ping", key)
		assert.Equal(t, http.StatusTooManyRequests, limited.Code, "the fourth request of a 3/1m key")
		assert.Contains(t, limited.Header().Get("RateLimit-Policy"), `"api-key"`)
		other, _ := create()
		assert.Equal(t, http.StatusOK, call("/v1/me", other).Code, "each key has its own budget")

		body := `[{"token":"` + other + `","type":"keel_api_key","url":"https://example.test/leak"},{"token":"not-ours","type":"x"}]`
		id, now := "msg_"+ids.New().String(), clock.Wall(t.Context()).Now()
		sig, err := webhook.Sign(leakSecret, id, now, []byte(body))
		require.NoError(t, err)
		report := send(t, h, http.MethodPost, "/api/v1/webhooks/api-key-leaks", body, map[string]string{
			webhook.HeaderID: id, webhook.HeaderTimestamp: strconv.FormatInt(now.Unix(), 10), webhook.HeaderSignature: sig,
		})
		require.Equal(t, http.StatusOK, report.Code, report.Body.String())
		assert.Contains(t, report.Body.String(), `"label":"true_positive"`)
		assert.Contains(t, report.Body.String(), `"label":"false_positive"`)
		assert.Equal(t, http.StatusUnauthorized, call("/v1/me", other).Code, "a leaked key stops at once")

		unsigned := send(t, h, http.MethodPost, "/api/v1/webhooks/api-key-leaks", body, nil)
		assert.Equal(t, http.StatusUnauthorized, unsigned.Code)
	})
}

// admins is an AdminNotifier that queues as many deliveries as reach says.
type admins struct {
	mu    sync.Mutex
	reach int
	kinds []string
}

func (a *admins) NotifyAdmins(_ context.Context, _ db.Transaction, n app.AdminNotice) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.kinds = append(a.kinds, n.Kind)
	return a.reach, nil
}

func (a *admins) told() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.kinds) > 0
}

// An expiry reminder counts as sent only once a delivery was queued: with no one to tell, the next run
// tries again.
func TestAPIKeys_ReminderIsSentOnlyWhenDelivered(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		for _, reach := range []int{0, 1} {
			d := e.Isolated(t)
			cfg, err := app.LoadConfig([]string{"APP_ENV=test", signingKeys, "APP_REALM_API_HOSTS=" + apiHost, "APP_JOBS_POLL=50ms", "APP_JOBS_SHUTDOWN_GRACE=0s"})
			require.NoError(t, err)
			notifier := &admins{reach: reach}
			built, err := app.Build(t.Context(), cfg, app.Deps{DB: d, Notifier: &links{}, AdminNotifier: notifier})
			require.NoError(t, err)
			expires := clock.Wall(t.Context()).Now().Add(48 * time.Hour)
			_, k, err := app.CreateAPIKey(t.Context(), cfg, app.Deps{DB: d}, "", apikeys.NewKey{Name: "Plugin", ExpiresAt: &expires})
			require.NoError(t, err)

			ran := func() bool {
				var n int
				require.NoError(t, d.SQL().QueryRowContext(t.Context(), "SELECT count(*) FROM jobs WHERE kind = 'apikeys.expiry_reminder' AND status = 'done'").Scan(&n))
				return notifier.told() && n == 1
			}
			runMaintenance(t, built.Queue, "apikeys.expiry_reminders", ran)
			var reminded bool
			require.NoError(t, d.SQL().QueryRowContext(t.Context(),
				db.Rebind(d.Dialect(), "SELECT expiry_reminded_at IS NOT NULL FROM api_keys WHERE id = ?"), k.ID).Scan(&reminded))
			assert.Equal(t, reach > 0, reminded, "reach %d", reach)
		}
	})
}

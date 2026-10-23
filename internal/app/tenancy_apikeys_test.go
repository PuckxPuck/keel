//go:build !notenancy && !noapikeys

package app_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/tenancy"
	"github.com/PuckxPuck/keel/internal/kit/users"
	"github.com/PuckxPuck/keel/internal/kit/webhook"
)

type tenantKey struct{ id, key string }

func (a *tenancyApp) key(host string, cookie *http.Cookie) tenantKey {
	a.t.Helper()
	rec := a.call(http.MethodPost, host, "/api/v1/api-keys", `{"name":"plugin","scopes":[]}`, cookie)
	require.Equal(a.t, http.StatusCreated, rec.Code, rec.Body.String())
	return tenantKey{id: data(a.t, rec)["apiKey"].(map[string]any)["id"].(string), key: data(a.t, rec)["key"].(string)}
}

func (a *tenancyApp) asKey(key string) int {
	a.t.Helper()
	r := httptest.NewRequestWithContext(a.t.Context(), http.MethodGet, "/v1/me", nil)
	r.Host = apiHost
	if key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, r)
	return rec.Code
}

// Keys belong to a tenant: another tenant cannot see or revoke them, each checks out in its own tenant,
// it outlives its creator's membership, a leak revokes it in its tenant, and no tenant may take the api
// realm's host as a custom domain.
func TestTenancy_APIKeysStayInTheirTenant(t *testing.T) {
	a := newTenancyApp(t, "APP_REALM_API_HOSTS="+apiHost, "APP_APIKEY_LEAK_SECRETS="+leakSecret, "APP_TENANCY_CUSTOM_DOMAINS=true")
	ann, bob, carol := a.person("ann"), a.person("bob"), a.person("carol")
	acme := a.tenant("acme", ann)
	a.tenant("globex", bob)
	require.NoError(t, app.GrantRole(t.Context(), a.deps, audit.New(audit.Options{}), app.RealmTenant, "admin", carol, "acme"))
	annIn, bobIn := a.cookie(acmeHost, ann), a.cookie(globexHost, bob)
	acmeKey, globexKey, carolKey := a.key(acmeHost, annIn), a.key(globexHost, bobIn), a.key(acmeHost, a.cookie(acmeHost, carol))

	assert.Equal(t, http.StatusNotFound, a.call(http.MethodDelete, acmeHost, "/api/v1/api-keys/"+globexKey.id, "", annIn).Code)
	keys := listed(t, a.call(http.MethodGet, globexHost, "/api/v1/api-keys", "", bobIn))
	require.Len(t, keys, 1)
	assert.Nil(t, keys[0]["revokedAt"], "globex's key was not revoked")
	assert.Len(t, listed(t, a.call(http.MethodGet, acmeHost, "/api/v1/api-keys", "", annIn)), 2)
	assert.Equal(t, http.StatusUnauthorized, a.asKey(""))
	for _, k := range []tenantKey{acmeKey, globexKey} {
		assert.Equal(t, http.StatusOK, a.asKey(k.key), "a key is checked in its own tenant")
	}

	require.NoError(t, db.InOperatorTx(t.Context(), a.deps.Operator, func(ctx context.Context, tx db.Tx[db.Operator]) error {
		u, err := users.ByEmail(ctx, tx, carol)
		if err != nil {
			return err
		}
		return tenancy.RemoveMember(ctx, tx, acme.ID, u.ID)
	}))
	assert.Equal(t, http.StatusOK, a.asKey(carolKey.key), "the key is acme's, not carol's")

	body := `[{"token":"` + acmeKey.key + `","type":"keel_api_key"}]`
	id, at := "msg_"+ids.New().String(), clock.Wall(t.Context()).Now()
	sig, err := webhook.Sign(leakSecret, id, at, []byte(body))
	require.NoError(t, err)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/webhooks/api-key-leaks", strings.NewReader(body))
	r.Host = sharedHost
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(webhook.HeaderID, id)
	r.Header.Set(webhook.HeaderTimestamp, strconv.FormatInt(at.Unix(), 10))
	r.Header.Set(webhook.HeaderSignature, sig)
	report := httptest.NewRecorder()
	a.h.ServeHTTP(report, r)
	require.Equal(t, http.StatusOK, report.Code, report.Body.String())
	assert.Contains(t, a.trail(acme), "apikey.leaked")
	assert.Equal(t, http.StatusUnauthorized, a.asKey(acmeKey.key))

	_, err = app.CreateTenant(t.Context(), a.cfg, a.deps, tenancy.NewTenant{Slug: "taker", Name: "taker", Domains: []string{apiHost}}, ann)
	require.ErrorIs(t, err, tenancy.ErrInvalid)
}

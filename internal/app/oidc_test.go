//go:build !nooidc

package app_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/auth/oidc/oidctest"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

func TestOIDC_CallbackSignsInAndReturns(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		is := oidctest.New(t)
		a := newAuthApp(t, e, "APP_OIDC_ISSUER="+is.URL, "APP_OIDC_CLIENT_ID=keel-client", "APP_OIDC_EMAIL_TRUSTED=true")
		email := a.invite(goodPassword)

		start := a.call(http.MethodGet, "/api/v1/auth/oidc/start?returnTo=/after", "", nil, "")
		require.Equal(t, http.StatusSeeOther, start.Code, start.Body.String())
		var binding *http.Cookie
		for _, c := range start.Result().Cookies() {
			if c.Name == "oidc_state" {
				binding = c
			}
		}
		require.NotNil(t, binding)
		state, code := is.Authorise(t, start.Header().Get("Location"), ids.New().String(), email, true, nil)
		callback := "/api/v1/auth/oidc/callback?" + url.Values{"state": {state}, "code": {code}}.Encode()

		assert.Equal(t, http.StatusBadRequest, a.call(http.MethodGet, callback, "", nil, "").Code, "without the browser's binding cookie")
		done := a.call(http.MethodGet, callback, "", binding, "")
		require.Equal(t, http.StatusSeeOther, done.Code, done.Body.String())
		assert.Equal(t, "/after", done.Header().Get("Location"))
		assert.Equal(t, http.StatusOK, a.call(http.MethodGet, "/api/v1/me", "", sessionCookie(t, done), "").Code)
		assert.Equal(t, http.StatusBadRequest, a.call(http.MethodGet, callback, "", binding, "").Code, "a replayed callback")
	})
}

func TestOIDC_DiscoveryHoldsNoConnectionAndAFailureIsRemembered(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		var asked atomic.Int32
		release := make(chan struct{})
		down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			asked.Add(1)
			<-release
			http.Error(w, "down", http.StatusBadGateway)
		}))
		t.Cleanup(down.Close)
		a := newAuthApp(t, e, "APP_OIDC_ISSUER="+down.URL, "APP_OIDC_CLIENT_ID=keel-client")
		start := func(i int) int {
			return a.call(http.MethodGet, "/api/v1/auth/oidc/start", "", nil, "198.51.100."+strconv.Itoa(i)+":1234").Code
		}

		var wg sync.WaitGroup
		codes := make([]int, 3)
		for i := range codes {
			wg.Go(func() { codes[i] = start(i + 1) })
		}
		require.Eventually(t, func() bool { return asked.Load() > 0 }, 5*time.Second, 10*time.Millisecond)
		time.Sleep(200 * time.Millisecond)
		inUse := e.DB().SQL().Stats().InUse
		close(release)
		wg.Wait()

		assert.Zero(t, inUse, "no connection is held while the provider is asked")
		assert.Equal(t, []int{http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusServiceUnavailable}, codes)
		assert.Equal(t, http.StatusServiceUnavailable, start(9))
		assert.Equal(t, int32(1), asked.Load(), "a failed discovery is not retried at once")
	})
}

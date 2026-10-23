package app_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

// A manager makes pairing codes; a device trades one for a bearer token that resolves to the device;
// the realm's devices list in pages; rotation with no grace kills the old token and revoking kills the
// new one. Code redemption is counted by address before the code is looked up.
func TestDevices_PairListRotateRevoke(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		a := newAuthApp(t, e)
		cookie, _ := a.signIn(a.invite(goodPassword), goodPassword)
		pair := func() (string, string) {
			rec := a.call(http.MethodPost, "/api/v1/devices/pairing-codes", `{"name":"Front till","scope":"till"}`, cookie, "")
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			code, _ := data(t, rec)["code"].(string)
			rec = a.call(http.MethodPost, "/api/v1/devices/pair", `{"code":"`+code+`"}`, nil, "")
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			paired := data(t, rec)
			device, _ := paired["device"].(map[string]any)
			token, _ := paired["token"].(string)
			id, _ := device["id"].(string)
			return id, token
		}
		asDevice := func(token string) int {
			return a.send(http.MethodGet, "/api/v1/me", "", nil, "", map[string]string{"Authorization": "Bearer " + token}).Code
		}
		first, token := pair()
		second, _ := pair()
		me := a.send(http.MethodGet, "/api/v1/me", "", nil, "", map[string]string{"Authorization": "Bearer " + token})
		require.Equal(t, http.StatusOK, me.Code, me.Body.String())
		assert.Equal(t, "device", data(t, me)["kind"])

		var page struct {
			Data  []struct{ ID string }  `json:"data"`
			Links struct{ Next *string } `json:"links"`
		}
		rec := a.call(http.MethodGet, "/api/v1/devices?limit=1&sort=-createdAt", "", cookie, "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
		require.Len(t, page.Data, 1)
		assert.Equal(t, second, page.Data[0].ID, "newest first")
		require.NotNil(t, page.Links.Next)
		rec = a.call(http.MethodGet, *page.Links.Next, "", cookie, "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
		assert.Equal(t, first, page.Data[0].ID)

		rec = a.call(http.MethodPost, "/api/v1/devices/"+first+"/rotate", `{"graceSeconds":0}`, cookie, "")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		rotated, _ := data(t, rec)["token"].(string)
		assert.Equal(t, http.StatusUnauthorized, asDevice(token), "no grace: the old token stops at once")
		assert.Equal(t, http.StatusOK, asDevice(rotated))
		require.Equal(t, http.StatusNoContent, a.call(http.MethodDelete, "/api/v1/devices/"+first, "", cookie, "").Code)
		assert.Equal(t, http.StatusUnauthorized, asDevice(rotated), "revoked")
		assert.Equal(t, http.StatusNotFound, a.call(http.MethodDelete, "/api/v1/devices/"+first, "", cookie, "").Code)

		for range 10 {
			require.Equal(t, http.StatusUnprocessableEntity, a.call(http.MethodPost, "/api/v1/devices/pair", `{"code":"AAAA-AAAA"}`, nil, "198.51.100.7:1000").Code)
		}
		assert.Equal(t, http.StatusTooManyRequests, a.call(http.MethodPost, "/api/v1/devices/pair", `{"code":"AAAA-AAAA"}`, nil, "198.51.100.7:1000").Code)
	})
}

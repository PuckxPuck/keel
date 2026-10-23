//go:build !nopasskey

package app_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/auth/passkey/passkeytest"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
)

func TestPasskeys_SignInListAndRemove(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		a := newAuthApp(t, e, "APP_PASSKEY_RP_ID=localhost", "APP_PASSKEY_ORIGINS=http://localhost:8080")
		cookie, _ := a.signIn(a.invite(goodPassword), goodPassword)
		key := passkeytest.New(t, "localhost", "http://localhost:8080")
		challenge := func(path string, cookie *http.Cookie) (string, []byte) {
			rec := a.call(http.MethodPost, path, "", cookie, "")
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			var body struct {
				Data struct {
					ChallengeID string          `json:"challengeId"`
					Options     json.RawMessage `json:"options"`
				} `json:"data"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			return body.Data.ChallengeID, body.Data.Options
		}
		id, opts := challenge("/api/v1/auth/passkeys/register/begin", cookie)
		reg := a.call(http.MethodPost, "/api/v1/auth/passkeys/register/finish",
			`{"challengeId":"`+id+`","name":"Laptop","credential":`+string(key.Register(t, opts))+`}`, cookie, "")
		require.Equal(t, http.StatusOK, reg.Code, reg.Body.String())
		passkeyID, _ := data(t, reg)["id"].(string)
		signIn := func(count uint32) *httptest.ResponseRecorder {
			id, opts := challenge("/api/v1/auth/passkeys/sign-in/begin", nil)
			return a.call(http.MethodPost, "/api/v1/auth/passkeys/sign-in/finish",
				`{"challengeId":"`+id+`","credential":`+string(key.Assert(t, opts, passkeytest.FlagUP|passkeytest.FlagUV, count))+`}`, nil, "")
		}

		in := signIn(1)
		require.Equal(t, http.StatusOK, in.Code, in.Body.String())
		session := sessionCookie(t, in)
		list := a.call(http.MethodGet, "/api/v1/auth/passkeys", "", session, "")
		require.Equal(t, http.StatusOK, list.Code, list.Body.String())
		assert.Contains(t, list.Body.String(), `"name":"Laptop"`)
		renamed := a.call(http.MethodPatch, "/api/v1/auth/passkeys/"+passkeyID, `{"name":"Desk","version":1}`, session, "")
		require.Equal(t, http.StatusOK, renamed.Code, renamed.Body.String())
		assert.Equal(t, "Desk", data(t, renamed)["name"])

		require.Equal(t, http.StatusNoContent, a.call(http.MethodDelete, "/api/v1/auth/passkeys/"+passkeyID, "", session, "").Code)
		assert.Equal(t, http.StatusUnauthorized, signIn(2).Code, "a removed passkey")
		assert.Equal(t, http.StatusUnauthorized, a.call(http.MethodGet, "/api/v1/me", "", cookie, "").Code, "removing ended the other sessions")
	})
}

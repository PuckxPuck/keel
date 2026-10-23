// Package oidctest is a minimal OpenID provider for tests: discovery advertising ES256 only, its key,
// and a token endpoint that checks PKCE and answers with the ID token claims a test set for the code.
package oidctest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/ids"
)

type Issuer struct {
	URL   string
	key   *ecdsa.PrivateKey
	mu    sync.Mutex
	codes map[string]grant
}

type grant struct {
	challenge string
	claims    map[string]any
}

func New(t testing.TB) *Issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	is := &Issuer{key: key, codes: map[string]grant{}}
	point, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer": is.URL, "authorization_endpoint": is.URL + "/authorize", "token_endpoint": is.URL + "/token",
			"jwks_uri": is.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"ES256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig", "alg": "ES256", "x": b64(point[1:33]), "y": b64(point[33:]),
		}}})
	})
	mux.HandleFunc("POST /token", is.token)
	srv := httptest.NewServer(mux)
	is.URL = srv.URL
	t.Cleanup(srv.Close)
	return is
}

func (is *Issuer) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	is.mu.Lock()
	g, ok := is.codes[r.PostForm.Get("code")]
	delete(is.codes, r.PostForm.Get("code"))
	is.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || b64(sum[:]) != g.challenge {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	writeJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 60, "id_token": is.sign(g.claims)})
}

func (is *Issuer) sign(claims map[string]any) string {
	head, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "k1", "typ": "JWT"})
	body, _ := json.Marshal(claims)
	input := b64(head) + "." + b64(body)
	sum := sha256.Sum256([]byte(input))
	r, s, _ := ecdsa.Sign(rand.Reader, is.key, sum[:])
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + b64(sig)
}

// Authorise plays the browser and the provider's consent: it reads what Start sent and issues a code
// whose ID token carries the claims, adjusted by edit.
func (is *Issuer) Authorise(t testing.TB, authURL, subject, email string, verified bool, edit func(map[string]any)) (state, code string) {
	t.Helper()
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	q := u.Query()
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	now := clock.Wall(t.Context()).Now()
	claims := map[string]any{
		"iss": is.URL, "aud": q.Get("client_id"), "sub": subject, "email": email, "email_verified": verified,
		"nonce": q.Get("nonce"), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	if edit != nil {
		edit(claims)
	}
	code = ids.New().String()
	is.mu.Lock()
	is.codes[code] = grant{challenge: q.Get("code_challenge"), claims: claims}
	is.mu.Unlock()
	return q.Get("state"), code
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

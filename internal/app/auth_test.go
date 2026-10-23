package app_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/pquerna/otp"
	otptotp "github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/internal/app"
	"github.com/PuckxPuck/keel/internal/kit/audit"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/logx"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

// links records what the notifier was handed, and how often.
type links struct {
	mu    sync.Mutex
	sent  map[string]string
	count map[string]int
}

func (l *links) record(kind string, to users.User, token string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sent == nil {
		l.sent, l.count = map[string]string{}, map[string]int{}
	}
	l.sent[kind+":"+to.Email] = token
	l.count[kind+":"+to.Email]++
	return nil
}

func (l *links) get(kind, email string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sent[kind+":"+email]
}

func (l *links) times(kind, email string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count[kind+":"+email]
}

func (l *links) SendReset(_ context.Context, _ db.Transaction, to users.User, token string) error {
	return l.record("reset", to, token)
}

func (l *links) SendVerify(_ context.Context, _ db.Transaction, to users.User, token string) error {
	return l.record("verify", to, token)
}

func (l *links) SendInvite(_ context.Context, _ db.Transaction, to users.User, token string) error {
	return l.record("invite", to, token)
}

type authApp struct {
	t       *testing.T
	e       *testdb.Engine
	cfg     app.Config
	deps    app.Deps
	handler http.Handler
	links   *links
}

func newAuthApp(t *testing.T, e *testdb.Engine, env ...string) *authApp {
	t.Helper()
	environ := append([]string{"APP_ENV=test", "APP_PUBLIC_URL=http://localhost:8080", "APP_PASSWORD_ARGON2=m=64,t=1,p=1", signingKeys}, env...)
	cfg, err := app.LoadConfig(environ)
	require.NoError(t, err)
	a := &authApp{t: t, e: e, cfg: cfg, links: &links{}}
	a.deps = app.Deps{DB: e.DB(), Notifier: a.links}
	built, err := app.Build(t.Context(), cfg, a.deps)
	require.NoError(t, err)
	a.handler = built.Handler
	_, err = app.Setup(t.Context(), app.Deps{DB: e.DB()}, audit.New(audit.Options{}))
	require.NoError(t, err)
	return a
}

// invite creates a user, accepts the invite with a password and makes them an administrator.
func (a *authApp) invite(pass string) string {
	a.t.Helper()
	email := ids.New().String() + "@example.test"
	_, _, err := app.CreateUser(a.t.Context(), a.cfg, a.deps, email, "Ann", false)
	require.NoError(a.t, err)
	token := a.links.get("invite", email)
	require.NotEmpty(a.t, token)
	rec := a.call(http.MethodPost, "/api/v1/auth/invites/accept", `{"token":"`+token+`","password":"`+pass+`"}`, nil, "")
	require.Equal(a.t, http.StatusNoContent, rec.Code, rec.Body.String())
	require.NoError(a.t, app.GrantRole(a.t.Context(), app.Deps{DB: a.e.DB()}, audit.New(audit.Options{}), app.RealmTenant, "admin", email, ""))
	return email
}

func (a *authApp) call(method, path, body string, cookie *http.Cookie, remote string) *httptest.ResponseRecorder {
	a.t.Helper()
	return a.send(method, path, body, cookie, remote, nil)
}

func (a *authApp) send(method, path, body string, cookie *http.Cookie, remote string, headers map[string]string) *httptest.ResponseRecorder {
	a.t.Helper()
	ctx := logx.WithLogger(a.t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := httptest.NewRequestWithContext(ctx, method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if remote != "" {
		r.RemoteAddr = remote
	}
	for k, v := range headers {
		if k == "Host" {
			r.Host = v
			continue
		}
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, r)
	return rec
}

func (a *authApp) signIn(email, pass string) (*http.Cookie, map[string]any) {
	a.t.Helper()
	rec := a.call(http.MethodPost, "/api/v1/auth/sign-in", `{"email":"`+email+`","password":"`+pass+`"}`, nil, "")
	require.Equal(a.t, http.StatusOK, rec.Code, rec.Body.String())
	return sessionCookie(a.t, rec), data(a.t, rec)
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no session cookie in %v", rec.Header())
	return nil
}

func problemDetail(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p))
	return p.Code + ": " + p.Detail
}

func data(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body struct {
		Data map[string]any `json:"data"`
		Code string         `json:"code"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
	if body.Data == nil {
		return map[string]any{"code": body.Code}
	}
	return body.Data
}

const goodPassword = "violet-otter-harbour"

func TestAuth_InviteSignInMeSignOut(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		a := newAuthApp(t, e)
		email := ids.New().String() + "@example.test"
		_, _, err := app.CreateUser(t.Context(), a.cfg, a.deps, email, "Ann", false)
		require.NoError(t, err)
		invite := a.links.get("invite", email)

		weak := a.call(http.MethodPost, "/api/v1/auth/invites/accept", `{"token":"`+invite+`","password":"short-pass"}`, nil, "")
		require.Equal(t, http.StatusUnprocessableEntity, weak.Code, "15 characters when the realm has no second factor")
		assert.Contains(t, weak.Body.String(), `"location":"body.password"`)
		require.Equal(t, http.StatusNoContent, a.call(http.MethodPost, "/api/v1/auth/invites/accept", `{"token":"`+invite+`","password":"`+goodPassword+`"}`, nil, "").Code,
			"the refused attempt did not spend the invite")

		noRole := a.call(http.MethodPost, "/api/v1/auth/sign-in", `{"email":"`+email+`","password":"`+goodPassword+`"}`, nil, "")
		wrong := a.call(http.MethodPost, "/api/v1/auth/sign-in", `{"email":"`+email+`","password":"not-the-password"}`, nil, "")
		unknown := a.call(http.MethodPost, "/api/v1/auth/sign-in", `{"email":"nobody-`+email+`","password":"not-the-password"}`, nil, "")
		assert.Equal(t, http.StatusUnauthorized, wrong.Code)
		assert.Equal(t, "invalid_credentials", data(t, wrong)["code"])
		for name, rec := range map[string]*httptest.ResponseRecorder{"unknown account": unknown, "no role in the realm": noRole} {
			assert.Equal(t, wrong.Code, rec.Code, name)
			assert.Equal(t, problemDetail(t, wrong), problemDetail(t, rec), name)
		}

		require.NoError(t, app.GrantRole(t.Context(), app.Deps{DB: e.DB()}, audit.New(audit.Options{}), app.RealmTenant, "admin", email, ""))
		cookie, signedIn := a.signIn(email, goodPassword)
		assert.Equal(t, "none", signedIn["mfa"])
		assert.Nil(t, signedIn["token"], "browsers get the cookie, not a token")

		me := a.call(http.MethodGet, "/api/v1/me", "", cookie, "")
		require.Equal(t, http.StatusOK, me.Code, me.Body.String())
		got := data(t, me)
		assert.Equal(t, "tenant", got["realm"])
		assert.Equal(t, false, got["mfaRequired"])
		assert.Equal(t, email, got["user"].(map[string]any)["email"])
		assert.NotNil(t, got["user"].(map[string]any)["emailVerifiedAt"], "accepting the invite proved the address")

		require.Equal(t, http.StatusNoContent, a.call(http.MethodPost, "/api/v1/auth/sign-out", "", cookie, "").Code)
		assert.Equal(t, http.StatusUnauthorized, a.call(http.MethodGet, "/api/v1/me", "", cookie, "").Code)
	})
}

// Reset requests answer alike for known and unknown addresses, count by account in the database even
// under a concurrent burst, and hand the link to the notifier in the issuing transaction.
func TestPasswordReset_AnswersAlikeCountsAndRevokesSessions(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		a := newAuthApp(t, e)
		email := a.invite(goodPassword)
		cookie, _ := a.signIn(email, goodPassword)

		unknown := a.call(http.MethodPost, "/api/v1/auth/password/reset-request", `{"email":"nobody-`+email+`"}`, nil, "")
		assert.Equal(t, http.StatusNoContent, unknown.Code)
		assert.Empty(t, a.links.get("reset", "nobody-"+email))

		var wg sync.WaitGroup
		codes := make([]int, 8)
		for i := range codes {
			wg.Go(func() {
				codes[i] = a.call(http.MethodPost, "/api/v1/auth/password/reset-request", `{"email":"`+email+`"}`, nil, "").Code
			})
		}
		wg.Wait()
		for _, c := range codes {
			assert.Equal(t, http.StatusNoContent, c, "throttled or not, the answer is the same")
		}
		assert.Equal(t, 5, a.links.times("reset", email), "five requests an hour per account, however concurrent")
		token := a.links.get("reset", email)
		require.NotEmpty(t, token)

		reset := a.call(http.MethodPost, "/api/v1/auth/password/reset", `{"token":"`+token+`","password":"a-brand-new-passphrase"}`, nil, "")
		require.Equal(t, http.StatusNoContent, reset.Code, reset.Body.String())

		rec := a.call(http.MethodGet, "/api/v1/me", "", cookie, "")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "session_expired", data(t, rec)["code"])
		again := a.call(http.MethodPost, "/api/v1/auth/password/reset", `{"token":"`+token+`","password":"another-new-passphrase"}`, nil, "")
		assert.Equal(t, "invalid_token", data(t, again)["code"], "the link works once")
		a.signIn(email, "a-brand-new-passphrase")
	})
}

// In a realm that requires MFA, sign-in gives a restricted session that sees only that it must pass
// the second factor, and can enrol and confirm an authenticator. Confirming passes MFA, rotates the
// session and ends the user's other sessions.
func TestMFA_RequiredRealmEnrolsAndPasses(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		a := newAuthApp(t, e, "APP_REALM_TENANT_MFA=required", "APP_MFA_KEYS=first-test-key,older-test-key")
		email := a.invite("eight-ch")
		other, _ := a.signIn(email, "eight-ch")
		pending, signedIn := a.signIn(email, "eight-ch")
		require.Equal(t, "pending", signedIn["mfa"], "8 characters suffice with a required second factor")

		me := a.call(http.MethodGet, "/api/v1/me", "", pending, "")
		require.Equal(t, http.StatusOK, me.Code)
		got := data(t, me)
		assert.Equal(t, true, got["mfaRequired"])
		assert.Nil(t, got["user"])
		assert.Empty(t, got["roles"])
		assert.Empty(t, got["permissions"], "no grants before the second factor")

		enrol := a.call(http.MethodPost, "/api/v1/auth/mfa/totp/enrol", "", pending, "")
		require.Equal(t, http.StatusOK, enrol.Code, enrol.Body.String())
		secret, _ := data(t, enrol)["secret"].(string)
		code, err := otptotp.GenerateCodeCustom(secret, clock.Wall(t.Context()).Now(), otptotp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		require.NoError(t, err)

		wrongCode := string(rune('0'+(code[0]-'0'+1)%10)) + code[1:]
		wrong := a.call(http.MethodPost, "/api/v1/auth/mfa/totp/confirm", `{"code":"`+wrongCode+`"}`, pending, "")
		assert.Equal(t, http.StatusUnprocessableEntity, wrong.Code)
		confirm := a.call(http.MethodPost, "/api/v1/auth/mfa/totp/confirm", `{"code":"`+code+`"}`, pending, "")
		require.Equal(t, http.StatusOK, confirm.Code, confirm.Body.String())
		assert.Len(t, data(t, confirm)["recoveryCodes"], 10)
		assert.Equal(t, "passed", data(t, confirm)["mfa"])
		passed := sessionCookie(t, confirm)

		assert.Equal(t, http.StatusUnauthorized, a.call(http.MethodGet, "/api/v1/me", "", pending, "").Code, "the restricted session was rotated away")
		assert.Equal(t, http.StatusUnauthorized, a.call(http.MethodGet, "/api/v1/me", "", other, "").Code, "enabling a factor ends other sessions")
		me = a.call(http.MethodGet, "/api/v1/me", "", passed, "")
		require.Equal(t, http.StatusOK, me.Code)
		assert.Contains(t, data(t, me)["permissions"], string(app.PermAccessManage))
	})
}

// Code attempts are counted before they are checked: a concurrent burst from one address gets five
// checks and 429 for the rest. Ten wrong codes in a row, from any addresses, end every session of the
// user.
func TestMFA_AttemptsAreCountedAndAStreakRevokes(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		a := newAuthApp(t, e, "APP_REALM_TENANT_MFA=required", "APP_MFA_KEYS=first-test-key")
		email := a.invite("eight-ch")
		pending, _ := a.signIn(email, "eight-ch")
		require.Equal(t, http.StatusOK, a.call(http.MethodPost, "/api/v1/auth/mfa/totp/enrol", "", pending, "").Code)
		attempt := func(remote string) int {
			return a.call(http.MethodPost, "/api/v1/auth/mfa/totp/confirm", `{"code":"000000"}`, pending, remote).Code
		}

		codes := make([]int, 8)
		var wg sync.WaitGroup
		for i := range codes {
			wg.Go(func() { codes[i] = attempt("198.51.100.7:1000") })
		}
		wg.Wait()
		count := map[int]int{}
		for _, c := range codes {
			count[c]++
		}
		assert.Equal(t, map[int]int{http.StatusUnprocessableEntity: 5, http.StatusTooManyRequests: 3}, count)
		rec := a.call(http.MethodPost, "/api/v1/auth/mfa/totp/confirm", `{"code":"000000"}`, pending, "198.51.100.7:1000")
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.NotEmpty(t, rec.Header().Get("Retry-After"))

		for i := range 4 {
			require.Equal(t, http.StatusUnprocessableEntity, attempt("203.0.113.9:1000"), i)
		}
		assert.Equal(t, http.StatusOK, a.call(http.MethodGet, "/api/v1/me", "", pending, "").Code, "nine wrong codes in a row")
		assert.Equal(t, http.StatusUnprocessableEntity, attempt("203.0.113.9:1000"))
		assert.Equal(t, http.StatusUnauthorized, a.call(http.MethodGet, "/api/v1/me", "", pending, "").Code, "the tenth revoked every session")
		var events int
		require.NoError(t, e.DB().SQL().QueryRowContext(t.Context(), db.Rebind(e.Dialect(),
			"SELECT count(*) FROM audit_log WHERE action = 'mfa.failure_limit_reached'")).Scan(&events))
		assert.Positive(t, events)
	})
}

func TestEmailVerification_RequestAndConfirm(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		a := newAuthApp(t, e)
		email := a.invite(goodPassword)
		cookie, _ := a.signIn(email, goodPassword)
		require.Equal(t, http.StatusNoContent, a.call(http.MethodPost, "/api/v1/auth/email/verification", "", cookie, "").Code)
		assert.Empty(t, a.links.get("verify", email), "an address already confirmed gets no link")

		_, err := e.DB().SQL().ExecContext(t.Context(), db.Rebind(e.Dialect(), "UPDATE users SET email_verified_at = NULL WHERE email = ?"), email)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, a.call(http.MethodPost, "/api/v1/auth/email/verification", "", cookie, "").Code)
		token := a.links.get("verify", email)
		require.NotEmpty(t, token)
		require.Equal(t, http.StatusNoContent, a.call(http.MethodPost, "/api/v1/auth/email/verify", `{"token":"`+token+`"}`, nil, "").Code)
		me := data(t, a.call(http.MethodGet, "/api/v1/me", "", cookie, ""))
		assert.NotNil(t, me["user"].(map[string]any)["emailVerifiedAt"])
	})
}

// Dev login answers only a loopback client naming a loopback host with no forwarding header, so a
// tunnel or proxy in front of the dev server cannot reach it.
func TestDevLogin_OnlyLocalLoopbackAndUnproxied(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		local := newAuthApp(t, e, "APP_ENV=local", "APP_DEV_LOGIN=true", "APP_PROXY_TRUSTED=127.0.0.2/32")
		email := local.invite(goodPassword)
		body := `{"email":"` + email + `"}`
		devLogin := func(remote string, headers map[string]string) int {
			return local.send(http.MethodPost, "/api/v1/auth/dev-login", body, nil, remote, headers).Code
		}
		host := map[string]string{"Host": "localhost:8080"}

		assert.Equal(t, http.StatusOK, devLogin("127.0.0.1:5000", host))
		assert.Equal(t, http.StatusNotFound, devLogin("203.0.113.9:5000", host), "remote client")
		assert.Equal(t, http.StatusNotFound, devLogin("127.0.0.1:5000", map[string]string{"Host": "abc123.ngrok.app"}), "a tunnel's public host")
		assert.Equal(t, http.StatusNotFound, devLogin("127.0.0.1:5000", map[string]string{"Host": "localhost:8080", "X-Forwarded-For": "203.0.113.9"}), "a tunnel's forwarding header")
		assert.Equal(t, http.StatusNotFound, devLogin("127.0.0.2:5000", map[string]string{"Host": "localhost:8080", "X-Forwarded-For": "127.0.0.1"}), "a trusted proxy, even from loopback")

		off := newAuthApp(t, e, signingKeys)
		assert.Equal(t, http.StatusNotFound, off.send(http.MethodPost, "/api/v1/auth/dev-login", body, nil, "127.0.0.1:5000", host).Code, "off")
		_, err := app.LoadConfig([]string{"APP_ENV=test", "APP_DEV_LOGIN=true", signingKeys})
		require.ErrorContains(t, err, "dev login is only allowed with ENV=local")
	})
}

func TestLoadConfig_AuthRules(t *testing.T) {
	prod := []string{"APP_ENV=production", "APP_PUBLIC_URL=https://app.example.com", signingKeys}
	strongKey := "APP_MFA_KEYS=" + strings.Repeat("k", 32)
	tests := []struct {
		name string
		env  []string
		want string
	}{
		{"MFA without keys", []string{"APP_ENV=test", signingKeys, "APP_REALM_TENANT_MFA=optional"}, "needs APP_MFA_KEYS"},
		{"short MFA key in production", append(prod, "APP_REALM_TENANT_MFA=required", "APP_MFA_KEYS=short"), "MFA key 1 must be at least 32 bytes"},
		{"dev login in production", append(prod, "APP_DEV_LOGIN=true"), "dev login is only allowed with ENV=local"},
		{"dev login on every interface", []string{"APP_ENV=local", "APP_DEV_LOGIN=true", "APP_HTTP_ADDR=0.0.0.0:8080"}, "loopback listener"},
		{"weak argon2 in production", append(prod, "APP_PASSWORD_ARGON2=m=64,t=1,p=1"), "below OWASP's minimum"},
		{"argon2 over the memory budget", []string{"APP_ENV=test", signingKeys, "APP_PASSWORD_ARGON2=m=65536,t=3,p=4", "APP_PASSWORD_MAX_CONCURRENT=8"}, "over the memory budget"},
		{"unknown MFA policy", []string{"APP_ENV=test", signingKeys, "APP_REALM_TENANT_MFA=sometimes"}, "MFA must be off, optional or required"},
		{"no signing keys outside local", []string{"APP_ENV=staging", "APP_PUBLIC_URL=https://app.example.com"}, "APP_SESSION_KEYS is required outside local"},
		{"short signing key", []string{"APP_ENV=test", "APP_SESSION_KEYS=c2hvcnQ="}, "key 1 must be base64 of at least 32 bytes"},
		{"invalid cookie name", []string{"APP_ENV=test", signingKeys, "APP_SESSION_COOKIE=__Host-session"}, "cookie name"},
		{"invalid realm cookie name", []string{"APP_ENV=test", signingKeys, "APP_REALM_TENANT_COOKIE=my session"}, "cookie name"},
		{"production with a strong key", append(prod, "APP_REALM_TENANT_MFA=required", strongKey), ""},
	}
	for _, tt := range tests {
		_, err := app.LoadConfig(tt.env)
		if tt.want == "" {
			if err != nil {
				assert.NotContains(t, err.Error(), "MFA", tt.name)
			}
			continue
		}
		require.ErrorContains(t, err, tt.want, tt.name)
	}
}

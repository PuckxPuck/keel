package connections_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/config"
	"github.com/PuckxPuck/keel/internal/kit/connections"
	"github.com/PuckxPuck/keel/internal/kit/db"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/seal"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

var accountSeq atomic.Int64

// fakeProvider rotates refresh tokens: each one works once, like providers that detect reuse. current is
// the one live refresh token, empty once revoked.
type fakeProvider struct {
	srv     *httptest.Server
	account string

	mu         sync.Mutex
	challenges map[string]bool
	calls      int
	refreshes  int
	current    string
	access     string
	onRefresh  func()
}

func newFakeProvider(t *testing.T) *fakeProvider {
	p := &fakeProvider{challenges: map[string]bool{}, account: fmt.Sprintf("acct-%d", accountSeq.Add(1))}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("POST /revoke", func(_ http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		if r.PostForm.Get("token") == p.current {
			p.current = ""
		}
		p.mu.Unlock()
	})
	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		if !p.authorised(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprintf(w, `{"id":%q}`, p.account)
	})
	mux.HandleFunc("GET /api", func(w http.ResponseWriter, r *http.Request) {
		if !p.authorised(r) {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	mux.HandleFunc("GET /redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("to"), http.StatusFound) //nolint:gosec // the test chooses where its fake provider redirects
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProvider) authorised(r *http.Request) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return r.Header.Get("Authorization") == "Bearer "+p.access
}

func (p *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	p.mu.Lock()
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !p.challenges[base64.RawURLEncoding.EncodeToString(sum[:])] {
			p.mu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		p.current, p.access = "r0", "a0"
	case "refresh_token":
		p.calls++
		if r.PostForm.Get("refresh_token") != p.current || p.current == "" {
			p.mu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		p.refreshes++
		p.current, p.access = fmt.Sprintf("r%d", p.refreshes), fmt.Sprintf("a%d", p.refreshes)
		if hook := p.onRefresh; hook != nil {
			p.mu.Unlock()
			hook()
			p.mu.Lock()
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The first token expires inside the refresh skew, so the first API call has to refresh.
	expires := 3600
	if p.refreshes == 0 {
		expires = 1
	}
	body, _ := json.Marshal(map[string]any{"access_token": p.access, "refresh_token": p.current, "token_type": "Bearer", "expires_in": expires})
	p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (p *fakeProvider) state() (calls, refreshes int, current string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls, p.refreshes, p.current
}

func (p *fakeProvider) Name() string { return "fake" }

func (p *fakeProvider) OAuth2() *oauth2.Config {
	return &oauth2.Config{
		ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app.example.test/callback", Scopes: []string{"read"},
		Endpoint: oauth2.Endpoint{AuthURL: p.srv.URL + "/authorize", TokenURL: p.srv.URL + "/token", AuthStyle: oauth2.AuthStyleInParams},
	}
}

func (p *fakeProvider) APIOrigins() []string { return []string{p.srv.URL} }

func (p *fakeProvider) Account(ctx context.Context, client *http.Client) (connections.Account, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.srv.URL+"/me", nil)
	if err != nil {
		return connections.Account{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return connections.Account{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	var me struct{ ID string }
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		return connections.Account{}, err
	}
	return connections.Account{ExternalID: me.ID, Scopes: []string{"read"}}, nil
}

func (p *fakeProvider) Revoke(ctx context.Context, client *http.Client, token *oauth2.Token) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.srv.URL+"/revoke",
		strings.NewReader(url.Values{"token": {token.RefreshToken}}.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func newUser(t *testing.T, d *db.DB) users.ID {
	t.Helper()
	var id users.ID
	require.NoError(t, id.UnmarshalText([]byte(ids.New().String())))
	_, err := d.SQL().ExecContext(t.Context(), db.Rebind(d.Dialect(),
		"INSERT INTO users (id, email, name, status, created_at, updated_at, version) VALUES (?, ?, 'T', 'active', ?, ?, 1)"),
		id, id.String()+"@example.test", clock.Wall(t.Context()).Now(), clock.Wall(t.Context()).Now())
	require.NoError(t, err)
	return id
}

type setupOptions struct {
	tx     connections.TxRunner
	client *http.Client
}

func setup(t *testing.T, d *db.DB, o setupOptions) (*connections.Service, *fakeProvider) {
	t.Helper()
	p := newFakeProvider(t)
	keys, err := seal.NewKeyring([]config.Secret{"connections-test-key-0123456789abcd"}, "connections")
	require.NoError(t, err)
	if o.tx == nil {
		o.tx = connections.PlainTx(d)
	}
	if o.client == nil {
		o.client = &http.Client{Timeout: 5 * time.Second}
	}
	svc, err := connections.New(connections.Options{Tx: o.tx, Keys: keys, Providers: []connections.Provider{p}, HTTPClient: o.client})
	require.NoError(t, err)
	return svc, p
}

func start(t *testing.T, d *db.DB, svc *connections.Service, p *fakeProvider, user users.ID) string {
	t.Helper()
	var authURL string
	require.NoError(t, db.InTx(t.Context(), d, func(ctx context.Context, tx db.Tx[db.Plain]) error {
		var err error
		authURL, err = svc.Start(ctx, tx, "fake", user, "/settings")
		return err
	}))
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	assert.Equal(t, "S256", u.Query().Get("code_challenge_method"))
	p.mu.Lock()
	p.challenges[u.Query().Get("code_challenge")] = true
	p.mu.Unlock()
	return u.Query().Get("state")
}

func connect(t *testing.T, d *db.DB, svc *connections.Service, p *fakeProvider) connections.Connection {
	t.Helper()
	user := newUser(t, d)
	c, _, err := svc.Finish(t.Context(), "fake", user, start(t, d, svc, p, user), "code")
	require.NoError(t, err)
	return c
}

func call(ctx context.Context, client *http.Client, rawURL string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, resp.Body.Close()
}

func expire(t *testing.T, d *db.DB, id connections.ID) {
	t.Helper()
	_, err := d.SQL().ExecContext(t.Context(), db.Rebind(d.Dialect(), "UPDATE connections SET expires_at = ? WHERE id = ?"), time.Unix(1000, 0).UTC(), id)
	require.NoError(t, err)
}

// storedRotated checks the stored refresh token is the provider's live one: a fresh refresh succeeds.
func storedRotated(t *testing.T, d *db.DB, svc *connections.Service, p *fakeProvider, id connections.ID) {
	t.Helper()
	_, before, _ := p.state()
	expire(t, d, id)
	status, err := call(t.Context(), svc.Client(id), p.srv.URL+"/api")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	_, after, _ := p.state()
	assert.Equal(t, before+1, after)
}

func TestFinish_StateIsSingleUseAndBoundToTheUser(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		svc, p := setup(t, d, setupOptions{})
		owner, other := newUser(t, d), newUser(t, d)

		state := start(t, d, svc, p, owner)
		_, _, err := svc.Finish(t.Context(), "fake", other, state, "code")
		require.ErrorIs(t, err, connections.ErrInvalidState, "another user")
		_, _, err = svc.Finish(t.Context(), "fake", owner, state, "code")
		require.ErrorIs(t, err, connections.ErrInvalidState, "the state was spent by the first attempt")

		state = start(t, d, svc, p, owner)
		c, back, err := svc.Finish(t.Context(), "fake", owner, state, "code")
		require.NoError(t, err)
		assert.Equal(t, p.account, c.ExternalAccountID)
		assert.Equal(t, "/settings", back)
		_, _, err = svc.Finish(t.Context(), "fake", owner, state, "code")
		require.ErrorIs(t, err, connections.ErrInvalidState, "replay")
		require.NoError(t, svc.Disconnect(t.Context(), c.ID))
	})
}

func TestClient_ConcurrentRefreshCallsTheProviderOnce(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		svc, p := setup(t, d, setupOptions{})
		c := connect(t, d, svc, p)

		client := svc.Client(c.ID)
		var wg sync.WaitGroup
		statuses := make([]int, 8)
		errs := make([]error, 8)
		for i := range statuses {
			wg.Go(func() { statuses[i], errs[i] = call(t.Context(), client, p.srv.URL+"/api") })
		}
		wg.Wait()
		for i, s := range statuses {
			require.NoError(t, errs[i])
			assert.Equal(t, http.StatusOK, s)
		}
		calls, _, _ := p.state()
		assert.Equal(t, 1, calls)
		storedRotated(t, d, svc, p, c.ID)
	})
}

func retryable(d db.Dialect) error {
	if d == db.MySQL {
		return &mysql.MySQLError{Number: 1213, Message: "Deadlock found when trying to get lock"}
	}
	return &pgconn.PgError{Code: "40001", Message: "could not serialize access"}
}

// The provider has rotated the refresh token; failing writes must be retried without asking it again.
func TestRefresh_RetryableWriteFailureAfterRotationKeepsTheRotatedToken(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		var p *fakeProvider
		var injected atomic.Int64
		flaky := func(ctx context.Context, fn func(context.Context, db.Transaction) error) error {
			return connections.PlainTx(d)(ctx, func(ctx context.Context, tx db.Transaction) error {
				if err := fn(ctx, tx); err != nil {
					return err
				}
				if _, refreshes, _ := p.state(); refreshes > 0 && injected.Add(1) <= 4 {
					return retryable(d.Dialect())
				}
				return nil
			})
		}
		svc, prov := setup(t, d, setupOptions{tx: flaky})
		p = prov
		c := connect(t, d, svc, p)

		status, err := call(t.Context(), svc.Client(c.ID), p.srv.URL+"/api")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		calls, _, _ := p.state()
		assert.Equal(t, 1, calls, "the provider was asked again with the spent refresh token")
		storedRotated(t, d, svc, p, c.ID)
	})
}

// The caller gives up after the provider answered: the rotated token is still stored.
func TestRefresh_CallerCancelledAfterTheProviderAnsweredStillStores(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		svc, p := setup(t, d, setupOptions{})
		c := connect(t, d, svc, p)
		ctx, cancel := context.WithCancel(t.Context())
		p.mu.Lock()
		p.onRefresh = cancel
		p.mu.Unlock()

		_, _ = call(ctx, svc.Client(c.ID), p.srv.URL+"/api")
		require.Eventually(t, func() bool {
			var expires time.Time
			err := d.SQL().QueryRowContext(t.Context(), db.Rebind(d.Dialect(), "SELECT expires_at FROM connections WHERE id = ?"), c.ID).Scan(&expires)
			return err == nil && expires.After(clock.Wall(t.Context()).Now().Add(30*time.Minute))
		}, 5*time.Second, 20*time.Millisecond, "the rotated token was not stored")
		p.mu.Lock()
		p.onRefresh = nil
		p.mu.Unlock()
		storedRotated(t, d, svc, p, c.ID)
	})
}

// A disconnect during a refresh must not leave the token the refresh obtained alive at the provider.
func TestDisconnect_DuringRefreshLeavesNoLiveToken(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		svc, p := setup(t, d, setupOptions{})
		c := connect(t, d, svc, p)
		expire(t, d, c.ID)
		refreshing := make(chan struct{})
		p.mu.Lock()
		p.onRefresh = func() { close(refreshing) }
		p.mu.Unlock()

		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = call(t.Context(), svc.Client(c.ID), p.srv.URL+"/api")
		}()
		<-refreshing
		require.NoError(t, svc.Disconnect(t.Context(), c.ID))
		<-done

		var n int
		require.NoError(t, d.SQL().QueryRowContext(t.Context(), db.Rebind(d.Dialect(), "SELECT COUNT(*) FROM connections WHERE id = ?"), c.ID).Scan(&n))
		_, _, current := p.state()
		assert.Equal(t, 0, n)
		assert.Empty(t, current, "a refresh token is still live at the provider after the connection was deleted")
	})
}

// The token goes only to the provider's declared origins, never to another host or through a redirect.
func TestClient_TokenOnlyReachesTheProviderOrigin(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		svc, p := setup(t, d, setupOptions{})
		c := connect(t, d, svc, p)
		var leaked atomic.Int64
		attacker := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				leaked.Add(1)
			}
		}))
		defer attacker.Close()
		client := svc.Client(c.ID)

		_, _ = call(t.Context(), client, attacker.URL+"/steal")
		_, _ = call(t.Context(), client, p.srv.URL+"/redirect?to="+url.QueryEscape(attacker.URL+"/steal"))
		assert.Zero(t, leaked.Load())
	})
}

type originsProvider struct {
	*fakeProvider
	origins []string
}

func (p originsProvider) APIOrigins() []string { return p.origins }

func TestNew_APIOriginsMustBeHTTPSOrLoopback(t *testing.T) {
	keys, err := seal.NewKeyring([]config.Secret{"connections-test-key-0123456789abcd"}, "connections")
	require.NoError(t, err)
	cases := map[string]bool{
		"https://api.example.com": true, "https://api.example.com:8443/": true, "http://127.0.0.1:9000": true, "http://localhost:9000": true,
		"http://api.example.com": false, "https://api.example.com/v1": false, "https://u:p@api.example.com": false, "ftp://api.example.com": false,
	}
	for origin, ok := range cases {
		p := originsProvider{fakeProvider: newFakeProvider(t), origins: []string{origin}}
		_, err := connections.New(connections.Options{
			Tx:   func(context.Context, func(context.Context, db.Transaction) error) error { return nil },
			Keys: keys, Providers: []connections.Provider{p},
		})
		assert.Equal(t, ok, err == nil, "%s: %v", origin, err)
	}
}

// After Rekey every token opens with the newest key alone, so the old one can be removed.
func TestRekey_ResealsTokensWithTheNewestKey(t *testing.T) {
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		t.Parallel()
		d := e.DB()
		svc, p := setup(t, d, setupOptions{})
		c := connect(t, d, svc, p)
		newer, err := seal.NewKeyring([]config.Secret{"connections-newer-key-0123456789ab", "connections-test-key-0123456789abcd"}, "connections")
		require.NoError(t, err)
		rotated, err := connections.New(connections.Options{Tx: connections.PlainTx(d), Keys: newer, Providers: []connections.Provider{p}})
		require.NoError(t, err)
		res, err := rotated.Rekey(t.Context())
		require.NoError(t, err)
		assert.GreaterOrEqual(t, res.Rewrapped, 2)

		only, err := seal.NewKeyring([]config.Secret{"connections-newer-key-0123456789ab"}, "connections")
		require.NoError(t, err)
		var access, refresh []byte
		require.NoError(t, d.SQL().QueryRowContext(t.Context(), db.Rebind(d.Dialect(), "SELECT access_token, refresh_token FROM connections WHERE id = ?"), c.ID).
			Scan(&access, &refresh))
		_, _, err = only.Open(access, append(c.ID[:], "access"...))
		require.NoError(t, err)
		_, _, err = only.Open(refresh, append(c.ID[:], "refresh"...))
		require.NoError(t, err)
	})
}

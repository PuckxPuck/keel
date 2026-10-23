package idempotency_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PuckxPuck/keel/db/migrations"
	"github.com/PuckxPuck/keel/internal/kit/clock"
	"github.com/PuckxPuck/keel/internal/kit/httpx"
	"github.com/PuckxPuck/keel/internal/kit/httpx/problem"
	"github.com/PuckxPuck/keel/internal/kit/idempotency"
	"github.com/PuckxPuck/keel/internal/kit/ids"
	"github.com/PuckxPuck/keel/internal/kit/rbac"
	"github.com/PuckxPuck/keel/internal/kit/testdb"
	"github.com/PuckxPuck/keel/internal/kit/users"
)

func TestMain(m *testing.M) {
	testdb.Main(m, testdb.Options{Migrations: migrations.FS, RolePrefix: migrations.RolePrefix})
}

type payment struct {
	Number int64  `json:"number"`
	Pad    string `json:"pad,omitempty"`
}

type payInput struct {
	Account string `path:"account"`
	Body    struct {
		Amount int    `json:"amount"`
		Pad    string `json:"pad,omitempty"`
	}
}

type caller struct {
	user  users.ID
	realm string
}

type callerKey struct{}

type fromContext struct{}

func (fromContext) Principal(ctx context.Context) (rbac.Principal, bool) {
	c, ok := ctx.Value(callerKey{}).(caller)
	return rbac.NewPrincipal(c.user, c.realm), ok
}

var base = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

const (
	amountBlocks   = 0
	amountFails    = -1
	amountConflict = 409
	amountLarge    = 1000
)

func TestMiddleware(t *testing.T) {
	problem.Install()
	testdb.Each(t, func(t *testing.T, e *testdb.Engine) {
		var runs atomic.Int64
		started, release := make(chan struct{}), make(chan struct{})
		router := httpx.NewRouter()
		cfg := idempotency.Config{TTL: time.Hour, Lease: time.Minute, MaxStoredBytes: 256}
		store := idempotency.NewStore(e.DB())
		for _, realm := range []string{"tenant", "operator"} {
			api := httpx.NewAPI(router, httpx.Options{Title: "t", Version: "1", Realm: realm, BasePath: "/" + realm, MaxBodyBytes: 1 << 10})
			api.UseMiddleware(idempotency.Middleware(api, store, cfg, fromContext{}))
			httpx.Register(api, huma.Operation{OperationID: "pay", Method: http.MethodPost, Path: "/accounts/{account}/pay", DefaultStatus: http.StatusCreated},
				func(_ context.Context, in *payInput) (*httpx.One[payment], error) {
					switch in.Body.Amount {
					case amountBlocks:
						close(started)
						<-release
					case amountFails:
						return nil, huma.Error500InternalServerError("boom")
					case amountConflict:
						runs.Add(1)
						return nil, huma.Error409Conflict("already paid")
					case amountLarge:
						return httpx.OneOf(payment{Number: runs.Add(1), Pad: strings.Repeat("x", 300)}), nil
					}
					return httpx.OneOf(payment{Number: runs.Add(1)}), nil
				}, rbac.SignedIn(), idempotency.Required())
			require.NoError(t, idempotency.Check(api))
		}

		alice, bob := users.ID(ids.New()), users.ID(ids.New())
		type call struct {
			who         *caller
			realm, path string
			key, body   string
			contentType string
			at          time.Duration
		}
		post := func(c call) *httptest.ResponseRecorder {
			ctx := clock.WithWall(t.Context(), clock.Fixed(base.Add(c.at)))
			if c.who != nil {
				ctx = context.WithValue(ctx, callerKey{}, *c.who)
			}
			realm, path := c.realm, c.path
			if realm == "" {
				realm = "tenant"
			}
			if path == "" {
				path = "/accounts/a1/pay"
			}
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/"+realm+path, strings.NewReader(c.body))
			req.Header.Set("Content-Type", "application/json")
			if c.contentType != "" {
				req.Header.Set("Content-Type", c.contentType)
			}
			if c.key != "" {
				req.Header.Set(idempotency.Header, c.key)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			return rec
		}
		as := func(u users.ID, realm string) *caller { return &caller{user: u, realm: realm} }
		key := "pay-" + ids.New().String()
		first := post(call{who: as(alice, "tenant"), key: key, body: `{"amount": 10}`})
		require.Equal(t, http.StatusCreated, first.Code, first.Body.String())

		t.Run("a repeat replays the first response without running again", func(t *testing.T) {
			again := post(call{who: as(alice, "tenant"), key: key, body: `{"amount": 10}`})
			assert.Equal(t, http.StatusCreated, again.Code)
			assert.Equal(t, first.Body.String(), again.Body.String())
			assert.Equal(t, "application/json", again.Header().Get("Content-Type"))
			assert.Equal(t, "true", again.Header().Get(idempotency.ReplayedHeader))
			assert.Equal(t, int64(1), runs.Load())
		})

		t.Run("a repeat that differs in anything that changes the request is refused", func(t *testing.T) {
			for name, c := range map[string]call{
				"body":         {body: `{"amount": 11}`},
				"query":        {path: "/accounts/a1/pay?dryRun=true", body: `{"amount": 10}`},
				"path":         {path: "/accounts/a2/pay", body: `{"amount": 10}`},
				"content type": {body: `{"amount": 10}`, contentType: "application/merge-patch+json"},
			} {
				c.who, c.key = as(alice, "tenant"), key
				rec := post(c)
				assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, name)
				assert.Contains(t, rec.Body.String(), idempotency.CodeMismatch, name)
			}
		})

		t.Run("a key belongs to one caller in one realm", func(t *testing.T) {
			for _, who := range []*caller{as(bob, "tenant"), as(alice, "operator")} {
				rec := post(call{who: who, realm: who.realm, key: key, body: `{"amount": 10}`})
				assert.Equal(t, http.StatusCreated, rec.Code)
				assert.Empty(t, rec.Header().Get(idempotency.ReplayedHeader))
			}
			assert.Equal(t, int64(3), runs.Load())
		})

		t.Run("a repeat while the first runs is in progress, and after its lease the outcome is unknown", func(t *testing.T) {
			slow := "slow-" + ids.New().String()
			done := make(chan *httptest.ResponseRecorder)
			go func() { done <- post(call{who: as(alice, "tenant"), key: slow, body: `{"amount": 0}`}) }()
			<-started
			rec := post(call{who: as(alice, "tenant"), key: slow, body: `{"amount": 0}`})
			assert.Equal(t, http.StatusConflict, rec.Code)
			assert.Contains(t, rec.Body.String(), idempotency.CodeInProgress)
			rec = post(call{who: as(alice, "tenant"), key: slow, body: `{"amount": 0}`, at: 2 * time.Minute})
			assert.Equal(t, http.StatusConflict, rec.Code)
			assert.Contains(t, rec.Body.String(), idempotency.CodeOutcomeUnknown, "a claim is never taken over")
			close(release)
			assert.Equal(t, http.StatusCreated, (<-done).Code)
		})

		t.Run("a 5xx leaves the outcome unknown, so a retry never runs it twice", func(t *testing.T) {
			retry := "fail-" + ids.New().String()
			assert.Equal(t, http.StatusInternalServerError, post(call{who: as(alice, "tenant"), key: retry, body: `{"amount": -1}`}).Code)
			rec := post(call{who: as(alice, "tenant"), key: retry, body: `{"amount": -1}`})
			assert.Equal(t, http.StatusConflict, rec.Code)
			assert.Contains(t, rec.Body.String(), idempotency.CodeOutcomeUnknown)
		})

		t.Run("a 4xx answer is kept and replayed", func(t *testing.T) {
			conflict := "conflict-" + ids.New().String()
			before := runs.Load()
			assert.Equal(t, http.StatusConflict, post(call{who: as(alice, "tenant"), key: conflict, body: `{"amount": 409}`}).Code)
			rec := post(call{who: as(alice, "tenant"), key: conflict, body: `{"amount": 409}`})
			assert.Equal(t, http.StatusConflict, rec.Code)
			assert.Equal(t, "true", rec.Header().Get(idempotency.ReplayedHeader))
			assert.Equal(t, before+1, runs.Load())
		})

		t.Run("a response over the stored cap is sent whole and replayed as not stored", func(t *testing.T) {
			large := "large-" + ids.New().String()
			rec := post(call{who: as(alice, "tenant"), key: large, body: `{"amount": 1000}`})
			assert.Equal(t, http.StatusCreated, rec.Code)
			assert.Contains(t, rec.Body.String(), strings.Repeat("x", 300))
			rec = post(call{who: as(alice, "tenant"), key: large, body: `{"amount": 1000}`})
			assert.Equal(t, http.StatusConflict, rec.Code)
			assert.Contains(t, rec.Body.String(), idempotency.CodeResponseNotStored)
			assert.Contains(t, rec.Body.String(), `"originalStatus":201`)
		})

		t.Run("a body at the limit is accepted and one byte more is not", func(t *testing.T) {
			atLimit := `{"amount": 5, "pad": "` + strings.Repeat("p", 1<<10-24) + `"}`
			require.Len(t, atLimit, 1<<10)
			assert.Equal(t, http.StatusCreated, post(call{who: as(alice, "tenant"), key: ids.New().String(), body: atLimit}).Code)
			over := post(call{who: as(alice, "tenant"), key: ids.New().String(), body: atLimit + " "})
			assert.Equal(t, http.StatusRequestEntityTooLarge, over.Code)
		})

		t.Run("the key and a signed-in caller are required", func(t *testing.T) {
			rec := post(call{who: as(alice, "tenant"), body: `{"amount": 10}`})
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Contains(t, rec.Body.String(), idempotency.CodeKeyRequired)
			assert.Equal(t, http.StatusUnauthorized, post(call{key: ids.New().String(), body: `{"amount": 10}`}).Code)
			assert.Equal(t, http.StatusUnauthorized, post(call{who: as(alice, "operator"), key: ids.New().String(), body: `{"amount": 10}`}).Code,
				"a principal of another realm is nobody")
		})
	})
}
